#include "server/dev_engine.hpp"

#include "server/engine_thunks.hpp"

#include "wfh/log.hpp"
#include "wfh/server/dev_console.hpp"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <array>
#include <atomic>
#include <cstdint>
#include <cstring>
#include <sstream>
#include <string>
#include <vector>

// WFH_* logging macros expand to the project's do-while(0) printf-variadic guard; suppress
// the two macro-inherent findings file-wide (matches the other server TUs).
// NOLINTBEGIN(cppcoreguidelines-avoid-do-while,cppcoreguidelines-pro-type-vararg)
namespace wfh::server {

namespace {

constexpr std::size_t kMaxStackArgs = 16;         // dev `call` stack-arg cap
constexpr int kCallTimeoutMs = 2000;              // socket-thread wait for the tick to run it
constexpr std::uint32_t kImageBase = 0x00400000;  // wulfram2.exe load base
constexpr std::uint32_t kImageEnd = 0x00688000;   // ...end (for RVA annotation in bt)
constexpr int kMaxFrames = 32;                    // bt frame cap
constexpr std::uint32_t kRetAddrSlot = 4;         // return address at [ebp+4]

// One in-flight dev call, owned by the waiting socket thread; executed by the tick thread.
struct DevCall {
    std::uint32_t addr = 0;
    std::uint32_t ecx = 0;
    std::uint32_t edx = 0;
    std::array<std::uint32_t, kMaxStackArgs> stack{};
    int argc = 0;
    std::uint32_t result = 0;
    bool faulted = false;
    std::atomic<bool> done{false};
};

struct DevEngineState {
    std::atomic<DevCall*> pending{nullptr};
    std::atomic<std::uint32_t> engine_tid{0};
};

auto State() -> DevEngineState& {
    static DevEngineState state;
    return state;
}

// Map the parsed convention + args onto register/stack slots. Returns an error string, or
// "" on success.
auto BuildCall(const DevCommand& cmd, DevCall& call) -> std::string {
    call.addr = cmd.addr;
    std::size_t stack_start = 0;
    if (cmd.conv == "thiscall") {
        if (!cmd.args.empty()) {
            call.ecx = cmd.args.front();
        }
        stack_start = 1;
    } else if (cmd.conv == "fastcall") {
        if (!cmd.args.empty()) {
            call.ecx = cmd.args.front();
        }
        if (cmd.args.size() >= 2) {
            call.edx = cmd.args.at(1);
        }
        stack_start = 2;
    }
    std::size_t pushed = 0;
    for (std::size_t i = stack_start; i < cmd.args.size(); ++i) {
        if (pushed >= call.stack.size()) {
            return "err: too many stack args (max 16)";
        }
        call.stack.at(pushed) = cmd.args.at(i);
        ++pushed;
    }
    call.argc = static_cast<int>(pushed);
    return {};
}

auto HandleCall(const DevCommand& cmd) -> std::string {
    DevCall call;
    std::string err = BuildCall(cmd, call);  // non-const so the early-return can move it
    if (!err.empty()) {
        return err;
    }
    DevEngineState& st = State();
    DevCall* expected = nullptr;
    if (!st.pending.compare_exchange_strong(expected, &call)) {
        return "err: a call is already in flight";
    }
    for (int waited = 0; waited < kCallTimeoutMs && !call.done.load(); ++waited) {
        Sleep(1);
    }
    if (!call.done.load()) {
        st.pending.store(nullptr);  // reclaim the slot; tick never ran it
        return "err: call timed out (is the tick running? world_host on?)";
    }
    if (call.faulted) {
        return "call FAULTED (access violation) — check addr / conv / args";
    }
    std::ostringstream out;
    out << "ok: eax=0x" << std::hex << call.result << std::dec << " (" << call.result << ")";
    return out.str();
}

auto Read32(std::uint32_t addr, std::uint32_t& out) -> bool {
    std::vector<std::uint8_t> bytes;
    if (!SafeReadMemory(addr, sizeof(out), bytes) || bytes.size() < sizeof(out)) {
        return false;
    }
    std::memcpy(&out, bytes.data(), sizeof(out));
    return true;
}

void AppendFrame(std::ostringstream& out, std::uint32_t code_addr) {
    out << "  0x" << std::hex << code_addr;
    if (code_addr >= kImageBase && code_addr < kImageEnd) {
        out << " (wulfram2+0x" << (code_addr - kImageBase) << ")";
    }
    out << std::dec << "\n";
}

auto HandleBacktrace() -> std::string {
    const std::uint32_t tid = State().engine_tid.load();
    if (tid == 0) {
        return "err: engine tick thread not captured yet (let the server tick once)";
    }
    const HANDLE thread = OpenThread(
        THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION, FALSE, tid);
    if (thread == nullptr) {
        return "err: OpenThread failed";
    }
    SuspendThread(thread);
    CONTEXT ctx{};
    ctx.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;  // need Eip (control) + Ebp (integer)
    std::ostringstream out;
    if (GetThreadContext(thread, &ctx) != 0) {
        out << "engine thread " << tid << " stack (EBP walk):\n";
        AppendFrame(out, ctx.Eip);
        std::uint32_t frame = ctx.Ebp;
        for (int i = 0; i < kMaxFrames && frame != 0; ++i) {
            std::uint32_t ret = 0;
            std::uint32_t next = 0;
            if (!Read32(frame + kRetAddrSlot, ret) || !Read32(frame, next)) {
                break;
            }
            AppendFrame(out, ret);
            if (next <= frame) {
                break;  // EBP chain must climb; stop on a non-increasing frame
            }
            frame = next;
        }
    } else {
        out << "err: GetThreadContext failed";
    }
    ResumeThread(thread);
    CloseHandle(thread);
    return out.str();
}

auto DevEngineHandle(const DevCommand& cmd) -> std::string {
    switch (cmd.kind) {
    case DevCmdKind::Call: return HandleCall(cmd);
    case DevCmdKind::Backtrace: return HandleBacktrace();
    case DevCmdKind::Break:
    case DevCmdKind::BreakClear:
    case DevCmdKind::Hook:
        return "err: bp/bc/hook are Increment 2b (VEH int3) — not implemented yet";
    default: return "err: unhandled engine command";
    }
}

}  // namespace

void PumpDevEngine() {
    DevEngineState& st = State();
    if (st.engine_tid.load() == 0) {
        st.engine_tid.store(GetCurrentThreadId());
    }
    DevCall* call = st.pending.load();
    if (call == nullptr) {
        return;
    }
    const InvokeResult res =
        SafeEngineInvoke(call->addr, call->ecx, call->edx, call->stack.data(), call->argc);
    call->result = res.eax;
    call->faulted = res.faulted;
    st.pending.store(nullptr);
    call->done.store(true);
}

void InstallDevEngine() {
    SetDevEngineHandler(&DevEngineHandle);
    WFH_INFO("dev", "engine handler registered (call/bt live; bp/bc/hook = 2b)");
}

}  // namespace wfh::server
// NOLINTEND(cppcoreguidelines-avoid-do-while,cppcoreguidelines-pro-type-vararg)
