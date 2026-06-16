#include "wfh/server/tick_guard.hpp"

#include "wfh/log.hpp"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#pragma warning(push)
#pragma warning(disable : 4091)
#include <dbghelp.h>
#pragma warning(pop)

#include <cstdint>

// Every WFH_* logging call expands to the project's intentional do-while(0) guard
// macro that forwards a printf-style C variadic to Log::Write. Suppress the two
// macro-inherent findings file-wide so the call sites stay readable; all other
// checks remain on.
// NOLINTBEGIN(cppcoreguidelines-avoid-do-while,cppcoreguidelines-pro-type-vararg)
namespace wfh::server {

namespace {

struct RawSehFault {
    bool faulted = false;
    bool dump_written = false;
    std::uint32_t code = 0;
    std::uintptr_t address = 0;
};

auto ExceptionAddress(const EXCEPTION_POINTERS* info) -> std::uintptr_t {
    if (info == nullptr || info->ExceptionRecord == nullptr) {
        return 0;
    }
    // ExceptionAddress is a code pointer captured by the OS; this is logging-only.
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    return reinterpret_cast<std::uintptr_t>(info->ExceptionRecord->ExceptionAddress);
}

auto DumpPathProvided(const TickGuardOptions* options) -> bool {
    return options != nullptr && options->dump_path != nullptr && *options->dump_path != L'\0';
}

auto WriteMiniDump(EXCEPTION_POINTERS* info, const TickGuardOptions* options) -> bool {
    if (info == nullptr || !DumpPathProvided(options)) {
        return false;
    }

    const HANDLE dump_file = CreateFileW(options->dump_path, GENERIC_WRITE, 0, nullptr,
                                         CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (dump_file == INVALID_HANDLE_VALUE) {
        return false;
    }

    MINIDUMP_EXCEPTION_INFORMATION exception_info{};
    exception_info.ThreadId = GetCurrentThreadId();
    exception_info.ExceptionPointers = info;
    exception_info.ClientPointers = FALSE;

    const BOOL written = MiniDumpWriteDump(GetCurrentProcess(), GetCurrentProcessId(), dump_file,
                                           MiniDumpNormal, &exception_info, nullptr, nullptr);
    CloseHandle(dump_file);
    return written != FALSE;
}

auto CaptureException(EXCEPTION_POINTERS* info, RawSehFault* fault, const TickGuardOptions* options)
    -> int {
    if (fault != nullptr && info != nullptr && info->ExceptionRecord != nullptr) {
        fault->faulted = true;
        fault->code = info->ExceptionRecord->ExceptionCode;
        fault->address = ExceptionAddress(info);
        fault->dump_written = WriteMiniDump(info, options);
    }
    return EXCEPTION_EXECUTE_HANDLER;
}

// Keep this function deliberately C-like: no local objects requiring destructors
// may live across the __try block, or MSVC will reject it.
void RunProtectedRaw(TickCallback callback, void* user, RawSehFault* fault,
                     const TickGuardOptions* options) {
    __try {
        if (callback != nullptr) {
            callback(user);
        }
    } __except (CaptureException(GetExceptionInformation(), fault, options)) {
    }
}

auto PhaseText(const TickBreadcrumb& breadcrumb) -> const char* {
    return breadcrumb.phase != nullptr ? breadcrumb.phase : "tick";
}

}  // namespace

auto RunProtectedTick(const TickBreadcrumb& breadcrumb, TickCallback callback, void* user)
    -> TickGuardResult {
    const TickGuardOptions options{};
    return RunProtectedTick(breadcrumb, callback, user, options);
}

auto RunProtectedTick(const TickBreadcrumb& breadcrumb, TickCallback callback, void* user,
                      const TickGuardOptions& options) -> TickGuardResult {
    Log::SetTick(breadcrumb.tick);
    WFH_TRACE("tick", "protected tick begin phase=%s", PhaseText(breadcrumb));

    RawSehFault fault;
    RunProtectedRaw(callback, user, &fault, &options);

    TickGuardResult result;
    result.tick = breadcrumb.tick;
    if (!fault.faulted) {
        WFH_TRACE("tick", "protected tick end phase=%s", PhaseText(breadcrumb));
        return result;
    }

    result.ok = false;
    result.seh_code = fault.code;
    result.seh_address = fault.address;
    result.dump_written = fault.dump_written;
    WFH_FATAL("tick", "SEH fault phase=%s code=0x%08X addr=0x%08X tick=%llu dump=%d",
              PhaseText(breadcrumb), static_cast<unsigned>(fault.code),
              static_cast<unsigned>(fault.address),
              static_cast<unsigned long long>(breadcrumb.tick), fault.dump_written ? 1 : 0);
    return result;
}

}  // namespace wfh::server
// NOLINTEND(cppcoreguidelines-avoid-do-while,cppcoreguidelines-pro-type-vararg)
