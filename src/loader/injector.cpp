#include "wfh/injector.hpp"

#include "wfh/log.hpp"
#include "wfh/pe_validate.hpp"

#include <array>
#include <cstddef>
#include <string>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "binary_manifest.h"  // generated; wfh::kBinaryManifest

// Every WFH_* logging call expands to the project's intentional do-while(0) guard
// macro that forwards a printf-style C variadic to Log::Write (see log.hpp, which
// documents and NOLINTs the macro itself). Suppress the two macro-inherent
// findings file-wide so the call sites stay readable; all other checks remain on.
// NOLINTBEGIN(cppcoreguidelines-avoid-do-while,cppcoreguidelines-pro-type-vararg)
namespace wfh {
namespace {

constexpr std::size_t kErrBufSize = 256;

// Upper bound on how long the remote LoadLibraryW thread may run before we treat
// it as wedged. A healthy load completes in milliseconds; 15s tolerates a heavily
// loaded box without hanging the loader forever on a stuck target.
constexpr DWORD kRemoteLoadTimeoutMs = 15000;

// Format the most recent Win32 error into "<api> failed (<code>): <message>".
// Called only on a failure path right after the failing API, so GetLastError()
// still reflects that call.
auto LastErrorMessage(const char* api) -> std::string {
    const DWORD code = GetLastError();
    std::array<char, kErrBufSize> buf{};
    FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, nullptr, code, 0,
                   buf.data(), static_cast<DWORD>(buf.size()), nullptr);
    return std::string(api) + " failed (" + std::to_string(code) + "): " + buf.data();
}

// Close whichever of the process/thread handles were opened, idempotently.
void CloseProcessInfo(PROCESS_INFORMATION& proc_info) {
    if (proc_info.hThread != nullptr) {
        CloseHandle(proc_info.hThread);
        proc_info.hThread = nullptr;
    }
    if (proc_info.hProcess != nullptr) {
        CloseHandle(proc_info.hProcess);
        proc_info.hProcess = nullptr;
    }
}

// Tear down a freshly-created (still suspended) process on any post-spawn error:
// free the remote allocation if one was made, kill the process so no orphaned
// suspended game lingers, then close handles. Single cleanup path, so every
// failure after CreateProcessW is guaranteed leak-free.
void DestroyProcess(PROCESS_INFORMATION& proc_info, LPVOID remote) {
    if (remote != nullptr) {
        VirtualFreeEx(proc_info.hProcess, remote, 0, MEM_RELEASE);
    }
    if (proc_info.hProcess != nullptr) {
        TerminateProcess(proc_info.hProcess, 1);
    }
    CloseProcessInfo(proc_info);
}

// Whole-binary identity gate. Runs BEFORE any process is created so we never
// spawn a wrong/untrusted binary. Returns ok=false (with a "mismatch" message)
// on the slightest header divergence from the pinned manifest.
auto CheckBinaryPinning(const InjectionPlan& plan) -> LaunchResult {
    const auto facts = ReadPeHeaderFacts(plan.game_exe_path);
    if (!facts.ok) {
        WFH_FATAL("loader", "cannot read PE headers: %s", facts.error.c_str());
        return {false, 0, facts.error};
    }
    const auto headers_ok = ValidateHeaders(facts.facts, kBinaryManifest);
    if (!headers_ok.ok) {
        WFH_FATAL("loader", "binary pinning failed: %s", headers_ok.error.c_str());
        return {false, 0, headers_ok.error};
    }
    WFH_INFO("loader", "binary pinning OK (stamp=%08x size=%08x)", facts.facts.time_date_stamp,
             facts.facts.size_of_image);
    return {true, 0, {}};
}

// Single failure path for the post-spawn injection steps: log the error, tear
// the (still-suspended) process down so nothing leaks, and return the error
// result. Centralizing this keeps each step's error branch a one-liner.
auto FailInject(PROCESS_INFORMATION& proc_info, LPVOID remote, std::string err) -> LaunchResult {
    WFH_FATAL("loader", "%s", err.c_str());
    DestroyProcess(proc_info, remote);
    return {false, 0, std::move(err)};
}

// Allocate a buffer in the target, write the DLL path into it, then run
// LoadLibraryW on it via a remote thread. On any failure the process is torn
// down (FailInject -> DestroyProcess) and ok=false is returned; on success the
// remote allocation is freed and ok=true is returned. Never resumes the main
// thread — the caller owns that decision.
auto InjectDll(PROCESS_INFORMATION& proc_info, const InjectionPlan& plan) -> LaunchResult {
    const std::wstring dll = plan.dll_path.wstring();
    const SIZE_T bytes = (dll.size() + 1) * sizeof(wchar_t);

    LPVOID remote = VirtualAllocEx(proc_info.hProcess, nullptr, bytes, MEM_COMMIT | MEM_RESERVE,
                                   PAGE_READWRITE);
    if (remote == nullptr) {
        return FailInject(proc_info, nullptr, LastErrorMessage("VirtualAllocEx"));
    }

    SIZE_T wrote = 0;
    if (WriteProcessMemory(proc_info.hProcess, remote, dll.c_str(), bytes, &wrote) == FALSE ||
        wrote != bytes) {
        return FailInject(proc_info, remote, LastErrorMessage("WriteProcessMemory"));
    }

    HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
    if (k32 == nullptr) {
        return FailInject(proc_info, remote, LastErrorMessage("GetModuleHandleW(kernel32.dll)"));
    }
    // reinterpret_cast of LoadLibraryW (FARPROC) to LPTHREAD_START_ROUTINE is the
    // canonical CreateRemoteThread idiom: kernel32 is mapped at the same base in
    // every process, and LoadLibraryW's __stdcall(LPVOID)->BOOL shape is ABI-
    // compatible with the thread-start signature. No portable alternative exists.
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    auto* load = reinterpret_cast<LPTHREAD_START_ROUTINE>(GetProcAddress(k32, "LoadLibraryW"));
    if (load == nullptr) {
        return FailInject(proc_info, remote, LastErrorMessage("GetProcAddress(LoadLibraryW)"));
    }

    HANDLE thr = CreateRemoteThread(proc_info.hProcess, nullptr, 0, load, remote, 0, nullptr);
    if (thr == nullptr) {
        return FailInject(proc_info, remote, LastErrorMessage("CreateRemoteThread"));
    }
    const DWORD wait = WaitForSingleObject(thr, kRemoteLoadTimeoutMs);
    if (wait == WAIT_TIMEOUT) {
        CloseHandle(thr);
        return FailInject(proc_info, remote, "remote LoadLibraryW timed out");
    }
    if (wait != WAIT_OBJECT_0) {
        const auto err = LastErrorMessage("WaitForSingleObject");
        CloseHandle(thr);
        return FailInject(proc_info, remote, err);
    }

    DWORD remote_exit = 0;
    if (GetExitCodeThread(thr, &remote_exit) == FALSE) {
        const auto err = LastErrorMessage("GetExitCodeThread");
        CloseHandle(thr);
        return FailInject(proc_info, remote, err);
    }
    CloseHandle(thr);

    // The remote thread's exit code is LoadLibraryW's return (the loaded HMODULE
    // truncated to 32 bits). Zero means the DLL failed to load in the target.
    if (remote_exit == 0) {
        return FailInject(proc_info, remote, "remote LoadLibraryW returned null");
    }

    VirtualFreeEx(proc_info.hProcess, remote, 0, MEM_RELEASE);
    WFH_INFO("loader", "injected wulf_headless.dll");
    return {true, 0, {}};
}

}  // namespace

auto LaunchAndInject(const InjectionPlan& plan) -> LaunchResult {
    // --- TOCTOU lock: pin the exact bytes we validate ---
    // Open the target with FILE_SHARE_READ only (denies others write/delete) and
    // HOLD this handle across CheckBinaryPinning + CreateProcessW so the validated
    // image cannot be swapped or modified in the validation->launch window. The OS
    // image mapping done by CreateProcessW also opens for read, which this sharing
    // mode permits, so holding the lock does not block the spawn.
    HANDLE lock = CreateFileW(plan.game_exe_path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                              OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (lock == INVALID_HANDLE_VALUE) {
        const auto err = LastErrorMessage("CreateFileW(lock)");
        WFH_FATAL("loader", "%s", err.c_str());
        return {false, 0, err};
    }

    // --- Binary pinning gate (BEFORE touching the process) ---
    auto pinned = CheckBinaryPinning(plan);
    if (!pinned.ok) {
        CloseHandle(lock);
        return pinned;
    }

    // --- Suspended launch ---
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION proc_info{};
    // CreateProcessW may write to the command-line buffer, so it must be a
    // mutable, null-terminated copy of plan.command_line.
    std::vector<wchar_t> cmd(plan.command_line.begin(), plan.command_line.end());
    cmd.push_back(L'\0');
    const std::filesystem::path work_dir = plan.game_exe_path.parent_path();
    const BOOL created = CreateProcessW(
        plan.game_exe_path.c_str(), cmd.data(), nullptr, nullptr, FALSE, CREATE_SUSPENDED, nullptr,
        work_dir.empty() ? nullptr : work_dir.c_str(), &startup, &proc_info);
    if (created == FALSE) {
        const auto err = LastErrorMessage("CreateProcessW");
        WFH_FATAL("loader", "%s", err.c_str());
        CloseHandle(lock);
        return {false, 0, err};
    }
    WFH_INFO("loader", "created suspended pid=%lu", proc_info.dwProcessId);

    // The child now holds its own image section; the lock has done its job and can
    // be released regardless of how the rest of injection turns out.
    CloseHandle(lock);

    // --- Inject; on failure InjectDll has already destroyed the process ---
    auto injected = InjectDll(proc_info, plan);
    if (!injected.ok) {
        return injected;
    }

    // Injection succeeded (remote alloc already freed): let the game run. A failed
    // ResumeThread leaves the process suspended, so tear it down rather than ship a
    // wedged game.
    if (ResumeThread(proc_info.hThread) == static_cast<DWORD>(-1)) {
        const auto err = LastErrorMessage("ResumeThread");
        WFH_FATAL("loader", "%s", err.c_str());
        DestroyProcess(proc_info, nullptr);
        return {false, 0, err};
    }
    const DWORD id = proc_info.dwProcessId;
    CloseProcessInfo(proc_info);
    return {true, id, {}};
}

}  // namespace wfh
// NOLINTEND(cppcoreguidelines-avoid-do-while,cppcoreguidelines-pro-type-vararg)
