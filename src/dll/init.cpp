#include "wfh/init.hpp"

#include "wfh/config.hpp"
#include "wfh/log.hpp"
#include "wfh/pe_validate.hpp"
#include "wfh/ready_event.hpp"

#include "hooks/engine_hooks.hpp"

#include "binary_manifest.h"

#include <windows.h>

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>

namespace wfh {

namespace {

// Exit code raised when the in-process binary self-check fails ('WF' in ASCII).
constexpr UINT kSelfCheckFailedExitCode = 0x5746;

// Resolve the directory the loaded DLL lives in, from its module handle.
auto DllDirectory(HMODULE module) -> std::filesystem::path {
    std::wstring buffer(MAX_PATH, L'\0');
    for (;;) {
        const DWORD copied =
            GetModuleFileNameW(module, buffer.data(), static_cast<DWORD>(buffer.size()));
        if (copied == 0) {
            return {};
        }
        if (copied < buffer.size()) {
            buffer.resize(copied);
            break;
        }
        buffer.resize(buffer.size() * 2);  // path was truncated; grow and retry
    }
    return std::filesystem::path(buffer).parent_path();
}

// Best-effort read of the whole file into a string; empty string if unavailable.
auto ReadFileToString(const std::filesystem::path& path) -> std::string {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        return {};
    }
    return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

// Signal the loader that hooks are installed so it can resume the suspended main
// thread. The event is manual-reset and keyed by our PID so it pairs with exactly
// the loader that injected us; CreateEventW is idempotent by name (the loader may
// have created it first). Only called on the SUCCESS path -- a failed self-check
// or HooksInit ExitProcess'es WITHOUT calling this, so the loader's wait times out
// and tears the process down rather than resuming a half-hooked game.
// The WFH_* macros wrap a printf-style C variadic primitive and expand to a
// do/while guard; both patterns are intentional for the logging facility.
// NOLINTBEGIN(cppcoreguidelines-pro-type-vararg,cppcoreguidelines-avoid-do-while)
void SignalReady() {
    const std::wstring ready_name = ReadyEventName(GetCurrentProcessId());
    HANDLE ev = CreateEventW(nullptr, TRUE /*manual reset*/, FALSE, ready_name.c_str());
    if (ev == nullptr) {
        WFH_FATAL("init", "CreateEventW(ready) failed (%lu)", GetLastError());
        return;
    }
    SetEvent(ev);
    CloseHandle(ev);
    WFH_INFO("init", "signaled ready");
}
// NOLINTEND(cppcoreguidelines-pro-type-vararg,cppcoreguidelines-avoid-do-while)

}  // namespace

// Signature (DWORD WINAPI ...) is fixed by the LPTHREAD_START_ROUTINE ABI, so a
// trailing return type does not apply here.
// NOLINTNEXTLINE(modernize-use-trailing-return-type)
DWORD WINAPI InitThread(LPVOID module_handle) {
    auto* const module = static_cast<HMODULE>(module_handle);
    const std::filesystem::path dll_dir = DllDirectory(module);

    const std::string config_text = ReadFileToString(dll_dir / "config" / "headless.toml");
    const Level level = ParseLogLevel(config_text);

    Log::Init(dll_dir / "logs" / "headless.log", level);

    // The WFH_* macros wrap a printf-style C variadic primitive and expand to a
    // do/while guard; both patterns are intentional for the logging facility.
    // NOLINTBEGIN(cppcoreguidelines-pro-type-vararg,cppcoreguidelines-avoid-do-while)
    WFH_INFO("init", "InitThread alive; logging up (level=%d)", static_cast<int>(level));

    const auto sites = ValidateHookSitesInProcess(kBinaryManifest);
    if (!sites.ok) {
        WFH_FATAL("init", "hook-site self-check failed: %s -- aborting", sites.error.c_str());
        Log::Shutdown();
        ExitProcess(kSelfCheckFailedExitCode);
    }
    WFH_INFO("init", "hook-site self-check OK (%u sites)", kBinaryManifest.site_count);

    // Stand up the hooking engine BEFORE we signal the loader. The head detours
    // (Milestone 3.3) will be installed here too, via InstallDetour, so they are
    // live before the loader resumes the game's main thread. For M3.2 there are
    // no head detours yet, so this is just engine init.
    if (!HooksInit()) {
        WFH_FATAL("init", "MinHook init failed -- aborting");
        Log::Shutdown();
        ExitProcess(kSelfCheckFailedExitCode);
    }
    WFH_INFO("init", "MinHook initialized");

    // Ready handshake: now that hooks are live, tell the loader it may resume the
    // still-suspended game main thread (see SignalReady).
    SignalReady();

    WFH_INFO("init", "foundation ready; head-chop deferred to Milestone 3");
    // NOLINTEND(cppcoreguidelines-pro-type-vararg,cppcoreguidelines-avoid-do-while)
    return 0;
}

}  // namespace wfh
