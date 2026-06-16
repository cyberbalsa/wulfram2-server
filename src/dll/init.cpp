#include "wfh/init.hpp"

#include "wfh/config.hpp"
#include "wfh/log.hpp"
#include "wfh/pe_validate.hpp"
#include "wfh/ready_event.hpp"
#include "wfh/server/runtime.hpp"
#include "wfh/server/server_config.hpp"

#include "hooks/engine_hooks.hpp"
#include "hooks/head_stubs.hpp"

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

// Exit code raised when head-stub detour installation fails ('WG' in ASCII).
constexpr UINT kHeadStubsFailedExitCode = 0x5747;

// Exit code raised when the socket server cannot start ('WN' in ASCII).
constexpr UINT kServerStartFailedExitCode = 0x574E;

struct InitContext {
    std::filesystem::path dll_dir;
    std::filesystem::path config_path;
    std::string config_text;
    Level level = Level::Trace;
};

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

auto LoadInitContext(HMODULE module) -> InitContext {
    InitContext context;
    context.dll_dir = DllDirectory(module);
    context.config_path = context.dll_dir / "config" / "headless.toml";
    context.config_text = ReadFileToString(context.config_path);
    context.level = ParseLogLevel(context.config_text);
    return context;
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

// Stand up the hooking engine and install every head detour, BEFORE the loader
// resumes the game thread, so all hooks are live before any seam can run. On
// success returns 0; on failure logs and returns the process exit code to abort
// with so the caller never signals ready (the loader then times out and tears
// the process down rather than resuming a half-hooked game).
auto SetUpHooks() -> UINT {
    if (!HooksInit()) {
        WFH_FATAL("init", "MinHook init failed -- aborting");
        return kSelfCheckFailedExitCode;
    }
    WFH_INFO("init", "MinHook initialized");

    if (!InstallHeadStubs()) {
        WFH_FATAL("init", "head-stub install failed -- aborting");
        return kHeadStubsFailedExitCode;
    }
    WFH_INFO("init", "head stubs installed");
    return 0;
}

void LogInitContext(const InitContext& context) {
    WFH_INFO("init", "InitThread alive; logging up (level=%d)", static_cast<int>(context.level));
    const std::string dll_dir_text = context.dll_dir.string();
    const std::string config_path_text = context.config_path.string();
    WFH_DEBUG("init", "DLL directory=%s", dll_dir_text.c_str());
    WFH_DEBUG("init", "config path=%s bytes=%zu", config_path_text.c_str(),
              context.config_text.size());
}

void AbortInit(UINT exit_code) {
    Log::Shutdown();
    ExitProcess(exit_code);
}

void ValidateHookSitesOrAbort() {
    WFH_TRACE("init", "validating hook-site bytes");
    const auto sites = ValidateHookSitesInProcess(kBinaryManifest);
    if (!sites.ok) {
        WFH_FATAL("init", "hook-site self-check failed: %s -- aborting", sites.error.c_str());
        AbortInit(kSelfCheckFailedExitCode);
    }
    WFH_INFO("init", "hook-site self-check OK (%u sites)", kBinaryManifest.site_count);
}

void InstallHooksOrAbort() {
    WFH_TRACE("init", "installing hooks before ready signal");
    if (const UINT hook_exit_code = SetUpHooks(); hook_exit_code != 0) {
        AbortInit(hook_exit_code);
    }
}

void StartServerOrAbort(const std::string& config_text) {
    const server::ServerConfig server_cfg = server::ParseServerConfig(config_text);
    WFH_DEBUG("init", "server config bind_port=%u tick_hz=%u map=%s udp_host=%s",
              static_cast<unsigned>(server_cfg.bind_port),
              static_cast<unsigned>(server_cfg.tick_hz), server_cfg.map.c_str(),
              server_cfg.advertised_udp_host.c_str());
    WFH_TRACE("init", "starting server runtime before loader ready signal");
    if (!server::ProcessRuntime().Start(server_cfg)) {
        WFH_FATAL("init", "server runtime failed to start -- aborting");
        AbortInit(kServerStartFailedExitCode);
    }
    WFH_INFO("init", "server runtime listening on port %u",
             static_cast<unsigned>(server::ProcessRuntime().BoundPort()));
}
// NOLINTEND(cppcoreguidelines-pro-type-vararg,cppcoreguidelines-avoid-do-while)

}  // namespace

// Signature (DWORD WINAPI ...) is fixed by the LPTHREAD_START_ROUTINE ABI, so a
// trailing return type does not apply here.
// NOLINTNEXTLINE(modernize-use-trailing-return-type)
DWORD WINAPI InitThread(LPVOID module_handle) {
    auto* const module = static_cast<HMODULE>(module_handle);
    InitContext context = LoadInitContext(module);
    Log::Init(context.dll_dir / "logs" / "headless.log", context.level);

    // The WFH_* macros wrap a printf-style C variadic primitive and expand to a
    // do/while guard; both patterns are intentional for the logging facility.
    // NOLINTBEGIN(cppcoreguidelines-pro-type-vararg,cppcoreguidelines-avoid-do-while)
    LogInitContext(context);
    ValidateHookSitesOrAbort();

    // Stand up the hooking engine and install the 11 head detours BEFORE we signal
    // the loader, so every hook is live before the game's main thread resumes. Any
    // failure aborts WITHOUT signaling ready (see SetUpHooks / SignalReady).
    InstallHooksOrAbort();
    StartServerOrAbort(context.config_text);

    // Ready handshake: now that hooks are live, tell the loader it may resume the
    // still-suspended game main thread (see SignalReady).
    SignalReady();

    WFH_INFO("init", "foundation ready; head seams stubbed");
    // NOLINTEND(cppcoreguidelines-pro-type-vararg,cppcoreguidelines-avoid-do-while)
    return 0;
}

}  // namespace wfh
