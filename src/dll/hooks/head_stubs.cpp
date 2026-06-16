#include "head_stubs.hpp"

#include "engine_hooks.hpp"

#include "wfh/log.hpp"

#include "addresses.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>

// Win32 + intrinsics. <windows.h> provides CreateWindowExA and the WS_*/HWND types
// for the M-B window hider; <intrin.h> provides _ReturnAddress(), used by
// Stub_App_ExitGracefully (M3.7) to identify the calling site so it skips ONLY the
// boot-time exit. Both headers trip the project's /W4 diagnostics, so they are
// wrapped in a local warning push/pop.
#ifdef _MSC_VER
#pragma warning(push, 0)
#endif
#include <windows.h>

#include <intrin.h>
#ifdef _MSC_VER
#pragma warning(pop)
#endif

// Every WFH_* logging call expands to the project's intentional do-while(0) guard
// macro that forwards a printf-style C variadic to Log::Write. Suppress the two
// macro-inherent findings file-wide so the call sites stay readable; all other
// checks remain on.
// NOLINTBEGIN(cppcoreguidelines-avoid-do-while,cppcoreguidelines-pro-type-vararg)
namespace wfh {
namespace {

// ===========================================================================
// Approach B: let the head boot for real (built-in GDI software renderer) into a
// HIDDEN window, then keep only the minimal hooks a headless server needs.
//
// We no longer "head-chop" (stub every render/audio/input *_Init seam and chase
// the resulting NULL-deref cascade). Instead:
//   1. Force the engine to select its "Software Windowed" (GDI) driver, so it
//      needs no 3D hardware and never hits the "Hokey Display Card" error box.
//   2. Hook CreateWindowExA so the real main window is created HIDDEN (no
//      WS_VISIBLE, off the taskbar) -- the HWND + GDI DC stay valid, so the
//      software blit still has a surface, but nothing is shown.
//   3. Keep the environmental bypasses (registry gate, browser launch) and the
//      boot-exit guard, plus the Client_RunMainLoop observation detour (the M4
//      server-tick hijack point).
//
// All hooks below are installed from InstallHeadStubs(), which runs in InitThread
// BEFORE the loader resumes the game's main thread -- so every detour and the
// force-software byte are live before any of these seams can run.
// ===========================================================================

// Turns an absolute VA into a void* target. reinterpret_cast on an integer address
// is unavoidable here (and read-only / never dereferenced as the wrong type by us).
auto TargetAt(std::uint32_t address) -> void* {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast,performance-no-int-to-ptr)
    return reinterpret_cast<void*>(static_cast<std::uintptr_t>(address));
}

// Turn a typed function pointer into the untyped void* InstallDetour expects.
template <typename Func> auto AsVoidPtr(Func func) -> void* {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    return reinterpret_cast<void*>(func);
}

// ---------------------------------------------------------------------------
// Approach B step 1: force the "Software Windowed" (GDI) renderer.
//
// Render_SwitchActiveDriver (0x00485f70) picks the active display driver. On first
// boot, if DAT_00679169 != 0 it forces the renderer name to "Software Windowed"
// (pure GDI/BitBlt from a DIB section -- no 3D hardware, no DirectDraw cooperative
// level), bypassing Winsys_SelectBestUsableRenderer and therefore the fatal "Hokey
// Display Card or Driver?" / "Can't find a usable display mode" box. DAT_00679169
// is the dedicated force-software flag (default 0), natively settable by a command
// -line arg in Cmd_ApplyClientFlags. We set it directly before the game resumes.
//
// VA pinned here (gen/addresses.h holds functions only).
constexpr std::uint32_t kForceSoftwareWindowedFlagVA = 0x00679169;

void ForceSoftwareRenderer() {
    // NOLINTNEXTLINE(performance-no-int-to-ptr,clang-analyzer-core.FixedAddressDereference)
    *static_cast<volatile std::uint8_t*>(TargetAt(kForceSoftwareWindowedFlagVA)) = 1;
    WFH_INFO("head", "Approach B: forced Software Windowed (DAT_00679169=1)");
}

// ---------------------------------------------------------------------------
// Approach B step 2: hide the main window.
//
// The GDI software window is created in Winsys_GDI_EnsureMainWindow (0x004b5460)
// via CreateWindowExA(exStyle=WS_EX_APPWINDOW, class "SlurpySoft", title "Wulfram",
// style=WS_VISIBLE|WS_CLIPSIBLINGS|WS_CAPTION|..., ...) and then ALWAYS calls
// ShowWindow(hWnd, SW_SHOWNORMAL) followed by UpdateWindow(hWnd). So stripping
// WS_VISIBLE in CreateWindowExA alone is NOT enough -- the following ShowWindow(1)
// would re-show it. We therefore hook BOTH:
//   - CreateWindowExA: strip WS_VISIBLE, add WS_EX_TOOLWINDOW, and remember the
//     main HWND (matched by its "Wulfram" title) before creating it.
//   - ShowWindow: force SW_HIDE for that one HWND; pass every other window through.
// The HWND and its GDI DC remain fully valid (the software backbuffer blit still
// works), but the main window is never shown and stays off the taskbar / Z-order.

// Trampoline slot for the real CreateWindowExA (filled by InstallDetour).
// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
void* g_create_window_orig = nullptr;

// Trampoline slot for the real ShowWindow (filled by InstallDetour).
// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
void* g_show_window_orig = nullptr;

// The game's main window, captured in the CreateWindowExA hook by its "Wulfram"
// title, so the ShowWindow hook only force-hides that one window and leaves
// dialogs / other windows untouched.
// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
HWND g_main_hwnd = nullptr;

// Log the hide action only once, even though several windows may be created.
// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
bool g_window_hidden_logged = false;

// Matches CreateWindowExA exactly: HWND WINAPI(__stdcall) with the full 12-arg
// signature, so the trampoline call is ABI-correct. The parameter set, order, and
// (necessarily short, convertible) names mirror the Win32 prototype, so the
// easily-swappable-parameters and identifier-length checks do not apply; the
// finding lands on the wrapped parameter line, so each suppression sits on the
// preceding line.
auto WINAPI Hook_CreateWindowExA(
    DWORD dwExStyle, LPCSTR lpClassName, LPCSTR lpWindowName,
    // NOLINTNEXTLINE(readability-identifier-length,bugprone-easily-swappable-parameters)
    DWORD dwStyle, int pos_x, int pos_y, int nWidth, int nHeight, HWND hWndParent, HMENU hMenu,
    HINSTANCE hInstance, LPVOID lpParam) -> HWND {
    // Strip WS_VISIBLE so the window is never shown; add WS_EX_TOOLWINDOW so it does
    // not appear on the taskbar or in the normal Z-order. The DC stays valid.
    const DWORD hidden_style = dwStyle & ~static_cast<DWORD>(WS_VISIBLE);
    const DWORD tool_ex_style = dwExStyle | static_cast<DWORD>(WS_EX_TOOLWINDOW);

    if (!g_window_hidden_logged) {
        WFH_INFO("head", "Approach B: hiding main window (cleared WS_VISIBLE, +WS_EX_TOOLWINDOW)");
        g_window_hidden_logged = true;
    }

    using CreateWindowExA_t = HWND(WINAPI*)(DWORD, LPCSTR, LPCSTR, DWORD, int, int, int, int, HWND,
                                            HMENU, HINSTANCE, LPVOID);
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    auto* const orig = reinterpret_cast<CreateWindowExA_t>(g_create_window_orig);
    const HWND hwnd = orig(tool_ex_style, lpClassName, lpWindowName, hidden_style, pos_x, pos_y,
                           nWidth, nHeight, hWndParent, hMenu, hInstance, lpParam);

    // Remember the main window (title "Wulfram") so the ShowWindow hook force-hides
    // exactly it. Only the GDI/D3D main window uses this title, so the match is
    // unambiguous.
    if ((lpWindowName != nullptr) && (std::strcmp(lpWindowName, "Wulfram") == 0)) {
        g_main_hwnd = hwnd;
    }
    return hwnd;
}

// Matches ShowWindow exactly: BOOL WINAPI(__stdcall)(HWND, int). Forces SW_HIDE for
// the captured main window so the engine's ShowWindow(hWnd, SW_SHOWNORMAL) right
// after creation cannot reveal it; all other windows pass through unchanged.
auto WINAPI Hook_ShowWindow(HWND hWnd, int nCmdShow) -> BOOL {
    int effective_cmd = nCmdShow;
    if (hWnd != nullptr && hWnd == g_main_hwnd) {
        effective_cmd = SW_HIDE;
    }
    using ShowWindow_t = BOOL(WINAPI*)(HWND, int);
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    auto* const orig = reinterpret_cast<ShowWindow_t>(g_show_window_orig);
    return orig(hWnd, effective_cmd);
}

// Resolve one user32 export by name and detour it, storing the trampoline. Logs
// and returns false on any failure. Kept as a helper so InstallWindowHider stays
// under the cognitive-complexity gate.
auto HookUser32Export(HMODULE user32, const char* name, void* detour, void** original) -> bool {
    // GetProcAddress returns FARPROC; reinterpret to the typed pointer we hook.
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    void* const target = reinterpret_cast<void*>(GetProcAddress(user32, name));
    if (target == nullptr) {
        WFH_FATAL("head", "Approach B: GetProcAddress(%s) failed (%lu)", name, GetLastError());
        return false;
    }
    if (!InstallDetour(target, detour, original)) {
        WFH_FATAL("head", "Approach B: failed to install %s window-hider hook", name);
        return false;
    }
    return true;
}

auto InstallWindowHider() -> bool {
    HMODULE user32 = GetModuleHandleW(L"user32.dll");
    if (user32 == nullptr) {
        WFH_FATAL("head", "Approach B: GetModuleHandleW(user32.dll) failed (%lu)", GetLastError());
        return false;
    }
    if (!HookUser32Export(user32, "CreateWindowExA", AsVoidPtr(&Hook_CreateWindowExA),
                          &g_create_window_orig)) {
        return false;
    }
    if (!HookUser32Export(user32, "ShowWindow", AsVoidPtr(&Hook_ShowWindow), &g_show_window_orig)) {
        return false;
    }
    WFH_INFO("head", "Approach B: window-hider hooks installed (CreateWindowExA + ShowWindow)");
    return true;
}

// ---------------------------------------------------------------------------
// Environmental bypasses (kept from M3.5): first-run registry-permission gate and
// the "open browser then quit" boot-exit branch. These are real headless-host
// concerns, unrelated to rendering, so they stay even under Approach B.
//
// PROBLEM (verified in Ghidra): early in Client_Main (0x004186d0), two
// self-contained registry-writing steps run --
//   1. Installer_RegisterFileAssociations (0x004a4180): registers .w2l file
//      associations, MIME types, App Paths, and Netscape URL handlers under HKCU
//      AND HKEY_USERS\.DEFAULT. The .DEFAULT write raises a blocking MessageBoxA
//      ("Can't open nor create registry element ... run this app first time on an
//      account that can modify the registry!") on an unprivileged account.
//   2. WebLaunch_SetWorkingDirectory (0x004a4db0): opens HKCU\Software\Wulfram.
// A headless server needs neither. Stubbing the shared leaf Cfg_RegOpenOrCreateSubkey
// is unsafe (it returns an HKEY via an out-param); instead we no-op the two
// self-contained callers, whose results Client_Main never reads back.
//
// We also no-op Shell_OpenUrlWithDefaultBrowser (0x004b8f70) so the headless server
// never spawns a web browser.

// void __cdecl(void). Caller-clean no-op; the original opens HKCU\Software\Wulfram.
auto __cdecl Stub_WebLaunch_SetWorkingDirectory() -> void {
    WFH_DEBUG("hook", "bypassed WebLaunch_SetWorkingDirectory");
}

// __fastcall(char* cmdline_in_ECX) -> void. MinHook __fastcall shim: ECX holds the
// single register argument, EDX is an unused dummy, no stack args, so the bare-`ret`
// callee cleanup matches the target's __fastcall frame (target epilogue is `ret`).
auto __fastcall Stub_Installer_RegisterFileAssociations(char* /*cmdline_ecx*/, int /*edx_unused*/)
    -> void {
    WFH_DEBUG("hook", "bypassed Installer_RegisterFileAssociations");
}

// void __cdecl(void* url) -> void. Caller-clean; the single stack arg is ignored.
// No-op so the default browser is never launched (the original WinExec's it).
auto __cdecl Stub_Shell_OpenUrlWithDefaultBrowser(void* /*url*/) -> void {
    WFH_DEBUG("hook", "bypassed Shell_OpenUrlWithDefaultBrowser (no browser launch)");
}

// ---------------------------------------------------------------------------
// M3.7 boot-exit guard.
//
// App_ExitGracefully (0x0041db40) is a NORETURN full-shutdown routine ending in
// _exit(). Diagnosed (via _ReturnAddress): the headless boot calls it EARLY in
// Client_Main, from the call site at 0x00418895 (return address 0x0041889A):
//
//   00418869 CMP byte [0x00677f4a],0 / JNZ skip
//   00418872 CMP byte [0x00679123],0 / JZ  skip      // web-launch guard
//   0041887b CMP byte [0x00677f48],0 / JNZ skip
//   00418884 Shell_OpenUrlWithDefaultBrowser(...)     // already no-op'd
//   00418895 App_ExitGracefully(0, 0)                 // <-- this exit
//   0041889A ADD ESP,8 ; ... continues into the rest of Client_Main
//
// This is the "open the Wulfram website, then quit" product-flow branch. We skip
// ONLY this exit so Client_Main continues toward the loop seam; every other caller
// (the legitimate shutdown sites) calls through unchanged, so real shutdown is
// intact.
//
// ABI: void __cdecl App_ExitGracefully(int, int) — confirmed in Ghidra
// (caller-clean, two stack args). The detour matches it exactly, so both the
// trampoline call-through and the early return are ABI-correct.

// Trampoline slot for the call-through. Filled by InstallDetour; this is the ONE
// detour that uses a real `original` (the no-op stubs leave it null).
// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
void* g_app_exit_gracefully_orig = nullptr;

// Module base of wulfram2.exe, used to log the caller as a module-relative RVA.
constexpr std::uintptr_t kModuleBase = 0x00400000;

// Return address of the boot-time App_ExitGracefully call site in Client_Main
// (instruction after CALL at 0x00418895). Identifies the one exit to skip.
constexpr std::uintptr_t kBootExitCallSiteRetAddr = 0x0041889A;

auto __cdecl Stub_App_ExitGracefully(int param_1, int param_2) -> void {
    // Immediate caller = the instruction after the CALL into App_ExitGracefully.
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    const auto ret_addr = reinterpret_cast<std::uintptr_t>(_ReturnAddress());

    if (ret_addr == kBootExitCallSiteRetAddr) {
        // The early boot-time browser-then-exit branch. The browser call is already
        // no-op'd; skip this exit so Client_Main continues toward the loop seam.
        WFH_INFO("boot",
                 "M3.7: skipped boot-time App_ExitGracefully(0x%X,0x%X) from Client_Main "
                 "(RVA=0x%X) — boot continues",
                 static_cast<unsigned>(param_1), static_cast<unsigned>(param_2),
                 static_cast<unsigned>(ret_addr - kModuleBase));
        return;
    }

    // Any other caller is a legitimate shutdown; call through unchanged (noreturn).
    WFH_WARN("boot",
             "App_ExitGracefully from VA=0x%X args=(0x%X,0x%X) — calling through (shutdown)",
             static_cast<unsigned>(ret_addr), static_cast<unsigned>(param_1),
             static_cast<unsigned>(param_2));
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    auto* const orig = reinterpret_cast<void(__cdecl*)(int, int)>(g_app_exit_gracefully_orig);
    orig(param_1, param_2);
}

// ---------------------------------------------------------------------------
// Client_RunMainLoop observation detour (the M4 server-tick hijack point).
//
// TEMP (M3): observation-only; M4 replaces the loop body.
// __cdecl() -> void. Logs arrival at the loop seam and RETURNS immediately WITHOUT
// calling the original (the real loop drives the present path). M4 replaces the
// loop body with the real headless server tick.
auto __cdecl Stub_Client_RunMainLoop_Observe() -> void {
    WFH_INFO("boot", "reached Client_RunMainLoop — head-chop OK");
}

// ---------------------------------------------------------------------------
// M4.1 connect-gate spoof.
//
// Client_Main's front-end loop only advances into the real game loop
// (App_RunGameAndExit @ 0x004a0b70 -> Client_RunMainLoop @ 0x004a0aa0) when the
// byte gate DAT_00677f1d != 0, which is read at 0x00418f9d. Natively that gate is
// set only by the network HELLO handshake (Net_HandleHello @ 0x0046d020 sets it on
// a version packet; Net_HandleVersionError sets it unconditionally). wulfram2.exe
// has NO in-binary dedicated server (Net_InitAccept* serve only the DbgNet debug
// port 6969), so there is nothing to loopback-connect to in-process. We therefore
// SPOOF "connected" by setting the gate ourselves at a safe point.
//
// Safe point: DbgNet_Init @ 0x004139e0 runs once near the END of Client_Main's
// init (after world/sim/collision/UI are all constructed), immediately before the
// front-end loop. We detour it to call through (real debug-net init) and THEN set
// the gate, so the first loop iteration takes the App_RunGameAndExit path.
//
// App_RunGameAndExit splits two version globals (DAT_005dd67c server, DAT_005dd674
// client) for the version display; Net_HandleHello normally fills them. We seed
// both with the client version (0x4e89 = 20105) so that math is sane.
//
// ABI: void __cdecl DbgNet_Init(void) — confirmed in Ghidra. Detour matches it, so
// the trampoline call-through is ABI-correct.

// VAs pinned here (gen/addresses.h holds functions only).
constexpr std::uint32_t kDbgNetInitVA = 0x004139e0;
constexpr std::uint32_t kConnectGateVA = 0x00677f1d;    // DAT_00677f1d
constexpr std::uint32_t kServerVersionVA = 0x005dd67c;  // DAT_005dd67c
constexpr std::uint32_t kClientVersionVA = 0x005dd674;  // DAT_005dd674
constexpr std::int32_t kClientVersion = 0x4e89;         // 20105

// Trampoline slot for the real DbgNet_Init (filled by InstallDetour).
// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
void* g_dbgnet_init_orig = nullptr;

auto __cdecl Stub_DbgNet_Init() -> void {
    // Run the real debug-net init first so its state is fully constructed.
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    auto* const orig = reinterpret_cast<void(__cdecl*)()>(g_dbgnet_init_orig);
    orig();

    // Seed the version globals App_RunGameAndExit reads, then flip the connect gate
    // so Client_Main enters App_RunGameAndExit -> Client_RunMainLoop on the next
    // loop iteration. (No real server exists to send HELLO; this is the spoof.)
    // NOLINTNEXTLINE(performance-no-int-to-ptr,clang-analyzer-core.FixedAddressDereference)
    *static_cast<volatile std::int32_t*>(TargetAt(kServerVersionVA)) = kClientVersion;
    // NOLINTNEXTLINE(performance-no-int-to-ptr,clang-analyzer-core.FixedAddressDereference)
    *static_cast<volatile std::int32_t*>(TargetAt(kClientVersionVA)) = kClientVersion;
    // NOLINTNEXTLINE(performance-no-int-to-ptr,clang-analyzer-core.FixedAddressDereference)
    *static_cast<volatile std::uint8_t*>(TargetAt(kConnectGateVA)) = 1;
    WFH_INFO("boot", "M4.1: connect gate spoofed (DAT_00677f1d=1) after DbgNet_Init — "
                     "Client_Main will enter Client_RunMainLoop");
}

// ---------------------------------------------------------------------------
// Install helpers.

// Install the registry-gate + browser bypass detours. The detours never call
// through, so each trampoline is discarded.
auto InstallRegistryGateBypass() -> bool {
    struct Bypass {
        const char* name;
        void* target;
        void* detour;
    };
    const std::array<Bypass, 3> bypasses = {{
        {"Installer_RegisterFileAssociations", TargetAt(addr::Installer_RegisterFileAssociations),
         AsVoidPtr(&Stub_Installer_RegisterFileAssociations)},
        {"WebLaunch_SetWorkingDirectory", TargetAt(addr::WebLaunch_SetWorkingDirectory),
         AsVoidPtr(&Stub_WebLaunch_SetWorkingDirectory)},
        {"Shell_OpenUrlWithDefaultBrowser", TargetAt(addr::Shell_OpenUrlWithDefaultBrowser),
         AsVoidPtr(&Stub_Shell_OpenUrlWithDefaultBrowser)},
    }};

    for (const Bypass& bypass : bypasses) {
        void* original = nullptr;
        if (!InstallDetour(bypass.target, bypass.detour, &original)) {
            WFH_FATAL("head", "failed to install %s bypass detour", bypass.name);
            return false;
        }
        WFH_INFO("head", "bypass detour installed: %s", bypass.name);
    }
    return true;
}

// M3.7: install the App_ExitGracefully boot-exit guard. UNLIKE the bypass stubs,
// this one CALLS THROUGH for non-boot callers, so it passes the real trampoline
// slot (g_app_exit_gracefully_orig) to InstallDetour. Returns true on success.
auto InstallAppExitGracefullyGuard() -> bool {
    if (!InstallDetour(TargetAt(addr::App_ExitGracefully), AsVoidPtr(&Stub_App_ExitGracefully),
                       &g_app_exit_gracefully_orig)) {
        WFH_FATAL("head", "M3.7: failed to install App_ExitGracefully boot-exit guard");
        return false;
    }
    WFH_INFO("head", "M3.7 boot-exit guard installed: App_ExitGracefully (skips boot exit, "
                     "calls through for real shutdown)");
    return true;
}

// M4.1: install the connect-gate spoof (DbgNet_Init detour). Calls through, so it
// passes the real trampoline slot (g_dbgnet_init_orig) to InstallDetour. Returns
// true on success.
auto InstallConnectGateSpoof() -> bool {
    if (!InstallDetour(TargetAt(kDbgNetInitVA), AsVoidPtr(&Stub_DbgNet_Init),
                       &g_dbgnet_init_orig)) {
        WFH_FATAL("head", "M4.1: failed to install DbgNet_Init connect-gate spoof");
        return false;
    }
    WFH_INFO("head",
             "M4.1 connect-gate spoof installed: DbgNet_Init (sets DAT_00677f1d after init)");
    return true;
}

// TEMP (M3): observation-only; M4 replaces the loop body. Install the
// Client_RunMainLoop observation detour. The detour never calls through, so the
// trampoline is discarded. Returns true on success.
auto InstallLoopObservationDetour() -> bool {
    void* original = nullptr;
    if (!InstallDetour(TargetAt(addr::Client_RunMainLoop),
                       AsVoidPtr(&Stub_Client_RunMainLoop_Observe), &original)) {
        WFH_FATAL("head", "failed to install Client_RunMainLoop observation detour");
        return false;
    }
    WFH_INFO("head", "TEMP (M3) observation detour installed: Client_RunMainLoop");
    return true;
}

}  // namespace

auto InstallHeadStubs() -> bool {
    // Approach B step 1: force the GDI "Software Windowed" renderer before the game
    // resumes, so Render_SwitchActiveDriver picks it and never hits the "Hokey
    // Display Card" error box.
    ForceSoftwareRenderer();

    // Approach B step 2: hook CreateWindowExA so the real main window comes up
    // hidden (no WS_VISIBLE, off the taskbar) with a still-valid GDI DC.
    if (!InstallWindowHider()) {
        return false;
    }

    // Bypass the first-run registry-permission gate and the browser launch (real
    // headless-host concerns, unrelated to rendering).
    if (!InstallRegistryGateBypass()) {
        return false;
    }

    // M3.7: skip ONLY the early "open website then quit" App_ExitGracefully so the
    // boot continues; real shutdown still calls through.
    if (!InstallAppExitGracefullyGuard()) {
        return false;
    }

    // M4.1: spoof the network connect gate (DAT_00677f1d) from a DbgNet_Init detour,
    // so Client_Main advances from the front-end into Client_RunMainLoop without a
    // real server (there is no in-binary server to loopback-connect to).
    if (!InstallConnectGateSpoof()) {
        return false;
    }

    // TEMP (M3): observation-only; the M4 server-tick hijack point. Live before the
    // loader resumes the game thread.
    return InstallLoopObservationDetour();
}

}  // namespace wfh
// NOLINTEND(cppcoreguidelines-avoid-do-while,cppcoreguidelines-pro-type-vararg)
