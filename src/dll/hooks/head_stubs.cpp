#include "head_stubs.hpp"

#include "engine_hooks.hpp"

#include "wfh/log.hpp"

#include "addresses.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>

// <intrin.h> provides _ReturnAddress(), used by Stub_App_ExitGracefully (M3.7) to
// identify the calling site so it skips ONLY the boot-time exit.
#ifdef _MSC_VER
#pragma warning(push, 0)
#endif
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

// Turns an absolute VA into a void* target (see the definition below for the
// reinterpret_cast rationale). Forward-declared so the M3.4 detour, defined above
// it, can reuse it instead of open-coding the int->ptr cast.
auto TargetAt(std::uint32_t address) -> void*;

// M3.9: point the engine's keystate-buffer global (DAT_006785d8) at a static
// 256-byte buffer. Forward-declared so Stub_Winsys_Input_InitWin32State (defined
// above the definition) can call it. See the definition for the full rationale.
void EnsureKeystateBuffer();

// ---------------------------------------------------------------------------
// The 11 head detours. CRITICAL: MinHook invokes each detour in place of the
// target, so the detour's calling convention MUST byte-for-byte match the
// target's, or the stack/registers corrupt on return. Conventions per seam are
// taken from the Ghidra discovery; see the table in head_stubs.hpp's caller.
//
// All stubs are full no-ops: they log once at DEBUG and return the success value
// the original's callers expect. They NEVER call through to the trampoline, so
// the `original` slot passed to InstallDetour stays null.
//
// The calling convention sits between `auto` and the name (e.g. `auto __cdecl
// Foo() -> void`); this is the trailing-return spelling MSVC accepts and that
// satisfies the repo's modernize-use-trailing-return-type lint.
// ---------------------------------------------------------------------------

// __cdecl(void* driver) -> void. caller-clean stack; one stack arg.
auto __cdecl Stub_Render_InitDriverAndViewports(void* /*driver*/) -> void {
    WFH_DEBUG("head", "stubbed Render_InitDriverAndViewports");
}

// __cdecl(void*, int) -> void.
auto __cdecl Stub_Winsys_D3D_Init(void* /*a*/, int /*b*/) -> void {
    WFH_DEBUG("head", "stubbed Winsys_D3D_Init");
}

// __thiscall(this, int bool) -> 1U.
//
// MSVC rejects __thiscall on a free/static function, so we use the standard
// MinHook shim: define the detour as __fastcall with a dummy EDX parameter.
//   __thiscall: arg `this` in ECX, remaining args on the stack, callee-clean.
//   __fastcall: arg1 in ECX, arg2 in EDX, remaining args on the stack, callee-clean.
// Mapping ECX->self, EDX->(unused), first stack slot->flag reproduces the
// __thiscall frame exactly: `this` lands in ECX, the single `int bool` is the
// first stack argument, and both conventions are callee-clean so the `ret 4`
// stack adjustment matches what the __thiscall caller expects. Verified in the
// generated DLL: this stub epilogue is `ret 4`.
auto __fastcall Stub_Winsys_D3D_InitDevice(void* /*self_ecx*/, int /*edx_unused*/,
                                           int /*flag_stack*/) -> unsigned {
    WFH_DEBUG("head", "stubbed Winsys_D3D_InitDevice");
    return 1U;
}

// __cdecl(char*, int) -> void.
auto __cdecl Stub_Winsys_DX_Init(char* /*a*/, int /*b*/) -> void {
    WFH_DEBUG("head", "stubbed Winsys_DX_Init");
}

// __cdecl(int, int) -> void.
auto __cdecl Stub_Winsys_GDI_Init(int /*a*/, int /*b*/) -> void {
    WFH_DEBUG("head", "stubbed Winsys_GDI_Init");
}

// __cdecl(unsigned) -> void.
auto __cdecl Stub_Winsys_InitGlideRenderer(unsigned /*a*/) -> void {
    WFH_DEBUG("head", "stubbed Winsys_InitGlideRenderer");
}

// __cdecl() -> 1U.
auto __cdecl Stub_DirectDraw_InitAndSetCooperativeLevel() -> unsigned {
    WFH_DEBUG("head", "stubbed DirectDraw_InitAndSetCooperativeLevel");
    return 1U;
}

// __cdecl() -> 1U.
auto __cdecl Stub_DirectInput_InitMouse() -> unsigned {
    WFH_DEBUG("head", "stubbed DirectInput_InitMouse");
    return 1U;
}

// __cdecl() -> 0U (joystick reported absent, as the headless server wants).
auto __cdecl Stub_DirectInput_InitJoystick() -> unsigned {
    WFH_DEBUG("head", "stubbed DirectInput_InitJoystick");
    return 0U;
}

// __cdecl() -> void. The original allocates the 256-byte keystate buffer
// (DAT_006785d8) via Winsys_Input_PushKeyboardSnapshot; the body-side input poll
// (Winsys_Input_PollKeyboardState, run from Client_Main's loop) dereferences it.
// We skip real Win32 input bring-up but MUST leave that buffer non-null (M3.9).
auto __cdecl Stub_Winsys_Input_InitWin32State() -> void {
    EnsureKeystateBuffer();
    WFH_DEBUG("head", "stubbed Winsys_Input_InitWin32State (keystate buffer installed)");
}

// TEMP (M3): observation-only; M4 replaces the loop body.
//
// __cdecl() -> void. The real Client_RunMainLoop would drive the render/present
// path through the now-null render driver and crash; for the M3 boot smoke we
// only want to PROVE the game reached the loop seam headlessly. So this detour
// logs arrival and RETURNS immediately WITHOUT calling the original. M4 replaces
// the loop body with the real headless server tick.
auto __cdecl Stub_Client_RunMainLoop_Observe() -> void {
    WFH_INFO("boot", "reached Client_RunMainLoop — head-chop OK");
}

// __fastcall(int* self_in_ECX) -> bool/byte (1).
//
// Target is __fastcall with its only argument in ECX. A __fastcall detour with
// (ECX=self, EDX=unused) matches: arg1 in ECX, arg2 in EDX, no stack args, so
// zero-byte callee cleanup matches the target (verified: this stub epilogue is a
// bare `ret`). The original returns a bool/byte; returning `int` 1 here yields
// AL=1, the success value callers test.
auto __fastcall Stub_Snd_InitDevice(int* /*self_ecx*/, int /*edx_unused*/) -> int {
    WFH_DEBUG("head", "stubbed Snd_InitDevice");
    return 1;
}

// ---------------------------------------------------------------------------
// M3.5 first-run registry-permission gate bypass (two seams).
//
// PROBLEM (from the M3.5 smoke, verified in Ghidra 2026-06-16): the boot raises
// a blocking MessageBoxA ("Can't open nor create registry element:\n
// HKEY_USERS\.DEFAULT ... run this app first time on an account that can modify
// the registry!") inside Cfg_RegOpenOrCreateSubkey (0x0047e040 entry; box at
// 0x0047e0e2), which opens/creates registry keys with KEY_ALL_ACCESS (0xf003f).
// Two distinct call paths early in Client_Main (0x004186d0) hit it:
//   1. Cmd_ResolveStartupArgs (0x004183a0) -> Installer_RegisterFileAssociations
//      (0x004a4180): registers .w2l file associations, MIME types, App Paths, and
//      the Netscape Navigator URL handlers (Suffixes/Viewers) under HKCU AND
//      HKEY_USERS\.DEFAULT -- this is the seam raising the .DEFAULT access-denied
//      box (it touches HKEY_USERS\.DEFAULT, which an unprivileged account cannot
//      create). Runs FIRST.
//   2. WebLaunch_SetWorkingDirectory (0x004a4db0): opens HKCU\Software\Wulfram and
//      sets the working directory. Runs shortly after.
//
// A headless server needs NEITHER: it does not register OS file associations /
// Netscape URL handlers, and it does not need the client's HKCU install-dir
// config. We bypass BOTH self-contained steps.
//
// CHOICE OF STUB POINT (decompilation evidence):
//   - Stubbing the shared leaf Cfg_RegOpenOrCreateSubkey is UNSAFE: it is
//     `void __fastcall(char* subkeyName)` that does not return a status but writes
//     the opened HKEY back into its caller object at EDI+0x10 (out-param via a
//     register-passed `this`); a no-op would leave that HKEY stale and break the
//     callers that subsequently use it. So we stub the two SELF-CONTAINED callers
//     instead, each of which Client_Main calls for its side effects and never
//     reads a result back from.
//   - Installer_RegisterFileAssociations: Ghidra types it `__fastcall(char*)` with
//     its one argument in ECX (prologue `MOV ESI,ECX`), no return value used by
//     its caller, bare `ret` epilogue. The __fastcall detour shape (ECX=arg1,
//     EDX=dummy) matches byte-for-byte; zero stack args means zero callee cleanup,
//     matching the bare `ret`.
//   - WebLaunch_SetWorkingDirectory: `void __cdecl(void)` (no params, plain `ret`
//     epilogue, caller-clean) -- the safest possible detour shape.
//
// FIX: detour BOTH to no-ops that return immediately without running the
// originals, so neither registry-write path (and thus neither MessageBox) ever
// executes.
//
// M3.5b — "open browser then quit" boot-exit branch.
//
// PROBLEM (observed after the registry gate was cleared; verified in Ghidra):
// with the registry box gone, the boot ran further but the wulfram2 process then
// exited cleanly (exit code 0) AND launched the default browser to the Wulfram
// website. Traced to a branch in Client_Main @ 0x00418872:
//     if (DAT_00677f4a == 0 && DAT_00679123 != 0 && DAT_00677f48 == 0) {
//         Shell_OpenUrlWithDefaultBrowser(DAT_00679160);  // browser -> wulfram.com
//         App_ExitGracefully(0, 0);                        // then _exit(0)
//     }
// In our headless config DAT_00679123 is non-zero (set by the client init/reset
// globals), so this "launch the website then quit" path is taken before the loop
// seam. Shell_OpenUrlWithDefaultBrowser (0x004b8f70) reads HKCR\http\shell\open\
// command and WinExec's the browser with the URL; App_ExitGracefully (0x0041db40)
// is a NORETURN full-shutdown routine ending in _exit().
//
// FIX (two parts, both safe):
//   1. Detour Shell_OpenUrlWithDefaultBrowser -> no-op, so NO browser is ever
//      launched (covers this branch AND the second call inside App_ExitGracefully).
//      ABI: void __cdecl(void* url) -- caller-clean; the no-op ignores the arg.
//   2. Clear the branch guard DAT_00679123 from the WebLaunch_SetWorkingDirectory
//      stub (which runs immediately before the branch), so App_ExitGracefully is
//      never reached and the boot continues. DAT_00679123 is read in EXACTLY ONE
//      place (the Ghidra xref shows a single [READ] at 0x00418872, the branch
//      guard); it has no other consumer, so forcing it to 0 is side-effect-free.
//      App_ExitGracefully itself is intentionally NOT detoured: it is noreturn and
//      is also the legitimate shutdown path, so neutralizing it globally would be
//      unsafe -- skipping the branch is the surgical fix.

// VA of the boot-exit branch guard (DAT_00679123). Read only at Client_Main
// 0x00418872; cleared here so the "open browser then quit" branch is not taken.
// Not in gen/addresses.h (functions only), so pinned as the absolute VA the RE
// established (same convention as kRenderDriverPtrVA below).
constexpr std::uint32_t kBootExitBranchGuardVA = 0x00679123;

// void __cdecl(void). Caller-clean, no arguments, no return value. A __cdecl no-op
// detour matches byte-for-byte (verified: target epilogue is a bare `ret`). Also
// clears the boot-exit branch guard (DAT_00679123) so the immediately-following
// Client_Main branch does not launch the browser and App_ExitGracefully out.
auto __cdecl Stub_WebLaunch_SetWorkingDirectory() -> void {
    // NOLINTNEXTLINE(performance-no-int-to-ptr,clang-analyzer-core.FixedAddressDereference)
    *static_cast<volatile char*>(TargetAt(kBootExitBranchGuardVA)) = 0;
    WFH_DEBUG("hook", "bypassed WebLaunch_SetWorkingDirectory; cleared boot-exit branch guard");
}

// __fastcall(char* cmdline_in_ECX) -> void. Same MinHook __fastcall shim as
// Stub_Snd_InitDevice: ECX holds the single register argument, EDX is an unused
// dummy, and there are no stack args, so the bare-`ret` callee cleanup matches the
// target's __fastcall frame exactly (verified: target epilogue is a bare `ret`).
auto __fastcall Stub_Installer_RegisterFileAssociations(char* /*cmdline_ecx*/, int /*edx_unused*/)
    -> void {
    WFH_DEBUG("hook", "bypassed Installer_RegisterFileAssociations");
}

// void __cdecl(void* url) -> void. Caller-clean; the single stack arg is ignored.
// No-op so the default browser is never launched (the original WinExec's it). M3.5b.
auto __cdecl Stub_Shell_OpenUrlWithDefaultBrowser(void* /*url*/) -> void {
    WFH_DEBUG("hook", "bypassed Shell_OpenUrlWithDefaultBrowser (no browser launch)");
}

// ---------------------------------------------------------------------------
// M3.7 boot-exit guard.
//
// App_ExitGracefully (0x0041db40) is a NORETURN full-shutdown routine ending in
// _exit(). Diagnosed (M3.7, via _ReturnAddress): the headless boot calls it EARLY
// in Client_Main, from the call site at 0x00418895 (return address 0x0041889A):
//
//   00418869 CMP byte [0x00677f4a],0 / JNZ skip
//   00418872 CMP byte [0x00679123],0 / JZ  skip      // web-launch guard
//   0041887b CMP byte [0x00677f48],0 / JNZ skip
//   00418884 Shell_OpenUrlWithDefaultBrowser(...)     // already no-op'd
//   00418895 App_ExitGracefully(0, 0)                 // <-- this exit
//   0041889A ADD ESP,8 ; ... continues into the rest of Client_Main
//
// This is the "open the Wulfram website, then quit" product-flow branch. Its guard
// DAT_00679123 is statically 0 but reads non-zero here at runtime (set via an
// address with no static writer xref — an indirect/struct store), and is re-set
// AFTER the WebLaunch stub's early clear, so clearing it there does not hold.
//
// FIX: detour App_ExitGracefully and, ONLY when invoked from this exact boot-time
// call site (return address 0x0041889A) with args (0,0), RETURN instead of running
// the original. The call site has caller-side cleanup (ADD ESP,8) and falls
// straight into the rest of Client_Main, so returning is structurally safe and the
// boot proceeds toward the loop seam. EVERY OTHER caller (the legitimate shutdown
// sites) calls through unchanged, so real shutdown is intact.
//
// ABI: void __cdecl App_ExitGracefully(int, int) — confirmed in Ghidra
// (caller-clean, two stack args). The detour matches it exactly, so both the
// trampoline call-through and the early return are ABI-correct.

// Trampoline slot for the call-through. Filled by InstallDetour; this is the ONE
// head stub that uses a real `original` (the no-op stubs leave it null).
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
// M3.4 render-driver defense.
//
// PROBLEM (from the Ghidra trace, verified 2026-06-16): with the head *_Init
// seams stubbed, the boot still dies in Render_SwitchActiveDriver (0x00485f70,
// called from Client_Main 0x004186d0). Render_SwitchActiveDriver enumerates the
// display-driver registry via Winsys_SelectBestUsableRenderer (0x004b9aa0); with
// no usable renderer headless, that function calls Sys_ErrorBoxAndExit("Hokey
// Display Card or Driver?", "Can't find a usable display mode...") -- this is the
// "Error" message box observed, not an access violation. Even if that were
// bypassed, Client_Main later dereferences the render-driver object DAT_00677e54
// directly: (*(code*)DAT_00677e54[0x18])(0) and DAT_00677e54[0x12](...), so a
// detour that merely returns without leaving a non-null DAT_00677e54 would then
// NULL-deref.
//
// FIX: detour Render_SwitchActiveDriver to install a non-null no-op driver object
// into DAT_00677e54 and return 1 (success), WITHOUT running the original (so the
// renderer enumeration / error box never executes). All later DAT_00677e54[idx]
// dispatches then land on no-op thunks.
//
// ABI of the driver "vtable": the engine calls these slots caller-cleanup and
// with a VARYING argument count at the same index (e.g. slot 0xb is called with
// 2 args in Render_SwitchActiveDriver and 3 args in Render_InitDriverAndViewports,
// with `this` passed explicitly as the first stack arg, not in ECX). Only
// caller-cleanup __cdecl tolerates a fixed thunk under a varying arg count, so the
// no-op thunk is __cdecl with a bare `ret` -- correct regardless of how many args
// any given slot is invoked with. Verified against the decompiled call sites.
//
// VA of the global render-driver object pointer, from the M3 discovery
// (DAT_00677e54). Not in gen/addresses.h (that file lists functions only), so it
// is pinned here as the absolute VA the RE established.
constexpr std::uint32_t kRenderDriverPtrVA = 0x00677e54;

// M3.8 viewport defense. Render_InitDriverAndViewports (which M3.4 no-ops) is what
// normally allocates the six render viewports (operator_new(0x3c) each) and stores
// them into these six globals. With it stubbed they stay NULL, and the body-side
// Viewport_InitManager (0x004283e0, runs unconditionally in Client_Main) does
// `DAT_00677fa4 = DAT_005f56ac; Viewport_SetProjectionScale(...)`, and
// Viewport_SetProjectionScale (0x004282d0) reads *DAT_00677fa4 / DAT_00677fa4[1]
// (the viewport's width/height floats) -> NULL deref (AV at 0x004282e4, confirmed
// by cdb). Provide one non-null stub viewport with sane dimensions and point all
// six globals at it so these reads return finite numbers headlessly.
constexpr std::array<std::uint32_t, 6> kViewportGlobalVAs = {0x005f567c, 0x005f56b8, 0x005f56a8,
                                                             0x005f552c, 0x005f5698, 0x005f56ac};

// A single caller-cleanup no-op returning 0. Used for every driver-object slot
// and every entry of the stub vtable. __cdecl == caller-cleanup, so a bare `ret`
// is stack-safe no matter how many arguments a call site pushes.
auto __cdecl RenderDriver_NoOp() -> int {
    return 0;
}

// Layout the engine assumes for the render-driver object (DAT_00677e54):
//   - slot [0] is a POINTER to a vtable (the engine does (**(code**)*obj)()),
//   - every other slot [idx] is itself a function pointer (the engine does
//     (*(code*)obj[idx])(...)).
// We satisfy both: slot [0] points at an all-no-op vtable; slots [1..] each hold
// the no-op thunk directly. Sized well past the highest index/field the boot path
// touches (max observed ~0x19 as a call, +0xd8 as a field) so any stray field
// read yields a harmless non-null value rather than running off the object.
constexpr std::size_t kStubDriverSlots = 0x100;

struct StubRenderDriver {
    std::array<void*, kStubDriverSlots> vtable;
    std::array<void*, kStubDriverSlots> object;
};

// Static storage: lives for the process lifetime, so DAT_00677e54 stays valid for
// every later dispatch. Filled once on first install. It is intentionally a
// mutable namespace-scope object: it IS the render-driver instance the engine
// dispatches through, so it cannot be const.
// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
StubRenderDriver g_stub_driver{};

auto StubDriverObject() -> void* {
    // `thunk` is stored into arrays of void* (non-const), so it must itself be a
    // non-const void*; cppcheck's pointer-to-const suggestion does not apply here.
    // cppcheck-suppress constVariablePointer
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    void* const thunk = reinterpret_cast<void*>(&RenderDriver_NoOp);
    std::fill(g_stub_driver.vtable.begin(), g_stub_driver.vtable.end(), thunk);
    std::fill(g_stub_driver.object.begin(), g_stub_driver.object.end(), thunk);
    // Slot [0] of the object must be the vtable pointer, not a raw thunk.
    g_stub_driver.object.front() = static_cast<void*>(g_stub_driver.vtable.data());
    return static_cast<void*>(g_stub_driver.object.data());
}

// Stub viewport size in dwords: covers the 0x3c-byte (15-dword) object the
// original Render_InitDriverAndViewports allocates, with margin.
constexpr std::size_t kStubViewportSlots = 0x40;

// M3.8: a single stub viewport object. The engine reads index [0]=width and
// [1]=height as floats (Viewport_SetProjectionScale / Viewport_RecomputeCachedBounds)
// and treats other slots as ints/zeros. Width/height are a sane headless default
// (640x480) so projection math produces finite values. Process-lifetime static;
// intentionally mutable.
// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
std::array<std::uint32_t, kStubViewportSlots> g_stub_viewport{};

auto StubViewportObject() -> std::uint32_t {
    constexpr float kWidth = 640.0F;
    constexpr float kHeight = 480.0F;
    std::fill(g_stub_viewport.begin(), g_stub_viewport.end(), 0U);
    // Reinterpret the float bit patterns into the int slots the engine reads back
    // as floats. memcpy avoids a strict-aliasing violation.
    std::memcpy(&g_stub_viewport.at(0), &kWidth, sizeof(float));
    std::memcpy(&g_stub_viewport.at(1), &kHeight, sizeof(float));
    // The engine's viewport globals are 32-bit pointer slots in this 32-bit build,
    // so narrowing the address to uint32 to store there is exactly intended.
    // cppcheck-suppress CastAddressToIntegerAtReturn
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    return static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(g_stub_viewport.data()));
}

// M3.8: point all six render-viewport globals at the one stub viewport, so the
// unconditional Viewport_InitManager path (and any later viewport read) sees a
// non-null object with finite dimensions instead of the NULL left by the stubbed
// Render_InitDriverAndViewports.
void InstallStubViewports() {
    const std::uint32_t viewport = StubViewportObject();
    for (const std::uint32_t global_va : kViewportGlobalVAs) {
        // NOLINTNEXTLINE(clang-analyzer-core.FixedAddressDereference)
        *static_cast<std::uint32_t*>(TargetAt(global_va)) = viewport;
    }
    WFH_INFO("head", "M3.8: installed stub viewport (640x480) into 6 viewport globals");
}

// VA of the engine keystate-buffer pointer (DAT_006785d8). The original
// Winsys_Input_PushKeyboardSnapshot malloc's 256 bytes and stores them here; the
// body loop's Winsys_Input_PollKeyboardState reads/writes *(DAT_006785d8 + i) for
// i in [0,0x100). Pinned VA (functions-only addresses.h).
constexpr std::uint32_t kKeystateBufferPtrVA = 0x006785d8;

// Keystate buffer size: the engine indexes it for virtual-key codes [0, 0x100).
constexpr std::size_t kKeystateBufferSize = 0x100;

// 256-byte keystate buffer the engine expects DAT_006785d8 to point at. Static,
// zero-initialized, process lifetime. Intentionally mutable: the engine reads and
// writes it every input poll.
// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
std::array<std::uint8_t, kKeystateBufferSize> g_keystate_buffer{};

// M3.9: ensure DAT_006785d8 is non-null. Idempotent (only sets it if still null),
// so it is safe even if the engine later allocates its own. Called from the
// Winsys_Input_InitWin32State stub, before the body loop polls input.
void EnsureKeystateBuffer() {
    auto** const slot = static_cast<void**>(TargetAt(kKeystateBufferPtrVA));
    // NOLINTNEXTLINE(clang-analyzer-core.FixedAddressDereference)
    if (*slot == nullptr) {
        *slot = static_cast<void*>(g_keystate_buffer.data());
        WFH_INFO("head", "M3.9: installed 256-byte stub keystate buffer (DAT_006785d8)");
    }
}

// M3.4: replaces Render_SwitchActiveDriver. Installs the non-null no-op driver and
// reports success; never calls the original (so Winsys_SelectBestUsableRenderer /
// the "Hokey Display Card" error box never runs). Returns 1 (uint success), which
// is what Client_Main and the other callers test.
//
// uint __cdecl Render_SwitchActiveDriver(void) -- signature confirmed in Ghidra.
auto __cdecl Stub_Render_SwitchActiveDriver() -> unsigned {
    // Writing the engine global at its fixed VA is the whole point of this detour;
    // the int->ptr cast and the fixed-address store are intentional and safe.
    // TargetAt() carries the int->ptr NOLINT; the void*->void** cast is benign.
    auto** const driver_ptr = static_cast<void**>(TargetAt(kRenderDriverPtrVA));
    // NOLINTNEXTLINE(clang-analyzer-core.FixedAddressDereference)
    *driver_ptr = StubDriverObject();
    WFH_INFO("head", "M3.4: Render_SwitchActiveDriver short-circuited; no-op driver installed");
    // M3.8: also populate the six viewport globals the stubbed
    // Render_InitDriverAndViewports would have filled, so the unconditional
    // Viewport_InitManager path does not NULL-deref.
    InstallStubViewports();
    // M3.9: ensure the keystate buffer is live here too. Render_SwitchActiveDriver
    // runs unconditionally on the boot path (whereas the Winsys_Input_InitWin32State
    // stub may be skipped), and the body loop's input poll dereferences it.
    EnsureKeystateBuffer();
    return 1U;
}

// One entry per seam. `target` is the absolute VA from gen/addresses.h; `detour`
// is the matching stub above. reinterpret_cast on both ends is unavoidable:
// turning an absolute integer address and a typed function pointer into the
// untyped void* InstallDetour expects is the entire point here (read-only, never
// dereferenced as the wrong type by us -- MinHook only patches the bytes).
struct HeadStub {
    const char* name;
    void* target;
    void* detour;
};

template <typename Func> auto AsVoidPtr(Func func) -> void* {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    return reinterpret_cast<void*>(func);
}

auto TargetAt(std::uint32_t address) -> void* {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast,performance-no-int-to-ptr)
    return reinterpret_cast<void*>(static_cast<std::uintptr_t>(address));
}

constexpr std::size_t kHeadStubCount = 11;

// TEMP (M3): observation-only; M4 replaces the loop body. Install the
// Client_RunMainLoop observation detour. Kept as its own helper so InstallHeadStubs
// stays under the cognitive-complexity gate and the temp detour is easy to remove
// in M4. Returns true on success; logs and returns false on MinHook error.
auto InstallLoopObservationDetour() -> bool {
    // The detour never calls through, so the trampoline is discarded.
    void* original = nullptr;
    if (!InstallDetour(TargetAt(addr::Client_RunMainLoop),
                       AsVoidPtr(&Stub_Client_RunMainLoop_Observe), &original)) {
        WFH_FATAL("head", "failed to install Client_RunMainLoop observation detour");
        return false;
    }
    WFH_INFO("head", "TEMP (M3) observation detour installed: Client_RunMainLoop");
    return true;
}

// M3.4: install the Render_SwitchActiveDriver defense detour (see the block above
// Stub_Render_SwitchActiveDriver). Returns true on success; logs and returns false
// on MinHook error. The detour never calls through, so the trampoline is discarded.
auto InstallRenderDriverDefense() -> bool {
    void* original = nullptr;
    if (!InstallDetour(TargetAt(addr::Render_SwitchActiveDriver),
                       AsVoidPtr(&Stub_Render_SwitchActiveDriver), &original)) {
        WFH_FATAL("head", "M3.4: failed to install Render_SwitchActiveDriver defense detour");
        return false;
    }
    WFH_INFO("head", "M3.4 defense detour installed: Render_SwitchActiveDriver");
    return true;
}

// M3.5: install the first-run registry-gate bypass detours (see the block above
// Stub_WebLaunch_SetWorkingDirectory). Both seams that write the registry early in
// Client_Main are short-circuited: Installer_RegisterFileAssociations (file
// associations + Netscape URL handlers, the .DEFAULT box) and
// WebLaunch_SetWorkingDirectory (HKCU\Software\Wulfram config). Returns true on
// success; logs and returns false on the first MinHook error. The detours never
// call through, so each trampoline is discarded.
auto InstallRegistryGateBypass() -> bool {
    // M3.5b Shell_OpenUrlWithDefaultBrowser no-ops the browser launch so the "open
    // website then quit" branch in Client_Main never spawns the default browser;
    // that branch's graceful exit is separately prevented by clearing DAT_00679123
    // in the WebLaunch stub.
    const std::array<HeadStub, 3> bypasses = {{
        {"Installer_RegisterFileAssociations", TargetAt(addr::Installer_RegisterFileAssociations),
         AsVoidPtr(&Stub_Installer_RegisterFileAssociations)},
        {"WebLaunch_SetWorkingDirectory", TargetAt(addr::WebLaunch_SetWorkingDirectory),
         AsVoidPtr(&Stub_WebLaunch_SetWorkingDirectory)},
        {"Shell_OpenUrlWithDefaultBrowser", TargetAt(addr::Shell_OpenUrlWithDefaultBrowser),
         AsVoidPtr(&Stub_Shell_OpenUrlWithDefaultBrowser)},
    }};

    for (const HeadStub& bypass : bypasses) {
        // The bypass detours never call through, so the trampoline is discarded.
        void* original = nullptr;
        if (!InstallDetour(bypass.target, bypass.detour, &original)) {
            WFH_FATAL("head", "M3.5: failed to install %s bypass detour", bypass.name);
            return false;
        }
        WFH_INFO("head", "M3.5 bypass detour installed: %s", bypass.name);
    }
    return true;
}

// M3.7: install the App_ExitGracefully boot-exit guard. UNLIKE every other head
// stub, this one CALLS THROUGH for non-boot callers, so it passes the real
// trampoline slot (g_app_exit_gracefully_orig) to InstallDetour. Returns true on
// success.
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

}  // namespace

auto InstallHeadStubs() -> bool {
    const std::array<HeadStub, kHeadStubCount> stubs = {{
        {"Render_InitDriverAndViewports", TargetAt(addr::Render_InitDriverAndViewports),
         AsVoidPtr(&Stub_Render_InitDriverAndViewports)},
        {"Winsys_D3D_Init", TargetAt(addr::Winsys_D3D_Init), AsVoidPtr(&Stub_Winsys_D3D_Init)},
        {"Winsys_D3D_InitDevice", TargetAt(addr::Winsys_D3D_InitDevice),
         AsVoidPtr(&Stub_Winsys_D3D_InitDevice)},
        {"Winsys_DX_Init", TargetAt(addr::Winsys_DX_Init), AsVoidPtr(&Stub_Winsys_DX_Init)},
        {"Winsys_GDI_Init", TargetAt(addr::Winsys_GDI_Init), AsVoidPtr(&Stub_Winsys_GDI_Init)},
        {"Winsys_InitGlideRenderer", TargetAt(addr::Winsys_InitGlideRenderer),
         AsVoidPtr(&Stub_Winsys_InitGlideRenderer)},
        {"DirectDraw_InitAndSetCooperativeLevel",
         TargetAt(addr::DirectDraw_InitAndSetCooperativeLevel),
         AsVoidPtr(&Stub_DirectDraw_InitAndSetCooperativeLevel)},
        {"DirectInput_InitMouse", TargetAt(addr::DirectInput_InitMouse),
         AsVoidPtr(&Stub_DirectInput_InitMouse)},
        {"DirectInput_InitJoystick", TargetAt(addr::DirectInput_InitJoystick),
         AsVoidPtr(&Stub_DirectInput_InitJoystick)},
        {"Winsys_Input_InitWin32State", TargetAt(addr::Winsys_Input_InitWin32State),
         AsVoidPtr(&Stub_Winsys_Input_InitWin32State)},
        {"Snd_InitDevice", TargetAt(addr::Snd_InitDevice), AsVoidPtr(&Stub_Snd_InitDevice)},
    }};

    for (const HeadStub& stub : stubs) {
        // The stubs never call through, so we discard the trampoline. A per-call
        // local keeps each MH_CreateHook's `original` slot valid and independent.
        void* original = nullptr;
        if (!InstallDetour(stub.target, stub.detour, &original)) {
            WFH_FATAL("head", "InstallHeadStubs: failed to install detour for %s", stub.name);
            return false;
        }
        WFH_INFO("head", "head stub installed: %s", stub.name);
    }

    WFH_INFO("head", "all %zu head stubs installed", kHeadStubCount);

    // M3.5: bypass the first-run registry-permission gate
    // (WebLaunch_SetWorkingDirectory), which otherwise raises a blocking
    // MessageBox early in Client_Main, before the render path.
    if (!InstallRegistryGateBypass()) {
        return false;
    }

    // M3.4: short-circuit Render_SwitchActiveDriver and install a non-null no-op
    // render driver, so the boot does not hit the "no usable display mode" error
    // box and later DAT_00677e54 dispatches land on no-op thunks.
    if (!InstallRenderDriverDefense()) {
        return false;
    }

    // M3.7: install the App_ExitGracefully boot-exit guard so the early browser-
    // then-exit branch in Client_Main does not terminate the headless boot.
    if (!InstallAppExitGracefullyGuard()) {
        return false;
    }

    // TEMP (M3): observation-only; M4 replaces the loop body. Install the loop
    // seam observation detour alongside the head stubs, so it is live before the
    // loader resumes the game thread.
    return InstallLoopObservationDetour();
}

}  // namespace wfh
// NOLINTEND(cppcoreguidelines-avoid-do-while,cppcoreguidelines-pro-type-vararg)
