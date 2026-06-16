#include "head_stubs.hpp"

#include "engine_hooks.hpp"

#include "wfh/log.hpp"

#include "addresses.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>

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

// __cdecl() -> void.
auto __cdecl Stub_Winsys_Input_InitWin32State() -> void {
    WFH_DEBUG("head", "stubbed Winsys_Input_InitWin32State");
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

    // M3.4: short-circuit Render_SwitchActiveDriver and install a non-null no-op
    // render driver, so the boot does not hit the "no usable display mode" error
    // box and later DAT_00677e54 dispatches land on no-op thunks.
    if (!InstallRenderDriverDefense()) {
        return false;
    }

    // TEMP (M3): observation-only; M4 replaces the loop body. Install the loop
    // seam observation detour alongside the head stubs, so it is live before the
    // loader resumes the game thread.
    return InstallLoopObservationDetour();
}

}  // namespace wfh
// NOLINTEND(cppcoreguidelines-avoid-do-while,cppcoreguidelines-pro-type-vararg)
