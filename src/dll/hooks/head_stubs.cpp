#include "head_stubs.hpp"

#include "engine_hooks.hpp"

#include "wfh/log.hpp"

#include "addresses.h"

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

    // TEMP (M3): observation-only; M4 replaces the loop body. Install the loop
    // seam observation detour alongside the head stubs, so it is live before the
    // loader resumes the game thread.
    return InstallLoopObservationDetour();
}

}  // namespace wfh
// NOLINTEND(cppcoreguidelines-avoid-do-while,cppcoreguidelines-pro-type-vararg)
