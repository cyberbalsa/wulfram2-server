// NOLINTBEGIN(portability-avoid-pragma-once)
// pragma once is the project-wide include-guard convention; intentional.
#pragma once
// NOLINTEND(portability-avoid-pragma-once)

namespace wfh {

// Thin, logged wrapper over MinHook. Lives in the DLL only; the engine is hooked
// in-process from InitThread. None of these touch global state we own beyond
// MinHook's own singleton, so call order is: HooksInit() once, InstallDetour()
// per seam, HooksShutdown() at teardown.

// MH_Initialize(). Logs and returns false on any MinHook error.
auto HooksInit() -> bool;

// MH_CreateHook(target, detour, original) then MH_EnableHook(target). Logs the
// target address and each step; on any MinHook error logs the status string and
// returns false. `original` receives the trampoline used to call the original
// function; it may be null when the detour never calls through (e.g. the M3 head
// stubs), but is kept in the signature for generality.
auto InstallDetour(void* target, void* detour, void** original) -> bool;

// MH_DisableHook(MH_ALL_HOOKS) + MH_Uninitialize(). Best-effort; errors are
// logged but not propagated, since this runs on a teardown path.
void HooksShutdown();

}  // namespace wfh
