// NOLINTBEGIN(portability-avoid-pragma-once)
// pragma once is the project-wide include-guard convention; intentional.
#pragma once
// NOLINTEND(portability-avoid-pragma-once)

namespace wfh {

// Install no-op detours over the 11 head `*_Init` seams discovered in
// wulfram2.exe (Milestone 3.3). Each detour logs once and returns the success
// value its callers expect WITHOUT calling through to the original, so the
// game's graphics/sound/input bring-up is fully short-circuited (the head is
// "chopped" so only the server-relevant tail keeps running headless).
//
// Must be called AFTER HooksInit() (MinHook must be live) and BEFORE the loader
// resumes the suspended game thread, so every detour is enabled before any of
// these seams can be reached.
//
// Returns true only if ALL detours installed; on the first failure it logs the
// offending seam and returns false (the caller aborts WITHOUT signaling ready).
auto InstallHeadStubs() -> bool;

}  // namespace wfh
