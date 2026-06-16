// NOLINTBEGIN(portability-avoid-pragma-once)
// pragma once is the project-wide include-guard convention; intentional.
#pragma once
// NOLINTEND(portability-avoid-pragma-once)
#include <windows.h>

#include <string>

namespace wfh {

// Builds the per-process name of the manual-reset event the DLL's InitThread
// signals once it has installed its hooks, and the loader waits on before it
// resumes the (still-suspended) game's main thread. Keyed by the target PID so
// concurrent injections never collide. The "Local\\" prefix scopes the event to
// the current session, which is sufficient: loader and target share a session.
//
// Header-only and pure so it can be unit-tested directly and so both the loader
// (wfh_loader_core) and the DLL (wulf_headless) build the IDENTICAL string.
inline auto ReadyEventName(DWORD pid) -> std::wstring {
    return L"Local\\WulfHeadlessReady_" + std::to_wstring(pid);
}

}  // namespace wfh
