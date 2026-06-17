// NOLINTBEGIN(portability-avoid-pragma-once)
// pragma once is the project-wide include-guard convention; intentional.
#pragma once
// NOLINTEND(portability-avoid-pragma-once)

namespace wfh::server {

// Register the dev-console engine handler (executes `call`/`bt` — the verbs the
// host-testable socket layer can't do because they touch engine ABI/threads). Call once
// during init, after the dev console is started.
void InstallDevEngine();

// Drain a pending dev `call` (running it on THIS thread) and record the engine thread id
// for `bt`. MUST be called from the engine tick thread (ServerTickBody), inside the
// SEH-guarded tick. Cheap no-op when nothing is pending.
void PumpDevEngine();

}  // namespace wfh::server
