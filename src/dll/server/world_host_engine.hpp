// NOLINTBEGIN(portability-avoid-pragma-once)
// pragma once is the project-wide include-guard convention; intentional.
#pragma once
// NOLINTEND(portability-avoid-pragma-once)

namespace wfh::server {

// Drive the headless world-host bootstrap one step per engine tick. Called from the
// SEH-guarded server tick (Net_ServiceConnection seam) on the engine main thread.
// No-op unless [server] world_host is set. This is the bridge layer: the ONLY code
// that calls engine world functions. It owns a process-lifetime WorldBootstrap (the
// pure, host-tested sequencer) and performs the real engine work for each action.
void ProcessWorldHostTick();

}  // namespace wfh::server
