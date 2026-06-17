#include "wfh/server/world_host.hpp"

#include <utility>

namespace wfh::server {

WorldBootstrap::WorldBootstrap(WorldHostPlan plan) : plan_(std::move(plan)) {}

void WorldBootstrap::Begin() {
    // Idempotent: only the initial Idle -> Reset transition starts the sequence;
    // a later call while already in progress (or complete) must not rewind.
    if (phase_ == WorldHostPhase::Idle) {
        phase_ = WorldHostPhase::Reset;
    }
}

auto WorldBootstrap::Advance() -> WorldHostAction {
    switch (phase_) {
    case WorldHostPhase::Reset: phase_ = WorldHostPhase::Load; return WorldHostAction::ResetSession;
    case WorldHostPhase::Load: phase_ = WorldHostPhase::Spawn; return WorldHostAction::LoadWorld;
    case WorldHostPhase::Spawn:
        phase_ = WorldHostPhase::Complete;
        return WorldHostAction::SpawnEntity;
    case WorldHostPhase::Idle:
    case WorldHostPhase::Complete: return WorldHostAction::None;
    }
    return WorldHostAction::None;
}

}  // namespace wfh::server
