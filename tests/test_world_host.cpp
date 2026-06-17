#include "wfh/server/world_host.hpp"

#include <gtest/gtest.h>

#include <vector>

namespace {

using wfh::server::WorldBootstrap;
using wfh::server::WorldHostAction;
using wfh::server::WorldHostPhase;
using wfh::server::WorldHostPlan;

auto MakePlan() -> WorldHostPlan {
    WorldHostPlan plan;
    plan.map_name = "bpass";
    plan.entity.oid = 7;
    plan.entity.unit_type = 1;
    plan.entity.team = 2;
    plan.entity.pos = {10.0F, 20.0F, 30.0F};
    plan.entity.rot = {0.1F, 0.2F, 0.3F};
    return plan;
}

// Drain the full action sequence by ticking Advance() until it reports done.
auto DrainActions(WorldBootstrap& bootstrap, int max_ticks) -> std::vector<WorldHostAction> {
    std::vector<WorldHostAction> actions;
    for (int i = 0; i < max_ticks && !bootstrap.done(); ++i) {
        const WorldHostAction action = bootstrap.Advance();
        if (action != WorldHostAction::None) {
            actions.push_back(action);
        }
    }
    return actions;
}

}  // namespace

TEST(WorldBootstrap, StartsIdleAndEmitsNothingUntilBegun) {
    WorldBootstrap bootstrap(MakePlan());

    EXPECT_FALSE(bootstrap.started());
    EXPECT_FALSE(bootstrap.done());
    EXPECT_EQ(bootstrap.phase(), WorldHostPhase::Idle);
    // Ticking before Begin() must not perform any engine action.
    EXPECT_EQ(bootstrap.Advance(), WorldHostAction::None);
    EXPECT_EQ(bootstrap.phase(), WorldHostPhase::Idle);
}

TEST(WorldBootstrap, BeginMovesToResetPhase) {
    WorldBootstrap bootstrap(MakePlan());

    bootstrap.Begin();

    EXPECT_TRUE(bootstrap.started());
    EXPECT_FALSE(bootstrap.done());
    EXPECT_EQ(bootstrap.phase(), WorldHostPhase::Reset);
}

TEST(WorldBootstrap, AdvanceWalksTheCanonicalBringupSequenceOnce) {
    WorldBootstrap bootstrap(MakePlan());
    bootstrap.Begin();

    const std::vector<WorldHostAction> actions = DrainActions(bootstrap, 16);

    // Engine-faithful order: Net_HandleWorldStats does Game_ResetSession +
    // Client_SetCurrentWorld (no screen-mode flip), then a spawn. Loading the world
    // is itself "game mode" headless: physics ticks once DAT_006785e4 is set.
    const std::vector<WorldHostAction> expected = {
        WorldHostAction::ResetSession, WorldHostAction::LoadWorld, WorldHostAction::SpawnEntity};
    EXPECT_EQ(actions, expected);
    EXPECT_TRUE(bootstrap.done());
    EXPECT_EQ(bootstrap.phase(), WorldHostPhase::Complete);
}

TEST(WorldBootstrap, AdvanceIsOneActionPerTick) {
    WorldBootstrap bootstrap(MakePlan());
    bootstrap.Begin();

    EXPECT_EQ(bootstrap.Advance(), WorldHostAction::ResetSession);
    EXPECT_EQ(bootstrap.Advance(), WorldHostAction::LoadWorld);
    EXPECT_EQ(bootstrap.Advance(), WorldHostAction::SpawnEntity);
    EXPECT_EQ(bootstrap.Advance(), WorldHostAction::None);
}

TEST(WorldBootstrap, AdvanceIsIdempotentOnceComplete) {
    WorldBootstrap bootstrap(MakePlan());
    bootstrap.Begin();
    DrainActions(bootstrap, 16);

    ASSERT_TRUE(bootstrap.done());
    EXPECT_EQ(bootstrap.Advance(), WorldHostAction::None);
    EXPECT_EQ(bootstrap.Advance(), WorldHostAction::None);
    EXPECT_TRUE(bootstrap.done());
}

TEST(WorldBootstrap, BeginIsIdempotentAndDoesNotRewindProgress) {
    WorldBootstrap bootstrap(MakePlan());
    bootstrap.Begin();
    EXPECT_EQ(bootstrap.Advance(), WorldHostAction::ResetSession);

    bootstrap.Begin();  // second Begin must not restart the sequence

    EXPECT_EQ(bootstrap.phase(), WorldHostPhase::Load);
    EXPECT_EQ(bootstrap.Advance(), WorldHostAction::LoadWorld);
}

TEST(WorldBootstrap, RetainsPlan) {
    WorldBootstrap bootstrap(MakePlan());

    EXPECT_EQ(bootstrap.plan().map_name, "bpass");
    EXPECT_EQ(bootstrap.plan().entity.oid, 7);
    EXPECT_EQ(bootstrap.plan().entity.team, 2);
    EXPECT_FLOAT_EQ(bootstrap.plan().entity.pos[1], 20.0F);
}
