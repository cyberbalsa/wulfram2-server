// NOLINTBEGIN(portability-avoid-pragma-once)
// pragma once is the project-wide include-guard convention; intentional.
#pragma once
// NOLINTEND(portability-avoid-pragma-once)

#include <array>
#include <cstdint>
#include <string>

namespace wfh::server {

// ===========================================================================
// WorldBootstrap — the pure sequencing brain for the headless "engine owns the
// world" bring-up (M5.4-min). It decides, one step per tick, which engine action
// the tick thread should perform to take the headless engine from a fresh boot to
// an in-game world with one authoritative entity spawned.
//
// Like Connection, this class touches NO engine memory and performs NO engine
// calls — it is fully host-testable by ticking Advance() and asserting the action
// sequence. The DLL-side engine glue (Game_ResetSession / Client_SetCurrentWorld /
// Screen_SwitchMode / Obj_Create+Obj_InitFromSpawn) reads the action + plan and
// performs the real, SEH-guarded engine work.
//
// Canonical order is load-bearing and mirrors the engine's OWN world-entry
// (Net_HandleWorldStats @ 0x46cf50 does Game_ResetSession(0) then
// Client_SetCurrentWorld(...)): reset the session, load the map (terrain +
// spatial/collision tree), THEN spawn — the engine's spawn path pushes into the
// world list and spatial index built by the load step, so spawning before load
// would fault. There is no separate "enter game mode" step: loading the world IS
// game mode headless (Client_Main ticks physics once DAT_006785e4 is set); the
// screen-mode enum is the local rendering client's camera, which a server lacks.
// ===========================================================================

// One engine action to perform this tick. The glue maps each to an engine call.
// NOLINTNEXTLINE(performance-enum-size)
enum class WorldHostAction : int {
    None,          // nothing to do (not started, waiting, or complete)
    ResetSession,  // Game_ResetSession(0): clean session, destroy stale entities
    LoadWorld,     // Client_SetCurrentWorld(map): load terrain + spatial tree
    SpawnEntity,   // Obj_Create + Obj_InitFromSpawn: one authoritative entity
};

// What the bootstrap will do on the NEXT Advance(); also the progress indicator.
// NOLINTNEXTLINE(performance-enum-size)
enum class WorldHostPhase : int {
    Idle,      // Begin() not called yet
    Reset,     // next Advance() -> ResetSession
    Load,      // next Advance() -> LoadWorld
    Spawn,     // next Advance() -> SpawnEntity
    Complete,  // bring-up done
};

// The one authoritative entity to spawn (M5.4-min proves the spawn/world path with
// a single object; M6 scales to the full world). Plain value type.
struct WorldHostEntitySpec {
    std::int32_t oid = 1;                        // OID handed to Obj_Create (engine registers it)
    std::int32_t unit_type = 1;                  // engine unit type id (1 = tank)
    std::int32_t owner = 0;                      // owning player id (0 = server-owned)
    std::int32_t team = 1;                       // team id
    std::array<float, 3> pos{0.0F, 0.0F, 0.0F};  // spawn position
    std::array<float, 3> rot{0.0F, 0.0F, 0.0F};  // spawn euler orientation
};

// What to bring up: which map and which entity. Defaults match the project map.
struct WorldHostPlan {
    std::string map_name = "bpass";
    WorldHostEntitySpec entity;
};

class WorldBootstrap {
public:
    explicit WorldBootstrap(WorldHostPlan plan);

    [[nodiscard]] auto phase() const -> WorldHostPhase { return phase_; }
    [[nodiscard]] auto started() const -> bool { return phase_ != WorldHostPhase::Idle; }
    [[nodiscard]] auto done() const -> bool { return phase_ == WorldHostPhase::Complete; }
    [[nodiscard]] auto plan() const -> const WorldHostPlan& { return plan_; }

    // Called by the glue once it decides the engine is ready to be bootstrapped
    // (e.g. after a few settle ticks). Idempotent: a second call never rewinds
    // progress. Before Begin(), Advance() returns None.
    void Begin();

    // Perform-one-step-per-tick: returns the action the caller must perform this
    // tick and advances past it. Returns None when not started or already complete.
    // Call exactly once per tick.
    auto Advance() -> WorldHostAction;

private:
    WorldHostPlan plan_;
    WorldHostPhase phase_ = WorldHostPhase::Idle;
};

}  // namespace wfh::server
