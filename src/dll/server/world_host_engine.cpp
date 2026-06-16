#include "server/world_host_engine.hpp"

#include "server/engine_thunks.hpp"

#include "wfh/log.hpp"
#include "wfh/server/runtime.hpp"
#include "wfh/server/server_config.hpp"
#include "wfh/server/world_host.hpp"

#include <cstdint>
#include <string>

// Every WFH_* logging call expands to the project's intentional do-while(0) guard
// macro that forwards a printf-style C variadic to Log::Write. Suppress the two
// macro-inherent findings file-wide so the call sites stay readable; all other
// checks remain on.
// NOLINTBEGIN(cppcoreguidelines-avoid-do-while,cppcoreguidelines-pro-type-vararg)
namespace wfh::server {

namespace {

// ===========================================================================
// Engine-glue bridge for the M5.4 "engine owns the world" bring-up.
//
// This replicates the engine's OWN world-entry path (Net_HandleWorldStats @
// 0x46cf50 does exactly Game_ResetSession(0) -> Client_SetCurrentWorld(...)), then
// spawns one authoritative entity (Obj_Create + Obj_InitFromSpawn). Once the world
// is loaded (DAT_006785e4 != 0), Client_Main's loop ticks the engine's own physics
// every iteration (Interp_UpdateAllEntities -> Interp_StepSimulationSubsteps), so
// the engine genuinely owns and advances the world -- no reimplemented simulation.
//
// VAs pinned here (gen/addresses.h holds only a curated subset; head_stubs.cpp
// pins its own VAs the same way). Verified in Ghidra against wulfram2.exe
// (image base 0x400000).
// ===========================================================================

// void __cdecl Game_ResetSession(char fullDisconnect): destroys all entities and
// resets per-session world state. Passing 0 keeps client params; it sets the
// local-player OID (DAT_005b83e0) to -1, so a later spawn with a real OID does not
// grab the local camera (Obj_InitFromSpawn only enters-world when OID == -1's slot).
// This one IS a plain __cdecl(char), so a direct cast is correct (verified live:
// it returns cleanly). Client_SetCurrentWorld is NOT — see EngineLoadWorld thunk.
constexpr std::uint32_t kGameResetSessionVA = 0x00419390;

// WORLD_STATS values our own server advertises for bpass (BuildWorldStats). A real
// rendering client loads + renders the map from exactly these, so they are
// known-valid for a direct in-process world load.
constexpr int kWorldType = 1;
constexpr int kWorldFlag = 1;
constexpr float kWorldScale = 1.0F;

// Let the engine's main loop settle after boot before driving the bring-up (the
// tick fires every loop iteration; a brief delay avoids racing the init tail).
constexpr int kSettleTicks = 30;

void EngineGameResetSession() {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast,performance-no-int-to-ptr)
    reinterpret_cast<void(__cdecl*)(char)>(static_cast<std::uintptr_t>(kGameResetSessionVA))(0);
}

void DoResetSession() {
    WFH_INFO("worldhost", "Game_ResetSession(0): clean session + destroy entities");
    EngineGameResetSession();
}

// map_name is the mutable engine buffer (the engine reads it read-only via
// Util_ChunkBuffer_AppendCString, but the wire signature is char*). The call goes
// through EngineLoadWorld, which matches Client_SetCurrentWorld's real (non-fastcall)
// convention via asm; a direct __fastcall cast deadlocks the engine thread on an
// /RTC1 ESP-mismatch dialog (see memory/client-setcurrentworld-abi).
void DoLoadWorld(char* map_name) {
    WFH_INFO("worldhost", "Client_SetCurrentWorld(map=%s, type=%d, flag=%d): load + build tree",
             map_name, kWorldType, kWorldFlag);
    EngineLoadWorld(map_name, kWorldType, kWorldFlag, kWorldScale);
    WFH_INFO("worldhost", "world loaded; engine loop now ticks physics on its own world list");
}

// Spawn ONE authoritative non-local entity into the loaded world. Mirrors the engine's
// own Net_HandleTankSpawn: Obj_Create (owner=team, like its teamOrFlag,teamOrFlag pair;
// creator/is_local/deco = 0) then Obj_InitFromSpawn for transform + world-list/spatial
// insertion. We leave DAT_005b83e0 = -1 (Game_ResetSession set it), and our oid != -1,
// so Obj_InitFromSpawn does NOT enter-world / grab the local camera.
void DoSpawn(const WorldHostEntitySpec& entity) {
    WFH_INFO("worldhost", "Obj_Create(oid=%d, type=%d, team=%d)", entity.oid, entity.unit_type,
             entity.team);
    // creator (ECX, stored at entity+0xcc) must be > the lose-OID threshold DAT_0067cd0c
    // (0 on a fresh world) for Obj_Create's LoseOid_IsHidden gate to pass — creator=0
    // is rejected. The engine passes the spawn packet's objectId here; for our
    // server-owned entity the oid (>0) is a fine positive id. is_local/deco = 0;
    // owner=team mirrors Net_HandleTankSpawn's (teamOrFlag, teamOrFlag) pair.
    void* obj = EngineObjCreate(entity.oid, entity.oid, 0, entity.unit_type, entity.team,
                                entity.team, 0, 0);
    if (obj == nullptr) {
        WFH_WARN("worldhost", "Obj_Create returned null (oid=%d rejected); spawn skipped",
                 entity.oid);
        return;
    }
    WFH_INFO("worldhost", "Obj_InitFromSpawn(oid=%d, pos=%.1f,%.1f,%.1f)", entity.oid,
             static_cast<double>(entity.pos.at(0)), static_cast<double>(entity.pos.at(1)),
             static_cast<double>(entity.pos.at(2)));
    EngineObjInitFromSpawn(obj, entity.pos.at(0), entity.pos.at(1), entity.pos.at(2),
                           entity.rot.at(0), entity.rot.at(1), entity.rot.at(2));
    WFH_INFO("worldhost", "spawned entity oid=%d into world list + spatial index", entity.oid);
}

// Thin dispatch: each case is a single call so the per-action logging do-while
// macros live in their own small helpers (keeps this under the complexity gate).
void PerformAction(WorldHostAction action, char* map_name, const WorldHostEntitySpec& entity) {
    switch (action) {
    case WorldHostAction::ResetSession: DoResetSession(); return;
    case WorldHostAction::LoadWorld: DoLoadWorld(map_name); return;
    case WorldHostAction::SpawnEntity: DoSpawn(entity); return;
    case WorldHostAction::None: return;
    }
}

}  // namespace

void ProcessWorldHostTick() {
    const ServerConfig& cfg = ProcessRuntime().Config();
    if (!cfg.world_host) {
        return;
    }

    // Process lifetime, mirroring ProcessMvpOnlineTick(): one bootstrap for the run.
    static WorldBootstrap bootstrap(WorldHostPlan{cfg.map});
    static std::string map_buf = cfg.map;  // mutable backing for the engine's char*

    if (!bootstrap.started()) {
        static int settle = 0;
        if (settle < kSettleTicks) {
            ++settle;
            return;
        }
        WFH_INFO("worldhost", "world_host enabled; beginning bootstrap map=%s", map_buf.c_str());
        bootstrap.Begin();
    }

    PerformAction(bootstrap.Advance(), map_buf.data(), bootstrap.plan().entity);

    static bool logged_done = false;
    if (bootstrap.done() && !logged_done) {
        WFH_INFO("worldhost", "world-host bootstrap complete");
        logged_done = true;
    }
}

}  // namespace wfh::server
// NOLINTEND(cppcoreguidelines-avoid-do-while,cppcoreguidelines-pro-type-vararg)
