#include "server/world_host_engine.hpp"

#include "server/engine_thunks.hpp"

#include "wfh/log.hpp"
#include "wfh/proto/framing.hpp"
#include "wfh/server/entity_snapshot.hpp"
#include "wfh/server/runtime.hpp"
#include "wfh/server/server_config.hpp"
#include "wfh/server/world_host.hpp"
#include "wfh/server/world_packets.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#include <string>
#include <vector>

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

// World-list walk (M6.1 readback). DAT_006785e4 -> WorldMap; [WorldMap+0] -> Util_List
// (count@+0, head@+4); node {next@+0, data@+8}. Verified live via cdb.
constexpr std::uint32_t kWorldMapPtrVA = 0x006785e4;
constexpr std::size_t kListHeadOff = 4;
constexpr std::size_t kNodeEntityOff = 8;
constexpr int kMaxWorldEntities = 4096;  // sanity cap if memory is unexpected
constexpr int kReadbackEvery = 200;      // throttle the readback log (~once/sec)

// --- M6 vehicle-drive spike (Increment 1): construct an engine vehicle controller for the
// test-spawn entity and confirm the engine resolved a model (proves the headless server
// has the vehicle-model registry populated). No physics step yet — that's Increment 2.
constexpr std::uint32_t kInitForEntityParam2VA = 0x0067cd58;  // DAT_0067cd58 (engine global)
constexpr std::size_t kControllerSize = 0x20;                 // Tank_Construct object size
constexpr std::uintptr_t kVehicleVtableOff = 0x00;            // controller+0x00 = vtable (0x543128)
constexpr std::uintptr_t kVehicleModelOff = 0x10;             // controller+0x10 = resolved model

// --- M6 on-join self-load: feed the server's own BEHAVIOR through the engine's CLIENT-side
// handler so the headless engine's vehicle physics tuning is populated, exactly as a joined
// client's would be. The engine booted a world but never "joined a server", so the on-join
// state a server pushes (BEHAVIOR = physics globals + per-model vehicle tuning) was unset.
// We mirror the engine's OWN receive path (Net_ProcessOrderedReceiveQueue @ 0x504a2c):
//   membuf = _malloc(0x20); body = _malloc(len); copy body bytes;
//   BitBuf_ConstructWithChunk(membuf, mode=1, body, len, owner=0);   // __thiscall ECX=membuf
//   Net_HandleBehavior(0, 0, membuf);                                // __cdecl, packet=membuf
//   MemBuff_FreeAllHunks(membuf); _free(membuf);                     // recv-path cleanup
// All calls go through SafeEngineInvoke (the same convention-agnostic, SEH-guarded invoker
// the dev console uses). VALIDATED LIVE before wiring (tools/feed_onjoin_probe.py): the
// 0x679170 scalar block goes zero->non-zero and the Tank model config doubles load (hover
// 3.25->9.75), no crash. Net_HandleBehavior's only side effect is Net_FlushSendBuffer on the
// packet itself, so no live connection is needed (unlike TRANSLATION, whose 0x33 ACK needs a
// send object -- and TRANSLATION is not required: our C++ relay does its own quantization).
constexpr std::uint32_t kMallocVA = 0x0050c8eb;                    // void* __cdecl _malloc(size_t)
constexpr std::uint32_t kFreeVA = 0x0050c292;                      // void  __cdecl _free(void*)
constexpr std::uint32_t kBitBufConstructWithChunkVA = 0x00508a50;  // __thiscall, RET 0x10
constexpr std::uint32_t kMemBuffFreeAllHunksVA = 0x00509a30;       // __thiscall(this)
constexpr std::uint32_t kNetHandleBehaviorVA = 0x0046dc00;         // __cdecl(p1, p2, packet)
constexpr std::uint32_t kMemBuffStructSize = 0x20;                 // BitBuf object size (recv path)
constexpr std::uint32_t kMemBuffReadMode = 1;                      // mode arg for a read buffer

// --- M6.2-min(b) drive: make the non-local tank MOVE under the engine's OWN thrust.
// Root cause (RE'd + live-verified 2026-06-17): the engine dispatches the per-frame thrust
// step (Vehicle_UpdateThrustSimulation @0x4f9e20, Tank_Model vtable[0]) for EXACTLY ONE
// object -- the singleton local-player vehicle client -- inside Interp_StepSimulationSubsteps.
// A non-local Obj_InitFromSpawn entity is never dispatched, so its forces are never produced.
// The TRUE missing init is the entity's physics handler at entity+0xc0: a fresh spawn gets the
// KINEMATIC handler (EntityPhysics_IntegrateLinear ignores the force accumulator at entity+0x24
// and only does pos += vel*dt), while the local player gets the FORCE-DRIVEN damped handler
// DAT_005b8634 (accel = force - vel*damping). So we (1) point entity+0xc0 at the force-driven
// handler, (2) populate the control-input slots the engine reads, and (3) call the thrust step
// ourselves each tick. The engine's global EntityPhysics_RunWorldTick then integrates
// entity+0x24 -> entity+0x18 (vel) -> entity+0x0c (pos) and ZEROS the accumulator each tick --
// so the slots + step must be re-applied every tick. (model+0x58/+0x5c "thrust magnitudes" are
// a non-issue: Vehicle_UpdateEngineGlowScale self-inits them to 1.0 inside the step.)
constexpr std::uint32_t kForceDrivenHandlerVA =
    0x005b8634;                                  // DAT_005b8634: local-player vehicle phys handler
constexpr std::size_t kEntityHandlerOff = 0xc0;  // entity+0xc0 -> physics-integration handler ptr
constexpr std::size_t kEntitySleepFlagOff =
    0xae;  // entity+0xae: sleep flag (nonzero => RunWorldTick skips it)
constexpr std::uint32_t kUpdateThrustSimVA =
    0x004f9e20;  // Vehicle_UpdateThrustSimulation(thiscall model; stack vehicle)
constexpr int kControlDivisor = 50;  // tankVehicle+0x0c divisor (GetScaledValue denominator)
constexpr std::uintptr_t kSlotStride = 0x20;     // tuning-table slot stride
constexpr std::uintptr_t kSlotScaledOff = 0x10;  // slot+0x10: control field GetScaledValue divides
constexpr std::uintptr_t kSlotRawOff = 0x18;  // slot+0x18: raw/cache field (slot-5 gate read here)
constexpr int kSlotTurn = 1;              // tuning slot 1 = turn channel (negated -> model+0x74)
constexpr int kSlotForward = 2;           // tuning slot 2 = forward channel
constexpr int kSlotThrustIntensity = 5;   // tuning slot 5 = thrust-intensity gate
constexpr float kThrustIntensity = 1.0F;  // slot-5 nonzero so UpdateThrustFx opens the gate

// Multi-tank demo: the server authoritatively drives SEVERAL independent tanks at once -- a
// capability the stock binary never had (it only ever drove the ONE local-player vehicle). The
// Tank_Model (per-type registry singleton) and the control-slot table are SHARED scratch objects,
// but the thrust step reads them synchronously during each call, so driving the tanks SEQUENTIALLY
// (write this tank's slots -> call its step -> next tank) gives each its own force with no
// cross-talk. Each tank gets a distinct bounded forward+turn demo input (temporary, until ACTION
// input routing) so it traces its own path and stays near spawn. forward/turn in [-1,1].
constexpr std::size_t kMaxServerTanks = 3;
struct DemoDrive {
    float forward;
    float turn;
};
constexpr std::array<DemoDrive, kMaxServerTanks> kDemoDrive = {{
    {0.30F, 0.80F},  // tank 0: tight forward+left circle near spawn
    {0.0F, -1.0F},   // tank 1: spin right in place (bounded)
    {0.0F, 1.0F},    // tank 2: spin left in place (bounded)
}};
// Extra (non-primary) tanks, spawned offset from the primary (index 0, from WorldBootstrap) so
// they sit near it on valid terrain.
struct ExtraSpawn {
    std::int32_t oid;
    float dx;
    float dy;
    std::int32_t team;
};
constexpr std::array<ExtraSpawn, kMaxServerTanks - 1> kExtraSpawns = {{
    {9002, 400.0F, 0.0F, 2},
    {9003, 0.0F, 400.0F, 1},
}};

// Mutable spike state lives in a function-local static (engine-thread-only), mirroring the
// file's other statics — kept off file scope. `controller` is the server-owned 0x20-byte
// vehicle-controller buffer (an array of void* so it is pointer-aligned for the vtable).
struct ServerTank {
    std::array<void*, kControllerSize / sizeof(void*)> controller{};  // own 0x20-byte Tank_Vehicle
    void* entity = nullptr;    // engine entity (own, from spawn)
    bool handler_set = false;  // force-driven physics handler installed on this entity yet?
};
struct VehicleDriveState {
    std::array<ServerTank, kMaxServerTanks> tanks{};
    int tank_count = 0;       // entities registered (primary + extras spawned)
    std::uint32_t model = 0;  // shared Tank_Model (per-type registry singleton, controller+0x10)
    std::uint32_t slot_base = 0;  // shared control-slot table base (*(DAT_0067cd58))
    bool built = false;           // controllers built yet?
};
auto DriveState() -> VehicleDriveState& {
    static VehicleDriveState state;
    return state;
}

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
// Spawn one authoritative non-local tank entity into the loaded world and return it (nullptr on
// reject). Mirrors the engine's own Net_HandleTankSpawn: Obj_Create then Obj_InitFromSpawn.
// creator (ECX, stored at entity+0xcc) must be > the lose-OID threshold DAT_0067cd0c (0 on a fresh
// world) for Obj_Create's LoseOid_IsHidden gate to pass — so we pass the oid (>0) as creator.
// is_local/deco = 0; owner=team mirrors Net_HandleTankSpawn's (teamOrFlag, teamOrFlag) pair. We
// leave DAT_005b83e0 = -1 (Game_ResetSession set it), and oid != -1, so Obj_InitFromSpawn does NOT
// enter-world / grab the local camera.
auto SpawnTankEntity(std::int32_t oid, std::int32_t unit_type, std::int32_t team,
                     const std::array<float, 3>& pos, const std::array<float, 3>& rot) -> void* {
    WFH_INFO("worldhost", "Obj_Create(oid=%d, type=%d, team=%d)", oid, unit_type, team);
    void* obj = EngineObjCreate(oid, oid, 0, unit_type, team, team, 0, 0);
    if (obj == nullptr) {
        WFH_WARN("worldhost", "Obj_Create returned null (oid=%d rejected); spawn skipped", oid);
        return nullptr;
    }
    WFH_INFO("worldhost", "Obj_InitFromSpawn(oid=%d, pos=%.1f,%.1f,%.1f)", oid,
             static_cast<double>(pos.at(0)), static_cast<double>(pos.at(1)),
             static_cast<double>(pos.at(2)));
    EngineObjInitFromSpawn(obj, pos.at(0), pos.at(1), pos.at(2), rot.at(0), rot.at(1), rot.at(2));
    WFH_INFO("worldhost", "spawned entity oid=%d into world list + spatial index", oid);
    return obj;
}

// M6.2 player spawn: oids for client tanks, distinct from the demo tanks (9001-9003) and map
// fixtures, kept near the demo-tank magnitude so they fit the snapshot id bit width.
constexpr std::int32_t kPlayerOidBase = 9100;
constexpr std::int32_t kPlayerUnitType = 0;  // tank

// Spawn a REAL engine tank for a reincarnating player at its pad so the authoritative relay
// (ReadEngineWorld) includes it -- the client's TankSpawn then correlates with a tank that
// actually appears in snapshots (otherwise it spawns a phantom -> loses sync -> "protocol
// mismatch"). Returns the engine oid (0 on failure). Tick-thread-only (the bridge's SpawnOnPad,
// driven by the same tick body just before ProcessWorldHostTick). Increment 1: spawn only
// (static/kinematic) so players SEE each other; driving from input is the next step.
auto SpawnPlayerTank(std::int32_t team, const std::array<float, 3>& pos,
                     const std::array<float, 3>& rot) -> std::int32_t {
    static std::int32_t next_player_oid = kPlayerOidBase;
    const std::int32_t oid = next_player_oid++;
    const void* obj = SpawnTankEntity(oid, kPlayerUnitType, team, pos, rot);
    if (obj == nullptr) {
        WFH_WARN("worldhost", "player engine-spawn failed oid=%d team=%d", oid, team);
        return 0;
    }
    WFH_INFO("worldhost", "M6.2 player tank engine-spawned oid=%d team=%d pos=%.1f,%.1f,%.1f", oid,
             team, static_cast<double>(pos.at(0)), static_cast<double>(pos.at(1)),
             static_cast<double>(pos.at(2)));
    return oid;
}

// The WorldBootstrap "Spawn" action spawns the PRIMARY tank (index 0); the extras are spawned in
// the engine glue (SetupServerTanks) since they are a multi-tank drive concern, not part of the
// pure host-tested bootstrap brain.
void DoSpawn(const WorldHostEntitySpec& entity) {
    void* obj = SpawnTankEntity(entity.oid, entity.unit_type, entity.team, entity.pos, entity.rot);
    if (obj != nullptr) {
        DriveState().tanks.at(0).entity = obj;
        DriveState().tank_count = 1;
    }
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

// Read a 32-bit value (pointer or int) from engine memory at `addr`. x86, so a
// uintptr_t holds a 32-bit word. Engine-thread-only (the world is single-threaded).
auto DerefU32(std::uintptr_t addr) -> std::uint32_t {
    // NOLINTNEXTLINE(performance-no-int-to-ptr,cppcoreguidelines-pro-type-reinterpret-cast,clang-analyzer-core.FixedAddressDereference)
    return *reinterpret_cast<const std::uint32_t*>(addr);
}

// Write a 32-bit word / float to engine memory at `addr`. Engine-thread-only (called from the
// SEH-guarded tick); the targets are writable heap (entity struct, tuning-slot table), not code,
// so no page-protection flip is needed. Used by the M6.2 drive to set the entity handler + slots.
void WriteU32(std::uintptr_t addr, std::uint32_t val) {
    // NOLINTNEXTLINE(performance-no-int-to-ptr,cppcoreguidelines-pro-type-reinterpret-cast,clang-analyzer-core.FixedAddressDereference)
    *reinterpret_cast<std::uint32_t*>(addr) = val;
}

void WriteF32(std::uintptr_t addr, float val) {
    // NOLINTNEXTLINE(performance-no-int-to-ptr,cppcoreguidelines-pro-type-reinterpret-cast,clang-analyzer-core.FixedAddressDereference)
    *reinterpret_cast<float*>(addr) = val;
}

void WriteU8(std::uintptr_t addr, std::uint8_t val) {
    // NOLINTNEXTLINE(performance-no-int-to-ptr,cppcoreguidelines-pro-type-reinterpret-cast,clang-analyzer-core.FixedAddressDereference)
    *reinterpret_cast<std::uint8_t*>(addr) = val;
}

// Walk the engine's authoritative world list (DAT_006785e4) and extract a by-value
// snapshot of every entity. The engine is now the source of truth; this read runs on
// the SEH-guarded tick thread (a stale/garbage pointer faults safely). The relay
// (M6.1) will serialize these to clients.
auto ReadEngineWorld() -> std::vector<MvpEntitySnapshot> {
    std::vector<MvpEntitySnapshot> out;
    const std::uintptr_t world_map = DerefU32(kWorldMapPtrVA);
    if (world_map == 0) {
        return out;  // world not loaded yet
    }
    const std::uintptr_t list = DerefU32(world_map);  // WorldMap+0 -> Util_List
    if (list == 0) {
        return out;
    }
    const auto count = static_cast<int>(DerefU32(list));  // list+0 -> count
    std::uintptr_t node = DerefU32(list + kListHeadOff);  // list+4 -> head node
    for (int i = 0; i < count && i < kMaxWorldEntities && node != 0; ++i) {
        const std::uintptr_t entity = DerefU32(node + kNodeEntityOff);
        if (entity != 0) {
            // NOLINTNEXTLINE(performance-no-int-to-ptr,cppcoreguidelines-pro-type-reinterpret-cast)
            out.push_back(ExtractEntitySnapshot(reinterpret_cast<const std::uint8_t*>(entity)));
        }
        node = DerefU32(node);  // node+0 -> next
    }
    return out;
}

// Throttled proof that we can read the engine's real world state by value each tick.
void LogWorldReadback() {
    static int ticks = 0;
    if (ticks++ % kReadbackEvery != 0) {
        return;
    }
    const std::vector<MvpEntitySnapshot> world = ReadEngineWorld();
    WFH_INFO("worldhost", "engine world readback: %zu entit%s", world.size(),
             world.size() == 1 ? "y" : "ies");
    // Log every tank's live pos/rot so independent multi-tank motion is visible (cap a few).
    constexpr std::size_t kLogCap = 8;
    for (std::size_t i = 0; i < world.size() && i < kLogCap; ++i) {
        const MvpEntitySnapshot& ent = world.at(i);
        WFH_INFO("worldhost",
                 "  entity[%zu] oid=%d type=%d team=%d pos=%.1f,%.1f,%.1f rot=%.2f,%.2f,%.2f", i,
                 ent.net_id, ent.unit_type, ent.team, static_cast<double>(ent.pos.at(0)),
                 static_cast<double>(ent.pos.at(1)), static_cast<double>(ent.pos.at(2)),
                 static_cast<double>(ent.rot.at(0)), static_cast<double>(ent.rot.at(1)),
                 static_cast<double>(ent.rot.at(2)));
    }
}

// One-shot: spawn the extra tanks (the primary is index 0 from the bootstrap) and build a vehicle
// controller for every server tank. The model (controller+0x10, Tank_Model vtable 0x5430e8) and
// the control-slot table (*(DAT_0067cd58)) are shared per-type/scratch objects, resolved once from
// tank 0. Runs on the SEH-guarded tick thread, so a bad call faults safely.
void SetupServerTanks(const WorldHostEntitySpec& primary) {
    VehicleDriveState& st = DriveState();
    if (st.built || st.tanks.at(0).entity == nullptr) {
        return;
    }
    st.built = true;  // one-shot regardless of outcome (avoid retrying faulting calls)

    // Spawn the extras near the primary, registering each that succeeds.
    for (const ExtraSpawn& ex : kExtraSpawns) {
        if (static_cast<std::size_t>(st.tank_count) >= kMaxServerTanks) {
            break;
        }
        const std::array<float, 3> pos = {primary.pos.at(0) + ex.dx, primary.pos.at(1) + ex.dy,
                                          primary.pos.at(2)};
        void* obj = SpawnTankEntity(ex.oid, primary.unit_type, ex.team, pos, primary.rot);
        if (obj != nullptr) {
            st.tanks.at(static_cast<std::size_t>(st.tank_count)).entity = obj;
            ++st.tank_count;
        }
    }

    // Build a controller per tank; resolve the shared model + slot table from tank 0.
    const std::uint32_t param2 = DerefU32(kInitForEntityParam2VA);
    // NOLINTNEXTLINE(performance-no-int-to-ptr,cppcoreguidelines-pro-type-reinterpret-cast)
    void* param2_ptr = reinterpret_cast<void*>(static_cast<std::uintptr_t>(param2));
    for (std::size_t i = 0; i < static_cast<std::size_t>(st.tank_count); ++i) {
        void* controller = static_cast<void*>(st.tanks.at(i).controller.data());
        EngineTankConstruct(controller);
        EngineVehicleInitForEntity(controller, st.tanks.at(i).entity, param2_ptr);
        if (i == 0) {
            // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
            const auto ctrl_addr = reinterpret_cast<std::uintptr_t>(controller);
            st.model = DerefU32(ctrl_addr + kVehicleModelOff);
            st.slot_base = (param2 != 0) ? DerefU32(param2) : 0;
        }
    }
    WFH_INFO("worldhost",
             "M6.2 multi-tank setup: %d tanks; shared model=0x%08X (expect vtable 0x5430e8) "
             "slot_base=0x%08X param2=0x%08X",
             st.tank_count, st.model, st.slot_base, param2);
}

// M6.2: drive EVERY server tank each tick. For each tank: install the force-driven physics handler
// once, write THIS tank's control-input slots, then call the engine's OWN per-tank thrust step. The
// global world tick integrates the accumulated force into real motion. The slots/model are shared
// but read synchronously inside each step call, so writing-then-calling per tank in sequence keeps
// the tanks independent. See the kForceDrivenHandlerVA block. Engine-thread-only (SEH-guarded
// tick).
void DriveServerTanks() {
    VehicleDriveState& st = DriveState();
    if (!st.built || st.model == 0 || st.slot_base == 0) {
        return;
    }
    const auto fwd_slot =
        st.slot_base + (static_cast<std::uintptr_t>(kSlotForward) * kSlotStride) + kSlotScaledOff;
    const auto turn_slot =
        st.slot_base + (static_cast<std::uintptr_t>(kSlotTurn) * kSlotStride) + kSlotScaledOff;
    const auto gate_slot = st.slot_base +
                           (static_cast<std::uintptr_t>(kSlotThrustIntensity) * kSlotStride) +
                           kSlotRawOff;
    const auto div = static_cast<float>(kControlDivisor);

    for (std::size_t i = 0; i < static_cast<std::size_t>(st.tank_count); ++i) {
        ServerTank& tk = st.tanks.at(i);
        if (tk.entity == nullptr) {
            continue;
        }
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        const auto entity_addr = reinterpret_cast<std::uintptr_t>(tk.entity);

        // One-shot per tank: kinematic -> force-driven handler so IntegrateLinear consumes the
        // thrust force accumulator (entity+0x24) instead of doing pos += vel only.
        if (!tk.handler_set) {
            tk.handler_set = true;
            WriteU32(entity_addr + kEntityHandlerOff, kForceDrivenHandlerVA);
            WFH_INFO("worldhost", "M6.2 drive: tank %zu entity+0xc0 -> force-driven handler", i);
        }

        // Force-wake every tick: RunWorldTick skips entities whose sleep flag (entity+0xae) is set,
        // and a slept entity is never integrated -- so our applied force can never raise its motion
        // above the wake threshold (deadlock). Clearing the flag each tick keeps this authoritative
        // tank perpetually integrated (the local player is kept awake the same way each tick).
        WriteU8(entity_addr + kEntitySleepFlagOff, 0);

        // Write this tank's input into the shared slots (raw = input * divisor; gate slot 5
        // nonzero so Vehicle_UpdateThrustFx opens the thrust gate), then drive its step.
        WriteF32(fwd_slot, kDemoDrive.at(i).forward * div);
        WriteF32(turn_slot, kDemoDrive.at(i).turn * div);
        WriteF32(gate_slot, kThrustIntensity);
        // thiscall ECX=model, stack arg=this tank's Tank_Vehicle controller.
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        const auto vehicle_ptr = reinterpret_cast<std::uintptr_t>(tk.controller.data());
        auto vehicle_arg = static_cast<std::uint32_t>(vehicle_ptr);
        SafeEngineInvoke(kUpdateThrustSimVA, st.model, 0, &vehicle_arg, 1);
    }
}

// Engine-malloc `size` bytes via the engine CRT heap. Returns 0 on fault/OOM. The buffers
// we hand to the MemBuff are freed by the engine (RetrieveBits / FreeAllHunks), so they
// MUST come from this heap, not operator new / a static region.
auto EngineMalloc(std::uint32_t size) -> std::uint32_t {
    std::uint32_t arg = size;
    const InvokeResult res = SafeEngineInvoke(kMallocVA, 0, 0, &arg, 1);
    return res.faulted ? 0 : res.eax;
}

void EngineFree(std::uint32_t ptr) {
    if (ptr != 0) {
        SafeEngineInvoke(kFreeVA, 0, 0, &ptr, 1);
    }
}

// Feed the server's own BEHAVIOR body through Net_HandleBehavior so the headless engine's
// vehicle physics tuning is loaded (the on-join self-load). One-shot; runs on the SEH-guarded
// tick thread after the world-host bootstrap completes. See the VA block above for the recipe
// + the live validation. Necessary (loads move/turn/strafe adjust etc. the thrust math reads),
// though not yet sufficient to DRIVE a non-local entity (the per-vehicle slot table is still
// unpopulated — the next increment).
void FeedBehaviorToEngine() {
    const std::vector<std::uint8_t> framed = BuildBehavior();  // [u16 len][0x24][body]
    proto::TcpFrameAccumulator acc;
    acc.Feed(framed.data(), framed.size());
    const std::optional<proto::Frame> frame = acc.Next();
    if (!frame || frame->body.empty()) {
        WFH_WARN("worldhost", "on-join BEHAVIOR feed skipped: could not extract frame body");
        return;
    }
    const auto body_len = static_cast<std::uint32_t>(frame->body.size());

    const std::uint32_t data = EngineMalloc(body_len);
    if (data == 0) {
        WFH_WARN("worldhost", "on-join BEHAVIOR feed: engine _malloc(%u) failed", body_len);
        return;
    }
    // Same process: copy the body straight into the engine heap buffer.
    // NOLINTNEXTLINE(performance-no-int-to-ptr,cppcoreguidelines-pro-type-reinterpret-cast)
    std::memcpy(reinterpret_cast<void*>(static_cast<std::uintptr_t>(data)), frame->body.data(),
                body_len);

    const std::uint32_t membuf = EngineMalloc(kMemBuffStructSize);
    if (membuf == 0) {
        WFH_WARN("worldhost", "on-join BEHAVIOR feed: engine _malloc(membuf) failed");
        EngineFree(data);  // engine heap; safe to free the orphaned body
        return;
    }

    // BitBuf_ConstructWithChunk(membuf, mode=1, body, len, owner=0) — __thiscall ECX=membuf.
    const std::array<std::uint32_t, 4> cc = {kMemBuffReadMode, data, body_len, 0};
    SafeEngineInvoke(kBitBufConstructWithChunkVA, membuf, 0, cc.data(),
                     static_cast<int>(cc.size()));
    // Net_HandleBehavior(0, 0, membuf) — __cdecl; p1/p2 are unused by the handler.
    const std::array<std::uint32_t, 3> hb = {0, 0, membuf};
    const InvokeResult res =
        SafeEngineInvoke(kNetHandleBehaviorVA, 0, 0, hb.data(), static_cast<int>(hb.size()));
    // Cleanup mirrors Net_ProcessOrderedReceiveQueue (frees the chunk's backing + the struct).
    SafeEngineInvoke(kMemBuffFreeAllHunksVA, membuf, 0, nullptr, 0);
    EngineFree(membuf);

    WFH_INFO("worldhost",
             "on-join BEHAVIOR fed to engine (body=%u bytes, faulted=%d): vehicle physics tuning "
             "loaded (move/turn/strafe adjust, gravity, rates)",
             body_len, static_cast<int>(res.faulted));
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
        // On-join self-load: feed our own BEHAVIOR through the engine's client-side handler
        // so the engine's vehicle physics tuning is populated (it booted a world but never
        // "joined", so this state was unset). Runs once, on this tick thread.
        FeedBehaviorToEngine();
        // Arm the authoritative relay: the MVP bridge now sources its VIEW_UPDATE
        // entities from the live engine world instead of placeholder data, so
        // connected clients see the engine's real objects. The provider runs on this
        // tick thread during the bridge's snapshot emission.
        ProcessMvpBridge().SetWorldProvider(
            []() -> std::vector<MvpEntitySnapshot> { return ReadEngineWorld(); });
        // Players reincarnate into REAL engine tanks (relayed by the provider above), so their
        // TankSpawn correlates with a tank that actually appears in snapshots (no phantom-spawn
        // desync), and they SEE each other.
        ProcessMvpBridge().SetSpawnHandler([](std::int32_t team, const std::array<float, 3>& pos,
                                              const std::array<float, 3>& rot) -> std::int32_t {
            return SpawnPlayerTank(team, pos, rot);
        });
        WFH_INFO("worldhost", "authoritative relay armed: clients now receive the engine world");
        logged_done = true;
    }

    // Once the world is populated, periodically read it back by value (the engine is
    // now the source of truth). M6.1 will feed this snapshot to connected clients.
    if (bootstrap.done()) {
        SetupServerTanks(bootstrap.plan().entity);  // M6.2: spawn extras + build all controllers
        DriveServerTanks();  // M6.2: drive every server tank each tick (independent motion)
        LogWorldReadback();
    }
}

}  // namespace wfh::server
// NOLINTEND(cppcoreguidelines-avoid-do-while,cppcoreguidelines-pro-type-vararg)
