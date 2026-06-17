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
constexpr std::uint32_t kUpdateThrustSimVA =
    0x004f9e20;  // Vehicle_UpdateThrustSimulation(thiscall model; stack vehicle)
constexpr int kControlDivisor = 50;  // tankVehicle+0x0c divisor (GetScaledValue denominator)
constexpr std::uintptr_t kSlotStride = 0x20;     // tuning-table slot stride
constexpr std::uintptr_t kSlotScaledOff = 0x10;  // slot+0x10: control field GetScaledValue divides
constexpr std::uintptr_t kSlotRawOff = 0x18;  // slot+0x18: raw/cache field (slot-5 gate read here)
constexpr int kSlotForward = 2;               // tuning slot 2 = forward channel
constexpr int kSlotThrustIntensity = 5;       // tuning slot 5 = thrust-intensity gate
constexpr float kDemoForwardInput =
    1.0F;  // hardcoded forward [-1,1] (temp; ACTION input is the next step)
constexpr float kThrustIntensity = 1.0F;  // slot-5 nonzero so UpdateThrustFx opens the gate

// Mutable spike state lives in a function-local static (engine-thread-only), mirroring the
// file's other statics — kept off file scope. `controller` is the server-owned 0x20-byte
// vehicle-controller buffer (an array of void* so it is pointer-aligned for the vtable).
struct VehicleDriveState {
    std::array<void*, kControllerSize / sizeof(void*)> controller{};
    void* entity = nullptr;       // test tank entity captured from DoSpawn
    std::uint32_t model = 0;      // resolved Tank_Model (controller+0x10)
    std::uint32_t slot_base = 0;  // *(param2) = control-slot table base
    bool built = false;           // controller constructed yet?
    bool handler_set = false;     // force-driven physics handler installed on the entity yet?
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
    DriveState().entity = obj;  // M6: remember the entity so we can attach a vehicle controller
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
    if (!world.empty()) {
        const MvpEntitySnapshot& head = world.front();
        WFH_INFO("worldhost", "  entity[0] oid=%d type=%d team=%d pos=%.1f,%.1f,%.1f", head.net_id,
                 head.unit_type, head.team, static_cast<double>(head.pos.at(0)),
                 static_cast<double>(head.pos.at(1)), static_cast<double>(head.pos.at(2)));
    }
}

// Increment 1: build a vehicle controller for the test entity ONCE and log whether the
// engine resolved a model. vtable should be 0x543128 (Tank_Vehicle) and model should be
// non-zero (its own vtable 0x5430e8) — a zero model means the headless boot did NOT
// populate the vehicle-model registry, which would block this whole approach. Runs on the
// SEH-guarded tick thread, so a bad call faults safely instead of crashing the engine.
void BuildDriveController() {
    VehicleDriveState& st = DriveState();
    if (st.built || st.entity == nullptr) {
        return;
    }
    st.built = true;  // one-shot regardless of outcome (avoid retrying a faulting call)
    void* controller = static_cast<void*>(st.controller.data());
    EngineTankConstruct(controller);

    const std::uint32_t param2 = DerefU32(kInitForEntityParam2VA);
    // NOLINTNEXTLINE(performance-no-int-to-ptr,cppcoreguidelines-pro-type-reinterpret-cast)
    void* param2_ptr = reinterpret_cast<void*>(static_cast<std::uintptr_t>(param2));
    EngineVehicleInitForEntity(controller, st.entity, param2_ptr);

    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    const auto ctrl_addr = reinterpret_cast<std::uintptr_t>(controller);
    const std::uint32_t vtable = DerefU32(ctrl_addr + kVehicleVtableOff);
    const std::uint32_t model = DerefU32(ctrl_addr + kVehicleModelOff);
    st.model = model;  // M6.2: Tank_Model the thrust step runs on
    st.slot_base = (param2 != 0) ? DerefU32(param2) : 0;  // *(param2) = control-slot table base
    WFH_INFO("worldhost",
             "M6 drive controller built: controller=0x%08X vtable=0x%08X (expect 0x543128) "
             "model=0x%08X param2=0x%08X (model!=0 => vehicle-model registry present)",
             static_cast<unsigned>(ctrl_addr), vtable, model, param2);
    if (model != 0) {
        WFH_INFO("worldhost", "M6 model vtable=0x%08X (expect 0x5430e8 tank) slot_base=0x%08X",
                 DerefU32(model), st.slot_base);
    }
}

// M6.2-min(b): drive the test tank each tick. Installs the force-driven physics handler once,
// writes the control-input slots the engine reads, then calls the engine's OWN per-tank thrust
// step so the global world tick integrates the resulting force into real motion. See the
// kForceDrivenHandlerVA block for the RE rationale. Engine-thread-only (SEH-guarded tick).
void DriveServerTank() {
    VehicleDriveState& st = DriveState();
    if (!st.built || st.entity == nullptr || st.model == 0 || st.slot_base == 0) {
        return;
    }
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    const auto entity_addr = reinterpret_cast<std::uintptr_t>(st.entity);

    // One-shot: switch the entity from its kinematic handler to the force-driven one so
    // EntityPhysics_IntegrateLinear consumes the thrust force accumulator (entity+0x24).
    if (!st.handler_set) {
        st.handler_set = true;
        WriteU32(entity_addr + kEntityHandlerOff, kForceDrivenHandlerVA);
        WFH_INFO("worldhost", "M6.2 drive: entity+0xc0 -> force-driven handler 0x%08X",
                 kForceDrivenHandlerVA);
    }

    // Populate the control slots VehicleTuning_ComputeControlScalars reads (mirrors the local
    // lag-queue, which never runs for a non-local entity). raw = input * divisor; the gate slot
    // (5) must be nonzero or Vehicle_UpdateThrustFx leaves the thrust gate closed.
    const auto fwd_slot = st.slot_base + (kSlotForward * kSlotStride) + kSlotScaledOff;
    const auto gate_slot = st.slot_base + (kSlotThrustIntensity * kSlotStride) + kSlotRawOff;
    WriteF32(fwd_slot, kDemoForwardInput * static_cast<float>(kControlDivisor));
    WriteF32(gate_slot, kThrustIntensity);

    // Drive the engine's per-tank thrust step (thiscall ECX=model, stack arg=tankVehicle). It
    // computes control scalars, opens the gate, self-sets model+0x58/+0x5c, and accumulates
    // force/torque onto the entity; the global RunWorldTick (already running) integrates it.
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    const auto vehicle_ptr = reinterpret_cast<std::uintptr_t>(st.controller.data());
    auto vehicle_arg = static_cast<std::uint32_t>(vehicle_ptr);
    SafeEngineInvoke(kUpdateThrustSimVA, st.model, 0, &vehicle_arg, 1);
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
        WFH_INFO("worldhost", "authoritative relay armed: clients now receive the engine world");
        logged_done = true;
    }

    // Once the world is populated, periodically read it back by value (the engine is
    // now the source of truth). M6.1 will feed this snapshot to connected clients.
    if (bootstrap.done()) {
        BuildDriveController();  // M6 Increment 1: attach a vehicle controller to the test entity
        DriveServerTank();       // M6.2-min(b): drive the engine's thrust step -> authentic motion
        LogWorldReadback();
    }
}

}  // namespace wfh::server
// NOLINTEND(cppcoreguidelines-avoid-do-while,cppcoreguidelines-pro-type-vararg)
