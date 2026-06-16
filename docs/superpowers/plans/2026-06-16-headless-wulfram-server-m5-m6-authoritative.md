# Wulfram II Headless Server — M5/M6: Bit-Perfect Authoritative Server (Plan)

> Tight, single-purpose, controller-verified steps. No architecture pivots without
> sign-off. Each step: build green + lint PASS + a controller smoke before the next.

**Goal (user-stated):** Make the injected headless engine a **bit-perfect authoritative
server**: real clients connect; each client sends its tank inputs; the server applies
them to that player's server-side entity, runs the engine's OWN physics tick, and
relays authoritative actor create/update/destroy to all clients. Plus in-process
**tooling to add/modify actors**, which replicate the same way.

**Why this is bit-perfect:** we never reimplement float math (that is exactly why the
prior Python `..\Wulf-Forge` `wulfsim` drifts). The engine runs its own
`EntityPhysics_RunWorldTick @ 0x4f8550` and its own packet serializers in-process; we
only (a) feed inputs in, (b) read entity structs out, (c) emit the engine's own wire
packets. Same x87 code + constants + structs ⇒ byte-identical.

**Builds on:** M3 (Approach B headless boot) + M4.2 (the engine's inline loop runs as
our render-free, paced server tick; `DAT_00677f1d` kept 0 so it runs forever).

---

## RE foundation (validated this session — load-bearing addresses, base 0x400000)

### Actor model (in-process, authoritative)
- OID registry: `DAT_00677f34` (OidTable, 50 buckets, key = oid%50).
  - `OidTable_Find(table,oid)` 0x4e34f0, `Insert` 0x4e3450, `Remove` 0x4e3490, `Construct` 0x4e3530.
- World live list (ticked): `DAT_006785e4` (Util_List); walked by `Interp_UpdateAllEntities` 0x469f00.
- Local-player entity cache: `DAT_00677f2c`.
- Entity struct = 0x170 bytes (`operator_new(0x170)` + `Entity_Construct` 0x4e3720). Offsets:
  - +0x00 vtable; +0x08 type id; +0x0c/0x10/0x14 pos.xyz (float);
    +0x30/0x34/0x38 orientation/vel triple; +0xb4 OID (init 0xffffffff);
    +0xbc EntityPhysics obj; +0xec owner/player id; +0xf0 team.
  - (Physics field offsets being finalized by the struct RE pass — see notes when it lands.)
- Spawn: `Obj_Create(creatorThis,isLocal,type,owner,team,deco5,deco6)` 0x419a70 — **OID in EBX** —
  then `Obj_InitFromSpawn(x,y,z,o1,o2,o3)` 0x419880 (sets pos/orient, pushes `DAT_006785e4`,
  `SpatialIndex_InsertEntity`).
- Move: `Interp_SetEntityPositionAndRederive(entity,...)` 0x469980 (or write +0xc.. then
  `Entity_SaveInterpolationState` 0x4e3390).
- Destroy: `Obj_DestroyById()` 0x419320 — **OID in EDI**.

### Physics (bit-perfect, already running in our tick)
- `Client_Main` inline loop → `Interp_StepSimulationSubsteps` 0x469e00 → `EntityPhysics_RunWorldTick`
  0x4f8550 (walks `*(world+4)` list, `EntityPhysics_IntegrateStep` 0x4f2890 /
  `IntegrateLinear` 0x4f27a0, `CollisionContact_ResolveAll`). We read structs AFTER this.

### Replication (opcode-byte indexed; the `Net_SendStart` string is debug-only)
- Dispatch: `Proto_DispatchPacket` 0x509f70 (`handler[packetType*4]`); table built by
  `Net_RegisterMessageHandlers` 0x46c080 (`Proto_Init(...,0x56)`).
- Opcodes: 0x18 TankSpawn(create) `Net_HandleTankSpawn` 0x46d260; 0x0e UpdateArray(move/state)
  → `Net_ApplyWorldSnapshot` 0x47d82f; 0x15 DeleteObject(destroy) 0x46d4b0; 0x13 Hello
  `Net_HandleHello` 0x46d020 (version const **0x4e89** = 20105); 0x21 LOGIN (send) `Net_SendLogin` 0x46bbd0.
- Send: `Net_SendStart(sender,label,opcode,conn,flags)` 0x509cf0 → returns MemBuff;
  `Net_BeginSendUnreliablePacket` 0x509b60 writes the opcode byte first; reliable 0x509c90.
  `MemBuf_WriteByte/Int32/String` 0x509600/0x509520; bits via `MemBuf_WriteBits`;
  quantized vecs via `Net_DecodeColorTriple` encoder; finish `Proto_FinishPacket` 0x50a340.
  Quant tables: `DAT_00678134`.
- Globals: protocol sender `DAT_006782e4`; socket manager `DAT_006782e0`; active connection
  `DAT_005f3844`.

### The gap (the only thing the binary does NOT do natively)
- `Net_ServiceConnection` 0x46b830 is **single-connection** (client-style): drains the one
  UDP + the one `DAT_005f3844` stream. No multi-client accept/broadcast for the game protocol.
- BUT `Net_InitAccept(mgr,type,port)` 0x507ff0 is a **complete general listener** (TCP type 1:
  socket→SO_REUSEADDR→bind→listen(5); UDP type 2), currently only used by DbgNet (port 6969).
  `Net_CoreConnect` 0x5082d0 → `Net_FindOrCreatePeer` manufactures per-peer connection objects.
- ⇒ Bridge = listen + accept→peer + per-peer dispatch loop + per-peer handshake, then
  `Net_SendStart(DAT_006782e4, ..., peer, ...)` per peer (loop our own peer list to "broadcast").

---

## M5.0 wire-protocol findings (cross-validated vs the WORKING Python server)

The retired `..\Wulf-Forge` Python server is a **proven reference** — it got real clients
in-game. Its protocol is now cross-referenced to the binary. What was "bad" in Python was
the PHYSICS (`wulfsim` re-derives float math → drift), NOT the protocol/handshake. So the
protocol is a solved problem we can port with confidence.

### CORRECTION (important): `DAT_00677f1d` is NOT the join gate
It is the **version-MISMATCH error flag**, set to 1 only on FAILURE (HELLO sub-0 when
`version != 0x4E89`, and `Net_HandleVersionError`). A matching version leaves it 0. The
real "client joined" markers the client sets ITSELF are `DAT_00679080` (HELLO complete) and
`DAT_00678267` (UDP identified). Server job: don't trip the mismatch + complete the key/UDP
round-trip. (Note: M4.1's spoof set this error flag — fine as an exit/seam test, irrelevant
to real sessions.)

### Transport + framing (confirmed both sides)
- TCP = reliable control: `[u16_be length(incl 2)][opcode byte][MSB-first bitpacked body]`
  (`Net_FinalizeAndSendPacket` 0x509bc0 htons; opcode via `Net_BeginSendReliablePacket` 0x509c90).
- UDP = gameplay/unreliable: 2-byte seq word + opcode (`Net_BeginSendUnreliablePacket` 0x509b60).
- fixed 16.16 = `WriteInt32(round(v*65536))`. String = `[u16 len-incl-NUL][ASCII+NUL]`.
- Port is server-list-driven (no binary constant); Python used 2627 TCP+UDP.

### HELLO = opcode 0x13, subtype-multiplexed
sub-0 VERSION_CHECK (int32, MUST be `0x4E89`=20105), sub-1 UDP_CONFIG (u16 port,u16 count,
count×string host), sub-2 SESSION_KEY (string; client echoes on UDP), sub-3 VERIFIED.

### Ordered server→client bring-up (from the working `do_login_and_bootstrap`)
0x13/1 UDP_CONFIG → 0x13/0 VERSION(0x4E89) → 0x13/2 SESSION_KEY → (client echoes key on UDP)
→ 0x4D IDENTIFIED_UDP → (client LOGIN 0x21 user) → 0x22 LoginStatus(1=ask pw) → (LOGIN 0x21 pw)
→ 0x13/3 VERIFIED → 0x28 TEAM_INFO → 0x22 LoginStatus(8=ok) → 0x17 PLAYER(assign id) →
0x2F GAME_CLOCK → 0x23 MOTD → **0x24 BEHAVIOR (physics tunables — positional field counts
Tank7/Scout9/Bomber11, no framing; wrong count desyncs)** → 0x32 TRANSLATION (quant table;
client ACKs 0x33) → 0x1A ADD_TO_ROSTER(self+others) → 0x16 WORLD_STATS(map) → map entities.
Then client sends 0x39 WANT_UPDATES → server sends 0x0F snapshot. In-game control: client
0x25 REINCARNATE (UDP) → server 0x18 TANK spawn (net_id) + 0x25 REINCARNATE(0) + 0x1E
BIRTH_NOTICE; per-tick 0x0F (self) / 0x0E (others) carry motion.

### Gotchas
- Version equality (`0x4E89`) is the ONLY hard gate. No encryption/checksums; session key is a
  trust-the-echo round trip. BEHAVIOR(0x24) field counts are positional. TRANSLATION(0x32) must
  precede movement decode. UDP↔TCP linkage = correlate the UDP source by the echoed key.

### DECISION (user, 2026-06-16): **(B) Independent DLL socket server + engine as physics oracle**
Rationale (user): port the proven protocol but with **modern (2026) client handling** —
real multithreading, proper per-connection state machines — and **hardening against bad/hostile
data** (the 2006 binary has no such validation). Clean separation puts the untrusted network on
one side of a boundary and the (non-thread-safe) engine memory on the other.

Rejected: (A) in-binary accept bridge (couples us to the client handler table + the engine's
single-threaded send path); (C) inject into `Proto_DispatchPacket` (testing aid only).

#### Threading model (NON-NEGOTIABLE constraint)
The engine + all its memory (entity structs, OidTable, `Net_*`, `Obj_*`) are **single-threaded and
NOT thread-safe**. Therefore:
- **Network I/O threads** (accept loop + per-connection or async recv): own the sockets, do all
  blocking/`select`/`recv`, parse + VALIDATE untrusted bytes into plain POD command structs. They
  NEVER touch engine memory.
- **Engine tick thread** (the existing `Client_RenderFrame` tick seam): the ONLY thread that calls
  `Obj_Create`/`Obj_DestroyById`, reads entity structs, runs the engine sim, and builds outbound
  state. 
- **Boundary:** lock-protected (or lock-free) queues. Inbound: net thread → `IncomingCmdQueue`
  (validated commands: connect/login/action/reincarnate) → drained by the tick thread. Outbound:
  tick thread snapshots authoritative entity state → `OutboundStateQueue` → net threads serialize
  + send per connection. No engine pointer ever crosses to a net thread (snapshots are by value).

#### Security / hardening posture (the "bad data" requirement)
All inbound parsing treats bytes as hostile:
- Strict bounds: every read checks remaining length; the bit reader clamps; reject (drop the
  connection) on under/overflow rather than UB. Cap packet size (`u16` framing already bounds it);
  cap per-tick packets/bytes per connection (flood control).
- Validate every field against engine-valid ranges BEFORE it can reach the engine: opcode in the
  known set; unit_type 0..N; oid ownership (a client may only drive ITS own entity — owner check
  against the session, closing trap "any client moves any actor"); action channel ids/values
  clamped to [-1,1]; string lengths bounded + NUL-terminated.
- Per-connection state machine: reject packets out of handshake order (no ACTION before VERIFIED).
- Session/auth: bind UDP endpoint to TCP session via the key echo (as the proven flow does);
  do not trust client-asserted player_id/oid.
- The engine tick is SEH-guarded (M5.3) so even a validation miss faults safely, not silently.

#### Module layout (new, under src/dll/server/)
- `net/` — sockets, accept loop, per-connection state machine, framing (TCP `[u16][op][bits]`,
  UDP `[seq][op][bits]`), bit reader/writer (MSB-first), strict validators.
- `proto/` — packet encode/decode for the opcodes in the bring-up table; TRANSLATION-table-driven
  quantization captured from the engine.
- `bridge/` — the two queues + the tick-thread drain/apply + state-snapshot; the ONLY code that
  calls engine functions/reads structs.
- Reuse `wfh_log`; new code is /W4 /WX + clang-tidy + cppcheck clean like the rest.

## M5.0 entity data contract (verified — struct 0x170, world list, codec)

World list: `*DAT_006785e4` → WorldMap; `(*DAT_006785e4)+0` = Util_List (count@+0,head@+4,tail@+8);
nodes 0xc bytes (next@+0,prev@+4,entity@+8). RunWorldTick walks `*(param_1+4)`. By-id:
`OidTable_Find(DAT_00677f34, oid)` 0x4e34f0.

Entity struct (offset → field), all verified:
- +0x08 unit_type; +0x0C/10/14 **pos** (float); +0x18/1C/20 **velocity** (engine-produced);
  +0x24/28/2C linear-accel accumulator (**zeroed every tick**); +0x30/34/38 **orientation EULER**;
  +0x3C/40/44 **spin** (angular vel); +0x48/4C/50 angular-accel accumulator (**zeroed every tick**);
  +0x58..0x9F cached transform matrix/scale; +0xA0..A8 prev-euler cache; +0xAD at-rest, +0xAE sleep;
  +0xB0 target id; +0xB4 **OID** (init 0xffffffff); +0xB8 active flag; +0xBC EntityPhysics obj (0xc8);
  +0xC0 physics-descriptor (mode flag bytes); +0xCC owner; +0xD0 **health (absolute)**;
  +0xD4 **energy/fuel (absolute)**; +0xD8 weapon/turret array; +0xE8 spatial node; +0xEC team; +0xF0 owner2.
- Create: `Obj_Create` 0x419b62 (oid in EBX) → `Obj_InitFromSpawn` 0x4198d3 (pos/rot + world-list push).
  Destroy: `Obj_DestroyById` 0x419319 (oid in EDI). Move: write +0x0C/+0x30 then wake (+0xAE=0 /
  `EntityPhysics_WakeAndSnapshot`).
- UPDATE_ARRAY codec (ground truth = decoder `Net_ApplyWorldSnapshot` 0x47d828): per unit `ReadInt(oid)`,
  `ReadBits(1,hasEvent)`, `ReadBits(10,mask)`, defIndex. Mask bits: 0=DEF(type/team/owner) 1=POS 2=VEL
  3=ROT 4=SPIN 5=HEALTH 6=WEAPON 7=ENERGY 8=TARGET 9=HARD_SYNC. Vec3 via `Net_DecodeColorTriple` 0x47cfa0
  + `Range_LevelToValue` 0x4f8f40 against the **server-sent TRANSLATION_TABLE** at `DAT_00678134`
  (`Net_HandleTranslationTable` 0x46e9ac), entries 0x40 bytes.

## Why the Python server's gamestate was "bad" — and why our design avoids it by construction
These 5 are the reimplementation traps the bit-perfect (engine-runs-the-math) design SIDESTEPS:
1. Orientation is **euler vec3 @ +0x30**, not quaternion/matrix. (We read the engine's euler directly.)
2. Wire **velocity/spin do NOT write +0x18/+0x3C** — they seed the interpolator; live velocity is the
   engine integrator's output. (We never write wire-vel into the entity; the engine produces it.)
3. Accumulators **+0x24/+0x48 are zeroed every tick** — transient force/torque, not state. (Engine owns them.)
4. Quantization is **server-driven (TRANSLATION_TABLE)**, not constant — hardcoded quant = subtly-wrong
   pos/health/fuel = the "gamestate bad" symptom. (We capture/emit the engine's own table + codec.)
5. Health/fuel are **absolute (level × maxStat)** at +0xD0/+0xD4; wire carries a level index through
   `Range_LevelToValue`. (We read absolute from the struct and emit via the engine's encoder.)

---

## Scope: the server owns the FULL world state (not just per-player tanks)

Authoritative state is **every interacting object**: tanks, base objects (repair/build pads,
generators, turrets, team structures), missiles/projectiles, cargo boxes, flares/FX entities — all
of them, because they interact (weapons hit tanks, missiles track + collide, tanks collide with
terrain/bases, cargo pickup, base capture/power). This is exactly why engine-as-authority is right
and a from-scratch sim is not:

- `EntityPhysics_RunWorldTick @ 0x4f8550` already iterates the WHOLE world list (`DAT_006785e4`) and
  `CollisionContact_ResolveAll` resolves all inter-object contacts every tick. We do NOT reimplement
  object↔object interaction — the engine does it across the full set.
- Server world-state job: keep the engine's world list populated + authoritative (map/base objects
  at load; player tanks on join; missiles when weapons fire), let the engine tick advance + collide
  ALL of them, then replicate the FULL set (create/update/destroy) to every client. Short-lived
  entities (missiles): relay create on spawn, deltas while alive, destroy on detonation/expiry.
- Mechanism: iterate `DAT_006785e4` each tick (every object, type at +0x08), diff vs last-sent
  per client, emit create/update/destroy. Map/base objects come from the map `state` file (the
  proven Python `/s loadmap` populated repair pads + base units — same data → `Obj_Create`).
- Weapons/missiles: a client fire input → server spawns a projectile entity (engine spawn) → engine
  integrates + collides it like everything else → hits damage the target's +0xD0 health. (Weapon RE
  detail = M7; M6 establishes the full-world replication path that carries them.)

---

## Tasks

### M5.0 — RE: finalize the entity physics-field offsets + the inbound action-apply path (READ-ONLY)
- Pin pos/vel/rot/spin/health/energy struct offsets (struct RE in progress).
- Pin how an inbound ACTION_UPDATE (opcode for player action) maps to the engine's action
  channels for a *specific* entity (server-side apply), via the `Sync_*`/`Input_UpdateAnalogControlSliders
  @ 0x441e20` channel path. Report the call to set channel N for entity E so `RunWorldTick` integrates it.
- Report only. No code.

### M5.1a — Bit reader/writer + framing + validators (pure, UNIT-TESTED, no engine, no sockets)
- MSB-first bit reader/writer (matches the engine + Python `streams.py`), TCP `[u16_be len][op][bits]`
  and UDP `[seq][op][bits]` framing, `WriteString`/`ReadString` (`[u16 len-incl-NUL][bytes+NUL]`),
  fixed-16.16 helpers. Reader is **bounds-checked & fuzz-safe**: every read returns ok/fail, never UB.
- Validators: opcode whitelist, length caps, field-range clamps, string-length bounds.
- These are plain C++ (gtest-able on the host build) — highest-value to TDD first, zero engine risk.
- Verify: gtest round-trips + adversarial/truncated-input tests (no crash, clean reject).

### M5.1b — Threaded socket server + per-connection state machine (no engine yet)
- WinSock2 listener (TCP, + UDP gameplay) on the configured port; an accept/I/O thread model
  (thread-per-connection or `select`-based — pick simplest robust). Per-connection state machine
  drives the proven bring-up order; rejects out-of-order packets.
- Inbound parsed+validated → `IncomingCmdQueue` (POD commands). Outbound `OutboundStateQueue` →
  serialized + sent. NO engine calls on these threads.
- Verify: a real wulfram2 client (or a test harness) completes HELLO/LOGIN to VERIFIED against a
  stubbed (engine-less) state source; malformed/hostile inputs are rejected without crashing.

### M5.2 — Bridge: drain queue on the tick thread, apply via the engine (bit-perfect input→sim)
- On the engine tick thread (the `Client_RenderFrame` seam), drain `IncomingCmdQueue`: map each
  validated ACTION command to the engine's action-channel apply for THAT session's entity (with
  owner check) so the next `EntityPhysics_RunWorldTick` integrates it. No hand-rolled physics.
- Verify: a client's inputs move its server-side entity; struct-read positions match the client's
  local prediction (bit-perfect parity).

### M6.1 — Authoritative relay of the FULL world (bit-perfect output)
- On the tick thread, snapshot the WHOLE world list (`DAT_006785e4` — tanks, base objects, missiles,
  cargo, …; by value) → `OutboundStateQueue`. Maintain per-connection last-sent state; diff to emit
  0x18 create (new objects incl. just-spawned missiles), 0x0E UpdateArray (moved/changed), 0x15
  destroy (detonated/expired/removed) using the captured TRANSLATION-table quantization. New joiners
  get a full 0x0F snapshot of every object. HARD_SYNC bit corrects lagged clients.
- Verify: client B sees client A's tank AND base objects AND a fired missile, all authoritative;
  a lagged client snaps back on hard-sync; a destroyed object disappears on all clients.

### M6.2 — Actor tooling
- Tick-thread spawn/move/destroy: `Obj_Create`+`Obj_InitFromSpawn` / `Interp_SetEntityPositionAndRederive`
  / `Obj_DestroyById`, fed from a control command channel. These replicate via M6.1.
- Verify: a tool-spawned actor appears on all clients and can be moved/destroyed.

### M5.3 — SEH boundary (carry over from M4.3, now load-bearing)
- Wrap the per-tick engine calls (queue drain + sim + snapshot) in `__try/__except`: on fault, log
  code/addr + breadcrumb (tick#, last cmd) + MiniDumpWriteDump (dbghelp linked), terminate cleanly.
  Untrusted client input crossing into the engine makes this mandatory.

### M5.4 — World hosting: load a map + populate the world (engine-driven, no network) [VERIFIED CALLABLE]
The full-world bring-up is directly callable in-process (the net handlers are thin parsers over plain
functions). On the tick thread, after boot:
1. `Game_ResetSession(0)` @ 0x419390 — clean session (sets local-player OID `DAT_005b83e0 = -1`; a
   pure server leaves it -1 so nothing grabs the local camera via `Game_EnterWorldAsObject`).
2. **`Client_SetCurrentWorld(worldType, "mapname", worldFlag, seed)` @ 0x4b9eb0** — loads
   `./data/maps/<name>/land`, builds terrain quadtree + the spatial/collision tree. Internally:
   `MapGrid_LoadByName` 0x4e6d10 → `Spatial_RebuildWorldVisibilityTree` 0x441370 →
   `SpatialIndex_RebuildGlobal` 0x4e9030 → `SpatialRoot_InitFromMap` 0x4e8760. After this,
   `DAT_006785e4` (world map) and `g_pWorldTraceRootNode` (collision/raycast tree, sized to map) are live.
3. Per object (tank / base / missile / cargo): `Obj_Create(extra, isLocal=0, type, team, team, 0, 0)`
   @ 0x419a70 — **OID in EBX** (verify the exact convention before calling); auto-inserts into
   `OidTable_Construct`'d `DAT_00677f34`. Then `Obj_InitFromSpawn(x,y,z, oX,oY,oZ)` @ 0x419880 (entity
   in EAX) — sets transform AND **auto-registers into the spatial index** (`SpatialIndex_InsertEntity`
   0x4e8920), so it is immediately collidable + raycastable. No extra registration call needed.
- Boot-time globals (`WorldState_InitGlobal` 0x4e77d0, `World_InitState` 0x417330,
  `CollisionSystem_InitGlobals` 0x4e6fb0, `OidTable_Construct`) already run in `Client_Main` — done by
  the current headless build. **BEHAVIOR 0x24 tunables are NOT needed for spawn/collision/raycast** —
  only for correct movement integration (supply later, M6/M7).
- **Interaction is free:** all hit/collision/proximity queries read the engine's own world via
  `g_pWorldTraceRootNode`/`DAT_006785e4` — `WorldTrace_TraceTerrainAndEntities` 0x4f0c20,
  `Weapon_FireProjectileTrace` 0x4f77f0, `SpatialIndex_ForEachEntityInRadius` 0x4e8220,
  `Entity_CheckCollision` 0x4e73f0. Populate the world ⇒ tanks/missiles/bases interact natively.
- **Hard prereq:** map files must exist at `./data/maps/<name>/` relative to the headless process CWD
  (engine hard-codes `"./data/maps/"`; missing → `_exit`). Surface `..\Wulf-Forge\shared\data\maps\`
  (or the client's `data\maps\`) as `./data/maps/`. Tick already calls `SpatialIndex_TickMaintenance`
  when `g_pWorldTraceRootNode != 0`, keeping the index fresh as objects move.
- Verify: load a map headless (no crash), spawn N objects, confirm they appear in `DAT_006785e4`
  and that an `Entity_CheckCollision`/`WorldTrace_*` query sees them; this is the world the relay
  (M6.1) replicates and the action ingest (M5.2) drives.

---

## CODEX REVIEW (2026-06-16) — accepted findings + the resolved crux

Codex reviewed this plan. Accepted findings folded in below; the crux changes the control model.

### CRUX RESOLVED — the local-input channel is single-player; remote players must be per-entity
RE answer (verified): `Input_UpdateAnalogControlSliders @ 0x441e20` takes **no entity arg** — it reads
global slider singletons and calls `Sync_SetChannelTarget @ 0x45ca30`, which writes the **global**
channel-table singletons (`DAT_00678f44`/`DAT_00678f9c`/`DAT_00678eec`) indexed by channel id only.
No entity pointer anywhere on that path, and the binary (a CLIENT) has **no `Net_HandleActionUpdate`**
— it only SENDS `ACTION_UPDATE` and only drives the ONE local player. Routing N players through the
channel bus would collapse them onto one entity (last write wins). **Do NOT use the local-input
channel as a multi-tenant API.**
- **Adopted model:** the engine authoritatively simulates ALL entities in the world list; for each
  remote player's tank we inject control state **per-entity** onto its OWN physics/control object
  (per-entity tuning/control struct around `entity+0x48`/`+0x4c`, physics `@ +0xBC`), NOT via the
  global channels; then `EntityPhysics_RunWorldTick` integrates all of them. Local-channel path is
  used for at most one optional server-local slot, or not at all.
- **M5.0b (NEW, do FIRST, READ-ONLY):** pin the exact per-entity control fields — how a NON-LOCAL
  tank's throttle/turn/strafe reach its physics object so `IntegrateStep` produces motion (trace the
  active-vehicle control-apply in `RunWorldTick`'s per-entity branch / around `Vehicle_UpdateThrustFx`,
  reading `entity+0x48`/`+0x4c`/`+0xBC`). Raw accumulator writes (+0x24/+0x48) are a last-resort shim
  only (transient, zeroed each tick, bypass gameplay logic).

### Resequencing (accepted): prove control injection CHEAPLY before the socket server
New order: **M5.3 SEH first** (crash diag) → **M5.4-min** (boot → `Game_ResetSession` →
`Client_SetCurrentWorld` → spawn ONE entity → run 10 ticks → confirm predictable motion) →
**M5.2-min** (inject control for that one non-local entity, confirm physics integrates it, read it)
→ THEN build **M5.1b** socket server at scale → M6.1 relay → M6.2 tooling. M5.1a stands; M5.1b's
engine-less socket code is unaffected by the crux (its bridge just isn't wired until M5.2-min proves
the control path).

### Timing contract (accepted, MAJOR)
Stamp each validated command with a sim-tick/seq on arrival; drain the IncomingCmdQueue EXACTLY once
per tick at a fixed PRE-physics point on the engine thread; snapshot for relay ONLY AFTER
`Interp_StepSimulationSubsteps`/`RunWorldTick` returns and accumulator zeroing is done (gate with an
explicit post-tick flag). A net thread MUST NEVER read engine memory for any purpose.

### Engine interference (accepted, MAJOR)
The engine's own client net (`Net_ServiceConnection 0x46b830`, `DAT_005f3844`, `DAT_006782e4`) is
still live and could open sockets / contend on our port / re-enter world state. STUB/NO-OP the native
connect + `Net_ServiceConnection` at inject time. Audit `SetTimer`/`WM_TIMER`/`timeSetEvent` so the
only code walking the world list / physics is OUR tick seam.

### Bit-perfect hazards beyond the 5 (accepted, MAJOR)
- **x87 control word:** set/restore the engine's FPU precision+rounding mode on the tick thread (match
  the `_controlfp` the engine set in init); verify with a known-value vector.
- **fixed16.16 rounding:** implement identical to the engine's assembly at the quant site (don't assume
  `lround`); negative/halfway values are FPU-rounding-mode dependent.
- **dt source:** confirm whether `RunWorldTick`/`IntegrateStep` reads its own timer (timeGetTime/QPC)
  or takes a dt arg; if self-timed, Sleep-pacing → cross-machine non-determinism; if arg, pass fixed dt.
- **collision iteration order:** `CollisionContact_ResolveAll` is sensitive to world-list insertion
  order — enforce canonical spawn order (map objects by file order → players by join order → missiles
  by fire order); never hash/pointer iteration for physics.
- **read after tick only** (timing contract).

### Missing (accepted)
Per-opcode reliability: create(0x18)/destroy(0x15) reliable (TCP); pos/state (0x0E/0x0F) unreliable
(UDP). Document clock-drift (0x2F) handling, reconnection, and whether UDP `[seq]` is passthrough/
echoed/synthesized by us. DEFER per-client interest/visibility scoping (broadcast-to-all first).

### MINOR
Session-key echo is trust-the-echo (no crypto); UDP source-IP binding is the only mitigation (none
behind NAT). Acceptable for LAN/trusted; document the threat model for internet use.

## Risks / notes
- Resident dispatch table is the CLIENT handler set (RECEIVES spawns/snapshots) and has NO server-side
  action-apply — we drive per-entity control directly (see crux above).
- "Current player" singletons (`DAT_00677f2c`/`DAT_005b83e0`/the channel bus) assume one local player;
  remote players are NON-LOCAL entities, never routed through those singletons.
- Keep M3/M4 verified behavior (headless boot, hidden window, paced tick) — do not regress.
