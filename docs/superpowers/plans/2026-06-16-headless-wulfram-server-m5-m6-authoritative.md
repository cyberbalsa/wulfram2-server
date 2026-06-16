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

### Two ways to be the server (DECISION NEEDED — see below)
- **(A) In-binary accept bridge:** `Net_InitAccept` 0x507ff0 + `Net_FindOrCreatePeer` + reuse the
  engine's own send/recv. Maximal reuse of engine framing, but the resident handler table is the
  CLIENT set; we'd register/drive server-side handling.
- **(B) Independent socket server in the DLL** that speaks the (now-known, proven) framing
  directly (port the Python protocol to C++), and uses the in-process engine purely as the
  **bit-perfect physics oracle** (feed inputs → run engine tick → read entity structs → emit
  state). Cleanest separation; the protocol is already proven in Python.
- **(C) Inject inbound packets into the client receive path** via `Proto_DispatchPacket` 0x509f70.

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

## Tasks

### M5.0 — RE: finalize the entity physics-field offsets + the inbound action-apply path (READ-ONLY)
- Pin pos/vel/rot/spin/health/energy struct offsets (struct RE in progress).
- Pin how an inbound ACTION_UPDATE (opcode for player action) maps to the engine's action
  channels for a *specific* entity (server-side apply), via the `Sync_*`/`Input_UpdateAnalogControlSliders
  @ 0x441e20` channel path. Report the call to set channel N for entity E so `RunWorldTick` integrates it.
- Report only. No code.

### M5.1 — Multi-client accept bridge
- Per-tick pump seam: the `Client_RenderFrame` detour (runs every loop iteration) is the natural
  hook — after pacing, call our `ServerTick()` (accept new peers, pump each peer's recv, run relay).
- Stand up the game listener: `Net_InitAccept(mgr, 1, tcp_port)` (+ UDP type 2 as needed); mgr =
  `DAT_006782e0` or a fresh `operator_new(0x4c)`. Accept readable sockets → `Net_FindOrCreatePeer`
  → keep a peer list (our own std::vector).
- Per new peer: drive the HELLO handshake (version 0x4e89) + LOGIN using `Net_SendStart`/`Proto_FinishPacket`.
- Verify: two clients can establish a connection (or a loopback self-connect) without crashing;
  the existing single-connection path still works. SEH-guard the per-peer parse (see M5.3).

### M5.2 — Action ingest (bit-perfect input→sim)
- Parse each peer's inbound ACTION_UPDATE/ACTION_DUMP (reuse the engine's MemBuf/stream readers),
  and apply the channel values to THAT peer's server-side entity via the engine's action path so the
  next `EntityPhysics_RunWorldTick` integrates them. No hand-rolled physics.
- Verify: a client's inputs move its server-side entity; positions read from the struct match the
  client's local prediction (bit-perfect parity check).

### M6.1 — Authoritative relay (bit-perfect output)
- Each tick: gather changed entities (dirty), broadcast 0x0e UpdateArray (+0x18 create/0x15 destroy)
  to every peer via the engine's serializer. Use HARD_SYNC bit to correct lagged clients.
- Verify: client B sees client A's tank move authoritatively; a lagged client snaps back on hard-sync.

### M6.2 — Actor tooling
- In-process spawn/move/destroy: `Obj_Create`+`Obj_InitFromSpawn` / `Interp_SetEntityPositionAndRederive`
  / `Obj_DestroyById`. Expose via a simple command/control surface. These replicate via M6.1.
- Verify: a tool-spawned actor appears on all clients and can be moved/destroyed.

### M5.3 — SEH boundary (carry over from M4.3, now load-bearing)
- Wrap per-tick + per-peer-parse engine calls in `__try/__except`: on fault, log code/addr +
  breadcrumb + MiniDumpWriteDump (dbghelp linked), terminate cleanly. Untrusted client packets make
  this mandatory.

---

## Risks / notes
- Resident dispatch table is the CLIENT handler set (it RECEIVES spawns/snapshots). To act as the
  server we register a server-side handler subset (LOGIN/HELLO/ACTION inbound) or hand-drive; prefer
  reusing engine readers to keep parsing bit-perfect.
- "Current player" singletons (`DAT_00677f2c`) assume one local player; multi-client needs care so
  per-peer state does not collide with the resident client-singleton assumptions (audit in M6/M7).
- Keep M3/M4 verified behavior (headless boot, hidden window, paced tick) — do not regress.
