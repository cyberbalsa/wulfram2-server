# Wulfram II Headless Server — Progress

Living log of what's been done. Newest entries at the top of each section.

**Repo:** https://github.com/cyberbalsa/wulfram2-server (private) · default branch `master` ·
identity `cyberbalsa <804052+cyberbalsa@users.noreply.github.com>`.

## What this is
Turn the original `wulfram2.exe` client into a headless, authoritative multiplayer server by
**injecting a C++ DLL**, stubbing the render/audio/input "head", hijacking `Client_RunMainLoop`,
and reusing the binary's own physics + `Net_*` code. Spec and plan live under `docs/superpowers/`.

## Key decisions
- **Architecture:** function-level reuse of the binary's authentic physics; all-in-C++ injected
  server; boot client → stub head → hijack loop. (spec: `docs/superpowers/specs/2026-06-15-headless-wulfram-server-design.md`)
- **Language: C++** (MSVC x86). Rust evaluated and rejected 2026-06-15 (`__thiscall` nightly-only,
  no native SEH, FFI-heavy so Rust safety is neutralized).
- **Hooking:** MinHook **v1.3.4** (FetchContent). **Build:** CMake + Ninja, 32-bit only, `/W4 /WX /sdl`.
- **Testing:** GoogleTest (FetchContent + CTest) — replacing the initial hand-rolled harness.
- **Static analysis:** clang-tidy (LLVM x64) + cppcheck + MSVC `/analyze`.
- **Binary pinning:** PE stamps + hook-site bytes validated before any hook (loader + InitThread).

## Milestone status (M0–M2 plan)
- [x] **Task 0** — Repo + CMake skeleton + MinHook v1.3.4 + strict flags. Commits `f52c342`, `df27c7c`, `16378cc`.
- [x] **Task 1** — Logging subsystem (leveled async, file + OutputDebugString). Commits `841421f`, `f086fd8`
      (hardening: idempotent `Init`, safe `~State` teardown). Both reviews passed.
- [x] **Task 1.5** — clang-tidy + cppcheck installed; tests migrated to GoogleTest (FetchContent + CTest);
      `lint.ps1` gate (clang-tidy + cppcheck) green. Commits `c4ffa26`, `97ef444`. Verified: ctest 2/2, lint PASS.
- [x] **Task 1.6** — Git hooks (`.githooks/` + `core.hooksPath`): pre-commit clang-format check; pre-push
      hard gate (build `/W4 /WX` zero-warning + `lint.ps1` + ctest). Verified blocks a warning & a mis-format.
      Commits `e8b4341`, `5f99f16`. Docs: `docs/quality-gate.md`. (pre-push uses `pwsh`; hooks pinned LF.)
- [x] **Task 2** — Loader arg parsing (`ParseLoaderArgs` + `CreateInjectionPlan`, GoogleTest). Commit `92f5a01`.
      Verified green via the live pre-push gate (build + lint + ctest).
- [x] **Task 3** — PE manifest model + validator. Commits `f5fdefd`, `8dc72e8` (Codex-hardened:
      alignment-safe `memcpy` parse, PE32 magic + optional-header-size checks, `VirtualQuery`
      readability guard so a wrong manifest fail-stops instead of faulting), `3b92105` (tests).
      10/10 ctest, lint PASS. **Codex-reviewed.**
- Note: **reordered Task 5 (generator) before Task 4 (injector)** — injector.cpp includes the
      generated `binary_manifest.h`, so the generator must run first to keep the gate green.
- [x] **Task 4** — Injector (suspended-launch + binary-pinning gate + LoadLibraryW remote-thread) + loader main.
      Commits `f3c182e`, `b7e7160` (Codex-hardened: 15s wait timeout, TOCTOU read-lock across spawn, checked
      ResumeThread/GetExitCodeThread/GetModuleHandle). 12/12 ctest, lint PASS. **Codex-reviewed.**
- [x] **Task 5** — `gen_addresses.py` + pytest; generated `addresses.h` (17 consts) + `binary_manifest.h`
      with real `wulfram2.exe` stamps (stamp `0x45254d1f`, size `0x288000`, sum `0x1c45a4`, base `0x400000`).
      gtest static-asserts the headers. Commit `20d1448`. 11/11 ctest.
- [x] **Task 6** — ABI binding typedefs (`Cdecl`/`Stdcall`/`Thiscall` by absolute address). `__thiscall`
      confirmed clean under `/permissive- /WX`. Commit `ea69f8c`. 13/13 ctest.
- [x] **Task 7+8** (merged) — minimal `DllMain` (loader-lock-safe) → `InitThread` (binary self-check +
      config-driven log level via header-only `ParseLogLevel`, unit-tested). Commit `71d9658`. 14/14 ctest.
      Codex review dispatched but stalled; **loader-lock safety validated empirically by the Task 9 smoke**.
  (Task 8 config/log-level wiring folded into Task 7+8 above.)
- [x] **Task 9** — Integration smoke (injected into real `./w2/wulfram2.exe`): pinning OK (stamp match) →
      suspended launch (pid) → injected → **InitThread markers logged inside the live process** (<0.5s, no
      loader-lock deadlock); wrong binary rejected (exit 1, no spawn); process cleaned up. Notes: `docs/superpowers/notes/2026-06-16-m0-m2-smoke.md`. Commit `02d9097`.

### ✅ Milestone 0–2 COMPLETE (2026-06-16)
Foundation done: 32-bit CMake/MinHook build, zero-warning quality gate (clang-tidy + cppcheck + git hooks),
async logging, suspended-inject loader with PE binary-pinning + TOCTOU lock, address/manifest generation from
the real binary, ABI typedefs, and a minimal DllMain→InitThread that runs in the live game process. Codex-reviewed
the security-critical paths (PE validator, injector). Final-review fixes applied (commit `d17becc`, 15/15 ctest): intentionally-leaked logger singleton
(no DLL-teardown join hang), `inline constexpr kSites`, malformed-PE fuzz tests, `ParseLogLevel`
precision, module-relative loader log.

Next: **Milestone 3 — head-chop** (stub the 12 `*_Init` seams, capture real hook-site bytes, prove
headless boot to the loop seam). Design input: `docs/superpowers/notes/2026-06-16-m3-head-chop-discovery.md`
— key finding: head/body are decoupled (no body-init reads head globals), so 11/12 seams are plain-stubbable.

## ⟳ M3 APPROACH PIVOT (2026-06-16): head-chop → boot hidden (Approach B)
The head-chop (stub every `*_Init`) hit an open-ended NULL-deref cascade (driver vtable → viewport →
keystate → …). **Decision: switch to Approach B** — let the engine boot its built-in SOFTWARE renderer
into a HIDDEN window (it allocates its own state, no NULL-derefs), force "Software Windowed", keep only the
real env bypasses (registry/browser), then hijack `Client_RunMainLoop` for the server tick (per-frame render
never runs). See `memory/m3-approach-b-boot-hidden.md`. The M3.1-M3.9 head-chop commits stay in history (they
map the boot path); the live install path will be reworked. Running in tight, reviewed steps from here.

### ✅ M3 ACHIEVED via Approach B (verified 2026-06-16, commit `4a5022c`)
`wulfram2.exe` boots **fully headless**: force GDI software renderer (`DAT_00679169=1`) + hide the window
(MinHook `CreateWindowExA`/`ShowWindow` → strip `WS_VISIBLE`, `+WS_EX_TOOLWINDOW`, `SW_HIDE`). Retired the
11 `*_Init` stubs + M3.4/3.8/3.9 + the `DAT_00679123` clear; kept registry/browser bypasses + the
`Client_RunMainLoop` observation detour. **Independently verified** (controller's own run): `MainWindowHandle=0`,
no window, CPU rising (running a real loop), stable, no AV; clean process teardown. 16/16 ctest, lint PASS.
**Nuance for M4:** the game runs `Client_Main`'s INLINE render loop, not `Client_RunMainLoop @ 0x4a0aa0`
(that path is `DAT_00677f1d`-gated and not taken here) — so M4 must hijack the inline loop.
**Process note:** a subagent overran scope badly (ran hours, made unsanctioned commits incl. the architecture
pivot). Outcome aligns with the approved Approach B, but going forward: tight, reviewed, single-purpose steps.

### ✅ M4 core achieved (verified 2026-06-16, commit `05dd6ca`)
Headless **server tick**: neuter `Client_RenderFrame @ 0x4281a0` (pure-draw, `void __stdcall`) → paced no-op;
keep `DAT_00677f1d==0` so `Client_Main`'s INLINE loop runs as the persistent tick (it already pumps
net/sim/anim each iteration via `Net_ServiceConnection @ 0x46b830`). **Verified (controller run):** no window,
~10Hz paced (CPU ~0.2s/5s), persistent, no AV, clean teardown. (`e746f70` was a superseded wrong-direction
connect-gate spoof — inactive in `05dd6ca`.) M4 refinements still open: explicit fixed-timestep + SEH boundary.
**Process note 2:** the same runaway subagent did M4.1+M4.2 autonomously; now hard-stopped.

### ⚠ FUNDAMENTAL M5 FINDING — `wulfram2.exe` is a CLIENT, not a server
The persistent loop pumps the CLIENT's single connection; there is **no in-binary listen/accept for game
traffic** (the `Net_InitAccept*` server primitives are only wired to the DbgNet debug port 6969). So the
original "all-in-C++ injected server reusing Net_*" assumption doesn't hold as-is. To make this an authoritative
server requires a topology decision.

### M5 DECISION (2026-06-16): all-in-DLL, approach B + engine owns the world
**Topology:** build the server in the injected DLL (all-in-one process). **Networking = B** — independent C++
socket server speaking the proven `Wulf-Forge` framing (NOT the engine's client-side Net accept machinery).
**HARD CONSTRAINT (user):** the ENGINE owns/tracks the whole object world — spawn all entities into its own
pools via `World_InitState`/`SpatialRoot_InitFromMap`/`CollisionSystem_InitGlobals`/`Game_EnterWorldAsObject`/
`Obj_InitFromSpawn`, so its NATIVE collision/spatial-index/raycast/hit-detection work on real objects. No
parallel object model or reimplemented collision in C++. The engine remains the source of truth for the
entire game state sent to clients; the C++ socket layer may hold only session state, validated commands,
and by-value outbound snapshots from the engine tick. See `memory/m5-server-topology-all-in-dll.md`.
M5.0 RE complete (`49ad05b`): full handshake (HELLO ver `0x4E89`), entity contract (euler orient `+0x30`,
health `+0xD0`…), and the 5 "gamestate-bad" traps the headless design avoids. **Driving M5 in tight,
controller-reviewed steps** (the prior autonomous agent overran repeatedly; now done).

### M5 implementation progress (2026-06-16)
- [x] **M5.1a** — hardened wire-protocol core already landed (`4f5bdea`): MSB-first bit codec,
      TCP/UDP framing, fixed16.16/string helpers, opcode/field validators, adversarial tests.
- [~] **M5.1b host-tested socket front end** — added `wfh_server_net` target + WinSock2
      select-based TCP/UDP acceptor, config parser, bring-up packet builders, per-connection
      HELLO/LOGIN/WANT_UPDATES state machine, thread-safe inbound/outbound queues, and a DLL-owned
      `ServerRuntime` that starts/stops the acceptor from `headless.toml`. TDD additions:
      loopback TCP HELLO burst, disconnect reaping -> `Disconnected`, raw UDP HELLO key-echo
      compatibility, and runtime start/stop on an ephemeral port. `InitThread` now starts the
      socket runtime after binary self-check + hook install and before the loader ready signal;
      bind/start failure is fatal before the suspended game is resumed. Added TRACE/DEBUG probes
      across DLL init, hook install/call paths, socket runtime/acceptor, and connection state
      transitions; default DLL config now enables TRACE, and CMake copies `config/headless.toml`
      into `build/config` so injected runs use the repo default. Verified `.\build.ps1` =
      61/61 CTest PASS and `.\lint.ps1` = PASS.
      **Injected listener smoke passed:** `build\loader.exe .\w2\wulfram2.exe -windowed`
      logged `level=0`, `server runtime listening on port 2627`, TRACE tick/hook/net lines,
      and accepted a TCP loopback session; launched process was cleaned up. **Real rendering
      client smoke still pending**; current bar is injected DLL listener behavior.
- [x] **M5.1c MVP online visibility bridge** — clients can now connect, complete the proven
      HELLO/UDP/LOGIN/WANT_UPDATES flow, and receive visible tank snapshots for each connected
      session. Ported the old `../Wulf-Forge` BEHAVIOR/TRANSLATION bootstrap shape into
      host-tested C++ packet builders, added a `VIEW_UPDATE` full-snapshot encoder, and added a
      tick-owned `MvpOnlineBridge` that drains validated session commands and pushes reliable
      per-session snapshots back through the acceptor. TDD coverage: translation table shape,
      two-tank `VIEW_UPDATE`, post-login BEHAVIOR+TRANSLATION bring-up, bridge fanout to both
      sessions, and a regression for the real TCP/UDP ordering race where UDP key echo can arrive
      before the delayed TCP HELLO(version). Verified `.\build.ps1` = 68/68 CTest PASS and
      `.\lint.ps1` = PASS.
      **Injected MVP smoke passed:** `build\loader.exe .\w2\wulfram2.exe -windowed` on the default
      config (`trace`, port 2627), two raw loopback clients logged in, sent `WANT_UPDATES`, and both
      received `VIEW_UPDATE` entity counts `[2, 2]`; launched process was cleaned up. **Authority
      caveat:** this is a temporary tick-owned projection so clients can see tanks online. Ghidra
      showed `Obj_Create @ 0x00419a70` and `Obj_InitFromSpawn @ 0x00419880` use custom EBX/EAX
      register handoff patterns, so the next engine-source-of-truth step needs a small verified
      assembly/ABI wrapper before snapshots are read from real engine objects.
- [x] **M5.1d map/spawn/physics packet parity** — continued the MVP toward real rendering-client
      compatibility using the old `../Wulf-Forge` server as protocol reference. TDD additions now
      cover: loading map `state` entities before player spawn, synthesizing team repair pads when
      map state lacks them, parsing in-game UDP reincarnate/spawn requests, emitting Python-shaped
      `TankSpawn`/`Reincarnate`/`BirthNotice` packets, and matching the Python `packets.toml`
      BEHAVIOR full-frame length/hash (`3566`, FNV-1a32 `0x11c91899`). The default map is now
      `bpass` in both `ServerConfig` and `config/headless.toml`, matching the Python default; the
      sent physics values now match `packets.toml` (`ground_friction=0.8`, `turn_rate=0.05`,
      `suspension_dampening=1.3`, `gravity_pct=1.0`). Verified `.\build.ps1` = 79/79 CTest PASS
      and `.\lint.ps1` = PASS. **Live rendering-client smoke status:** the previous attempt was
      stopped after client instability/launch confusion, all `wulfram2` processes were killed, and
      the original `w2\_override_args` was restored; rerun pending after this `bpass` + BEHAVIOR
      parity fix.
      **Follow-up before handoff:** live smoke then proved the server/client flow could reach
      login/WANT_UPDATES and send a snapshot, but also exposed that injected map loading used the
      wrong relative root (`w2\data\maps` from an already-`w2` CWD), so `bpass/state` was missed and
      fallback pads were used. Added a failing default-bootstrap regression, changed the default map
      root to `data\maps`, and logged resolved state paths. Also matched the Python server's UDP
      reincarnate ACK (`0x02`, len `9`, subcmd `1`, acked opcode/sequence), with both connection and
      acceptor socket tests. Latest verification before handoff: `.\build.ps1` = 80/80 CTest PASS.
      The final `.\lint.ps1` rerun was interrupted by the user after lint-driven structural fixes,
      so lint still needs a fresh rerun next session before claiming clean.
- [~] **M5.3 guarded tick seam** — added host-tested `wfh_server_tick` SEH boundary:
      `RunProtectedTick` records tick/phase breadcrumbs, catches SEH access violations, reports
      code/address, and optionally writes a minidump through DbgHelp. TDD path started red on the
      missing guard API, then added tests for success, SEH capture, and dump writing. The live
      `Client_RenderFrame` detour now runs its headless pacing body through this guard and exits
      with a distinct `WT` code on guarded faults; TRACE logging is enabled around begin/end and
      render suppression by default. Verified `.\build.ps1` = 64/64 CTest PASS, `.\lint.ps1` =
      PASS, and injected smoke observed both `server runtime listening` and
      `protected tick begin phase=Client_RenderFrame` under `build\logs\headless.log`.
- **Physics timing check (Ghidra, 2026-06-16):** physics is wallclock elapsed-ms based, not
      render-FPS/present bound. `Interp_StepSimulationSubsteps @ 0x00469e00` computes elapsed
      time from the engine timer delta (with first-frame default/cap and up to five substeps) and
      calls `EntityPhysics_RunWorldTick @ 0x004f8550(world, elapsed_ms)`, which divides elapsed ms
      by 1000.0 before integration/collision. `Client_Main @ 0x004186d0` updates the wallclock
      delta before sim/interp work and reaches `Client_RenderFrame @ 0x004281a0` only after that.
      Conclusion: we do **not** need to run rendering just to keep physics advancing. Our current
      render hook is a post-sim pacing seam; changing its `Sleep(100)` changes the wallclock loop
      cadence and therefore the elapsed time the next engine tick sees. Caveat: the current SEH
      guard catches only the render/pacing seam; guarding engine sim faults directly would require
      a deeper hook around `Interp_StepSimulationSubsteps` or its call site.
- **Reference checked:** `../Wulf-Forge` Python server is useful as a *protocol/packet-order*
      reference, not as a game-state model. Confirmed `do_login_and_bootstrap` order, LOGIN status
      flow, BEHAVIOR/TRANSLATION placement, raw UDP key echo (`opcode+body`) and optional UDP
      length envelope. The C++ acceptor now accepts the Python-observed raw UDP key echo while
      keeping strict seq-framed UDP support. Do NOT port Python `EntityManager`/`TankSim` authority;
      use engine world objects and engine-produced snapshots instead.
- **Tooling/process constraints:** use Ghidra for engine function-call, ABI, and hook-site lookups
      when moving back into engine integration; prefer structural fixes over lint suppressions
      (only suppress macro/SDK necessities); keep network threads away from engine memory.
- **Next:** official rendering-client smoke against the injected DLL listener, then continue the
      accepted resequence: finish the engine spawn/read wrapper for M5.4-min map/world populate ->
      M5.2-min per-entity control injection -> any deeper sim-guard decision for M5.3. The engine
      must become the source of truth for outbound snapshots; BEHAVIOR/TRANSLATION should
      ultimately come from engine/captured tables, not hard-coded Python defaults.

### ⟳ M6 — real-time positions of all entities incl. players (in progress 2026-06-16)
Goal: tanks move in real time for all clients. Client sends INPUTS only (confirmed in Ghidra:
`ACTION_UPDATE 0x0A`/`ACTION_DUMP 0x09`, never position), so the server must SIMULATE. Decision (user):
drive the BINARY's own vehicle physics per entity — NOT a ported sim ("use Ghidra, it's more true").
Relay vehicle already exists: the per-tick snapshot carries every entity (incl. session tanks); they're
just static because nothing updates their pos. Full RE map persisted in `memory/m6-tank-physics-drive-recipe.md`
and `memory/m6-realtime-movement-relay.md`.

Verified-in-Ghidra physics map (this session):
- `0x46af90` is a NET/render hook (NOT physics — the Python port mislabels it).
- Per-tank step = `Vehicle_UpdateThrustSimulation @0x4f9e20` `__thiscall(controller, paramObj)`, VIRTUAL
  (Tank vtable 0x543128). It sets controller+0x48=paramObj, +0x4c=*(paramObj+4)=entity (health@entity+0xd0),
  runs ComputeControlScalars/Thrust. Construct: `Tank_Construct @0x4f9a40` (__fastcall, 0x20B). Local-player
  template: `TankClient_Construct @0x4902b0` → `VehicleInstance_InitForEntity`. Integrate:
  `EntityPhysics_IntegrateStep @0x4f2890`. physObj @entity+0xbc; tuning table @physObj+0xc0; control-input
  slots (turn1/forward2/strafe3) writable per-tank. Multi-tank-safe (per-object), EXCEPT the local-player
  Sync sliders + the global world physics tick.

**cdb live capture done + full recipe mapped (decision: full authentic controller).** Broke on a real driven
local tank's `0x4f9e20` and captured ground truth (entity pos@+0x0c/rot@+0x30, physObj@entity+0xbc with
pos@+0x10/rot@+0x1c, health@+0xd0; the step's `this`=Tank_Model[vtable 0x5430e8], `param`=Tank_Vehicle[0x543128],
Tank_Vehicle+0x04=entity/+0x10=model). Traced the whole construction: the MODEL is looked up from a registry
(`VehicleInstance_InitForEntity @0x4f63c0` → `VehicleModel_FindById(entity+8)`), NOT constructed — so the build
is just: `new(0x20)` → `Tank_Construct @0x4f9a40` → `InitForEntity` → per tick write raw control at tuning
`slot+0x10` (slot = `*(*(physObj+8)) + n*0x20`, n=1 turn/2 fwd/3 strafe, raw=input*`*(physObj+0xc)`) →
`Vehicle_UpdateThrustSimulation @0x4f9e20` → integrate (`EntityPhysics_IntegrateStep @0x4f2890` or the global
world tick) → `ReadEngineWorld` relays. FULL verified recipe in `memory/m6-tank-physics-drive-recipe.md`.

**M6 Increment 1 DONE (cdb + live-validated):** added engine thunks `EngineTankConstruct`(Tank_Construct
0x4f9a40, __fastcall) + `EngineVehicleInitForEntity`(0x4f63c0, __thiscall) and a `BuildDriveController`
spike in `world_host_engine.cpp` that, after the test spawn, constructs a vehicle controller for the entity.
Validation run logged `M6 drive controller built: vtable=0x543128 model=0x... (model!=0)` + no crash — so
the headless server HAS the vehicle-model registry and `InitForEntity` resolves a model. The full graph is
confirmed: entity(+0xbc physObj) ↔ Tank_Vehicle(0x543128) ↔ Tank_Model(0x5430e8/type-specific).

**Dev live-poke console (tooling, replaces the rebuild/cdb loop):** localhost command socket (default port
**6969**, `[server] dev_port`) — `src/dll/server/net/dev_console.cpp` + Python client `tools/dev_poke.py`.
- Increment 1 (peek/poke/help) + Increment 2 (`call` + `bt`) are LIVE. `call <addr> <conv> [args]` runs on the
  engine tick thread (marshaled via `PumpDevEngine` in `ServerTickBody`; universal x86 invoker
  `EngineRawInvoke` in engine_thunks.cpp, ESP-frame-restore so convention-agnostic; SEH-guarded). `bt`
  suspends the engine thread + EBP-walks (wulfram2+RVA). DLL side: `src/dll/server/dev_engine.cpp`.
- Live-verified: `peek 0x4f9e20 16`→`8b 44 24 04 …`; `world` decodes the engine entity; `bt`→`wulfram2+0x18f7b`;
  `call 0x4f9e20 thiscall <model> <tankVehicle>`→`ok eax=…`, no crash. 109/109 CTest, lint PASS.
- **2b (next):** `bp`/`bc`/`hook` via VEH int3 (log-mode trace breakpoints + callstack capture).

**M6 live-drive findings (via the dev console):** constructed a vehicle controller for the test entity and
drove it live. Input → control-scalar WORKS: poking the forward slot (`*(TankVehicle+0x08)`→base`+0x50`,
value = float/divisor; divisor=50) then `call 0x4f9e20` set `model+0x70` (forward scalar) = 1.0. `call`
`EntityPhysics_IntegrateStep@0x4f2890` runs clean. **BLOCKER:** thrust = 0 — the vehicle tuning table is
entirely zero (slots 6/7 throttle/thrust = 0). ROOT CAUSE (user's framing): the headless engine **booted a
world but never joined a server**, so the on-join client state a server pushes — vehicle tuning (BEHAVIOR),
TRANSLATION tables, etc. — is unset; the server only *builds* `BuildBehavior` to SEND, never feeds it to its
own engine. Authentic fix = run the server's own on-join data through the engine's **client-side handlers**:
`Net_HandleBehavior @ 0x46dc00` (loads physics globals + `VehicleInfo_LoadGlobalState` +
`VehicleModel_ForEachLoadResources` = the tuning). It takes an engine **MemBuff**, so wrap the BEHAVIOR body
+ call it (same for TRANSLATION 0x32). Then thrust → integrate → motion.

### ✅ M6.2-min(a) — on-join self-load: BEHAVIOR fed through the engine's client handler (2026-06-17)
The headless engine now loads its own vehicle physics tuning at bootstrap by feeding the server's
own BEHAVIOR through the engine's **client-side** handler — exactly as a joined client would. The
engine booted a world but never "joined", so its tuning globals were unset (the diagnosed thrust=0
root cause). **Built, live-validated via the dev console, wired into the world-host bootstrap, and
re-verified end-to-end on a fresh injected session.**
- **Full RE of the MemBuff construction** (the crux): `Net_HandleBehavior @ 0x46dc00` is
  `__cdecl(p1,p2,packet)` (p1/p2 unused); `packet` is an engine **MemBuff** (hunk-list bit-stream,
  MSB-first — matches our `BitWriter`). Mirrored the engine's OWN receive path
  `Net_ProcessOrderedReceiveQueue @ 0x504a2c`: `_malloc(0x20)` struct + `_malloc(len)` body (copy in)
  → `BitBuf_ConstructWithChunk(membuf, mode=1, body, len, owner=0)` (`__thiscall` ECX=membuf, `RET 0x10`)
  → `Net_HandleBehavior(0,0,membuf)` → `MemBuff_FreeAllHunks(membuf)` + `_free(membuf)`. VAs: `_malloc`
  `0x50c8eb`, `_free` `0x50c292`, `BitBuf_ConstructWithChunk` `0x508a50`, `MemBuff_FreeAllHunks`
  `0x509a30`. Body buffers MUST be engine-`_malloc`'d (the engine frees them). All calls go through
  the existing `SafeEngineInvoke` (convention-agnostic, SEH-guarded).
- **HEADLESS-SAFE confirmed** (RE + live): `VehicleModel_ForEachLoadResources @ 0x4e9630` is pure
  stream-deserialize + heap (zero graphics/file I/O). BEHAVIOR's only side effect is
  `Net_FlushSendBuffer(packet)` on the packet itself, so **no live connection needed**. (TRANSLATION
  `0x32`/`Net_HandleTranslationTable @ 0x46e980` is NOT wired: it sends a `0x33` ACK via
  `DAT_006782e4` which needs a live send object, AND it is not required — our C++ relay does its own
  quantization; the engine's `DAT_00678134` codebook is unused by us.)
- **Verified live** (`tools/feed_onjoin_probe.py`): `0x679170` scalar block 6→25 non-zero bytes (11
  header floats 0.0→1.0); Tank model config doubles loaded — hover height **3.25 (default) → 9.75**
  (= our `kTankHoverHeight`), proving OUR BEHAVIOR deserialized into the model. After wiring: the
  fresh session logs `on-join BEHAVIOR fed to engine (body=3563 bytes, faulted=0)` at bootstrap.
  Build = **109/109 CTest**, `lint.ps1` = **PASS**.
- Code: `FeedBehaviorToEngine()` in `world_host_engine.cpp` (one-shot after bootstrap, before the
  relay/controller). New dev tools: `tools/feed_onjoin_probe.py`, `tools/drive_probe.py`; a DISABLED
  gtest `BringupPackets.DISABLED_DumpOnJoinBodies` dumps the body bytes for the live probe.

**DRIVE BLOCKER precisely scoped (next increment, M6.2-min(b)):** the on-join load is necessary but
NOT sufficient to drive a non-local server tank. Live drive of the test entity (post-BEHAVIOR) still
produced no motion. Ground-truth thrust math (decompiled this session):
- `Vehicle_UpdateThrustSimulation @ 0x4f9e20` gates on `entity+0xd0 (health) != 0` (ok) AND
  `TankVehicle+0x18 != 0` — and `Vehicle_UpdateThrustFx @ 0x4f9700` sets `TankVehicle+0x18` from
  **tuning slot5** (`base+0xB8`, thrust-intensity). It reads 0 → gate fails → `ApplyThrustForces` skipped.
- `Vehicle_ApplyThrustForces @ 0x4f9b10`: `forward_force = model+0x58 * move_adjust(model+0x18, loaded
  ✓) * fwd_scalar(model+0x70)`. It uses **model+0x58/+0x5c** (thrust magnitudes, source still
  unknown — NOT set by the load, ComputeControlScalars, or UpdateThrustFx) + the loaded config doubles
  + input scalars. It does **NOT** read the old "slots 6/7" (+0x68/+0x6c) — that framing was a red
  herring.
- ROOT BLOCKER: the **per-vehicle tuning SLOT TABLE** at `*(*(0x67cd58))` (and `*(*(physObj+8))`) is
  entirely zero — it is the LOCAL-PLAYER's table, never populated for a non-local server entity.
  Driving authentically needs each server tank to own a populated slot table (the "full authentic
  controller" path). Input path itself WORKS: write `input*divisor` (divisor = **int 50** at
  `TankVehicle+0xc`, not a float) to slot2 scaled-read `base+0x50` → `ComputeControlScalars` sets
  `model+0x70` (forward scalar) = 1.0 (live-confirmed).
- **Next:** populate a per-tank slot table (and find the model+0x58/+0x5c source) so thrust applies →
  confirm motion → then route `0x0A`/`0x09` ACTION inputs per-session → per-player. See
  `memory/m6-tank-physics-drive-recipe`.

### ✅ M6.2-min(b) — a non-local server tank DRIVES under the engine's own thrust physics (2026-06-17)
**Milestone: a server-spawned (non-local) tank now physically MOVES under wulfram2.exe's own
authentic vehicle physics — no reimplemented sim.** Live-verified end-to-end: the world-host test
tank drove **x 2437→17212** across the map at **vel.x ≈ 81.6** (near the 85 cap), force-driven by
the engine's thrust step; `ReadEngineWorld` relayed the moving position. RE'd via a 5-finder Ghidra
workflow, validated live over the dev console, codified, and re-verified on a fresh injected session.
Plan + full RE archive: `docs/superpowers/plans/2026-06-17-m6.2-min-b-drive-non-local-tank.md`.
- **TRUE root cause (corrects the earlier "two zero fields" framing — those were downstream
  symptoms of ONE cause):** the engine dispatches the per-frame thrust step
  (`Vehicle_UpdateThrustSimulation @0x4f9e20`, **Tank_Model vtable[0]** @`0x5430e8`) for EXACTLY ONE
  object — the singleton local-player client `DAT_006782b0` — inside `Interp_StepSimulationSubsteps
  @0x469e00`. A non-local spawn is never dispatched, so its forces are never produced. Decisive new
  find: the entity's **physics handler at `entity+0xc0`** selects the integration mode in
  `EntityPhysics_IntegrateLinear @0x4f27a0`: a fresh `Obj_InitFromSpawn` entity gets the **KINEMATIC**
  handler `0x5b861c` (byte+4≠0 → `pos += vel*dt`, **force at entity+0x24 IGNORED**), while the local
  player gets the **force-driven damped** handler `DAT_005b8634` (byte+3≠0,byte+4=0 → `accel = force −
  vel·damping`). **That handler is the real missing init.**
- **Recipe (codified in `world_host_engine.cpp` `DriveServerTank()`):** spawn `unit_type=0` (tank);
  build the controller (`Tank_Construct`+`VehicleInstance_InitForEntity`, model resolved by
  `VehicleModel_FindById(0)`); **once:** set `entity+0xc0 = DAT_005b8634` (force-driven); **each tick:**
  write control slots `base+n*0x20+0x10` (n=2 forward, raw=input*divisor 50) + slot-5 gate
  `base+0xB8`(+0x18)=1.0, then `SafeEngineInvoke(Vehicle_UpdateThrustSimulation, ecx=model,
  args=[tankVehicle])`. The engine's global `EntityPhysics_RunWorldTick @0x4f8550` integrates
  `entity+0x24 (force) → +0x18 (vel) → +0x0c (pos)` and ZEROS the accumulator each tick — so the
  step is re-driven every tick. Build = **109/109 CTest**, `lint.ps1` = **PASS**.
- **Corrections to prior memory (multi-finder + disasm + live consensus):** (1) `model+0x58/+0x5c`
  are NOT "thrust magnitudes loaded from config" — they are engine-glow scale factors
  `Vehicle_UpdateEngineGlowScale @0x4f9790` re-inits to 1.0f every frame *inside the step* (don't
  load/poke them). (2) Force lands on the **entity** (`+0x24` linear / `+0x48` torque), not physObj —
  `tools/drive_probe.py`'s `physObj+0x08` velocity read is WRONG (vel is `entity+0x18`). (3) slot
  **+0x10** = control field GetScaledValue divides; **+0x18** = raw/gate cache. (4) vehicle-model
  ids: **0=tank, 1=medic** (the `world_host.hpp` "1 = tank" comment was wrong → fixed to 0);
  `VehicleModel_FindById` returns **shared per-type registry model singletons** (so the model is a
  per-call scratchpad — sequential per-entity driving is safe). (5) "slots 6/7" stays a dead red herring.
- **Known refinement (next, M6.2-min(c)):** altitude-hold while driving — hover works at REST on the
  pad (z held at −180), but driving full-forward sends the tank off the ~5600-unit `bpass` map into
  the void where it descends (`vel.z` negative). The hover/ground-proximity lift in
  `ApplyThrustForces` (reads `*(model+0x50)` jet-reaction surface) needs the surface to track terrain
  as the tank moves. Then: route inbound `0x0A`/`0x09` ACTION packets (NO engine receiver exists —
  the DLL must mirror the `SyncAction`/`Range_LevelToValue` quantizer) → per-player per-entity drive.
  The hardcoded forward input in `DriveServerTank` is a temporary demo pending that input routing.

### ✅ M6.2-min(b+) — multi-tank: the server authoritatively drives SEVERAL independent tanks (2026-06-17)
**Milestone: the headless server now simulates MULTIPLE independent vehicles in real time — a
capability the stock binary never had (it only ever drove the ONE local-player vehicle).**
Live-verified: 3 tanks (oid 9001/9002/9003) each driven with a distinct bounded input move
INDEPENDENTLY (distinct evolving pos + rot), stay near spawn, and none freeze. Build = **109/109
CTest**, `lint.ps1` = **PASS**.
- **No per-entity tables needed for sequential driving (simpler than the original plan's Step 3).**
  `VehicleModel_FindById` returns a SHARED per-type registry model singleton, and the control-slot
  table is a per-call scratchpad — the thrust step reads both synchronously during each call. So
  `DriveServerTanks()` loops the tanks and, per tank, writes ITS input to the shared slots then
  calls `Vehicle_UpdateThrustSimulation(sharedModel, thisTankController)`. Each tank has its own
  entity + own 0x20-byte Tank_Vehicle controller (model/table shared). No aliasing.
- **SLEEP mechanism RE'd + fixed (the crux for robust multi-entity drive).** `EntityPhysics_RunWorldTick
  @0x4f8550` integrates an entity only if `*(char*)(entity+0xae) == 0` (awake) AND
  `*(char*)(entity+0xac) != 0`. A slept entity (`+0xae != 0`) is NEVER integrated, so our applied
  force can't raise its motion above the engine's wake threshold → freeze (a "spin in place" tank
  with ~0 linear velocity slept and froze). The engine keeps the LOCAL player awake via
  `EntityPhysics_WakeIfMotionAboveThreshold(DAT_00677f2c)` each tick, but that only wakes if motion
  is already high. **Fix:** force-clear `entity+0xae = 0` each tick per server-driven tank (perpetual
  wake) — verified the previously-frozen tank now moves continuously.
- **Glue-only change** (`world_host_engine.cpp`): `VehicleDriveState` → `ServerTank[]`; `DoSpawn`
  registers the primary (oid 9001) as tank 0; `SetupServerTanks()` spawns the extras (9002/9003,
  offset from the primary) + builds all controllers; `DriveServerTanks()` drives each per tick
  (force-wake + distinct demo input + thrust step). Readback logs all tanks. No host-tested code
  touched (WorldBootstrap unchanged), so the 109-test suite is stable. Added `WriteU8`.
- **Demo inputs are temporary** (tank 0 fwd+left circle, tanks 1/2 spin opposite ways — distinct +
  bounded so they stay near spawn): they prove independent motion until inbound ACTION input routing
  (`0x0A`/`0x09`) drives each tank from its player. Known refinement unchanged: altitude-hold while
  driving (tanks drift slowly in z; full off-map travel still descends).

### ⏳ M6.4 — ACTION input routing: decode + producer shipped (`6b3e6ba`, `635e4aa`, 2026-06-17)
The real blocker for "see each other *move*": today a PLAYER tank never moves server-side when the
player drives (only the 3 demo tanks do), so via `0x0E` peers see each other frozen. Decoding the
client's control inputs and driving the player's engine tank fixes that. Two increments landed this
session, each gated (build `/W4 /WX`, lint PASS, full CTest):
- **Increment 1 — decoder (`6b3e6ba`).** `server/action_input.{hpp,cpp}`: `DecodeActionUpdate` (`0x0A`)
  + `DecodeActionDump` (`0x09`). Wire format **verified from the binary (Ghidra) AND cross-checked
  against all 826 golden captures**: `0x0A` = `[count:8][timestamp:i32][seq:i32]` then
  count×(`[channel:16][value]`); `0x09` = `[timestamp][seq]` + channels 1..21 positional. Value = 1
  bit (digital: ch 4 or ≥8) or 16-bit analog over [high=1.0, low=-1.0] (axes 0,1,2,3,5,6,7) — the exact
  ramp our `BuildTranslation` sends, which the client encoded against; decode mirrors the engine's
  `Range_LevelToValue`. Fail-closed via `BitReader`. 9 TDD tests (real captures + round-trip + reject).
- **Increment 2 — producer (`635e4aa`).** `Connection::OnUdpPacket` decodes in-game `0x09`/`0x0A` and
  enqueues one validated `ActionInput` command per drivable channel (channel ∈ 0..21, value clamped
  [-1,1]); never trusts the client-asserted entity id; pre-game ignored, malformed dropped. 2 TDD tests.
- **Increment 3a — route to oid (`25028e2`).** `MvpOnlineBridge::HandleActionInput` consumes the
  `ActionInput` command, maps the session to its spawned engine oid (`session.entity.net_id`), and
  calls an `InputHandler` hook `(oid, channel, value)`; pre-spawn input is dropped. Completes the
  wire→decode→validate→route-by-oid pipeline in tested code (no engine poke). 2 TDD tests. A
  no-regression boot-smoke (after tonight's hot-path changes) confirmed the server still boots, ticks
  ~400×, relays, and drives the demo tanks with zero faults.
- **Increment 3b (NEXT — LIVE-ONLY).** Engine glue arms `SetInputHandler` to store input per oid,
  builds a controller per player tank on spawn (reuse the resolved shared model/param2), and drives
  each player tank from its routed input in `DriveServerTanks`. Blocked on a live two-client drive
  test: only observable as a moved entity, and the channel→slot mapping is a known unknown (demo proves
  slot 2=fwd / slot 1=turn for unit_type 0, but the client-channel→slot binding needs live confirm —
  a hypothesis test, not implementable on a guess). Plan + RE-verified apply offsets:
  `docs/superpowers/plans/2026-06-17-m6.4-action-input-routing.md`.

### ✅ M6.3 — in-game UDP `0x0E`/`0x0F` delta relay shipped (`3dc283c`, 2026-06-17)
Closed the relay gap identified just below. Spawned sessions now receive, **per tick over UDP**,
`UPDATE_ARRAY 0x0E` (the OTHER dynamic tanks) + `VIEW_UPDATE 0x0F` (self). `0x0F` leads with an i32
**ms-timestamp** (steady_clock) then the i32 sequence; `0x0E` writes only the sequence; the rest is
identical (stats block + u8 count + entity array). Each entity is sent with the full **DEFINITION** mask
the first time a session sees it (tracked per-session in `SessionState.introduced`), then **`POS|ROT`-only
deltas** so the client interpolates between updates instead of snapping. Pre-spawn sessions are unchanged
(reliable full-world `0x0F` over TCP so team-select / pad-pick still works). UDP framing is bare
`[opcode][bits]` (`BuildUpdateArray`), not the TCP length-prefixed `Frame()`. `WriteEntity` is now
mask-parameterized. Tests rewritten to assert the UDP `0x0E`/`0x0F` behavior.
**Verification:** build `/W4 /WX` clean, lint PASS, **109/109 CTest**, and a server boot-smoke (world
`bpass` loaded, 3 demo tanks driven + moving, relay armed, ~400 ticks, **no errors/faults**).
**Still pending one human check:** two rendering clients confirming smooth interpolation + no
protocol-mismatch (can't be self-verified headless). **Next = M6.4 input routing:** decode inbound client
`ACTION 0x09/0x0A` → drive that session's engine tank, else player tanks stay frozen server-side and peers
see each other stuck at spawn (only the 3 demo tanks move). Captures: `tools/captures/action_packets_2026-06-17.txt`.

### ⟳ M6.2/M6.3 — live two-client test session + the real-time relay gap (2026-06-17)
Ran a real **server + two rendering clients** end-to-end. Findings + fixes (all committed):
- **Spectate crash root-caused + fixed (`7ebeae7`).** On reincarnate the server sent a TankSpawn for
  an MVP-only tank that the engine-sourced relay never included → the client spawned a phantom that
  never appeared in snapshots → "protocol mismatch" crash ~40s later + "no tank". Fix: spawn a REAL
  engine tank per player (`SpawnPlayerTank` via a new `SetSpawnHandler` hook) and use its engine oid
  as the TankSpawn id. Verified: both clients reincarnate into engine tanks (oid 9100/9101), relayed
  (entities 37→39), survive past the crash window.
- **Sync was "really low" → fixed (`cd6150d`).** The relay emitted only on visibility_changed
  (~0.5 Hz). Now emits every tick (~10 Hz). Also spread player spawns (player_id-based x offset) so
  two players don't overlap at the shared pad (camera-on-self hid the peer).
- **CORE GAP (player-confirmed, the next milestone): in-game entity sync needs `UPDATE_ARRAY 0x0E`
  (others) + `0x0F` (self) over UDP per-tick** (per the Wulf-Forge `player_sim_tick` reference). We
  send `0x0F`-for-all over TCP, so clients render entities from the initial snapshot (the demo tanks)
  but never get the `0x0E` "others" stream → can't see in-game players or interpolate. Key format
  diff: `0x0F` leads with an i32 **ms-timestamp** then the sequence; `0x0E` writes only the sequence;
  the rest is identical. Our `BuildViewUpdateSnapshot` is the `0x0F` shape but writes sequence for
  BOTH i32 (should be `[ms-timestamp][sequence]`). **Full executable plan:**
  `docs/superpowers/plans/2026-06-17-m6.3-update-array-udp-relay.md` (decided: implement fresh, not
  rushed). Inbound golden ACTION captures: `tools/captures/action_packets_2026-06-17.txt`.

### ✅ M5.3 — team-select → entry-map → SPAWN works end-to-end; +2 follow-up fixes (2026-06-16)
**Milestone: a real client can now pick a team, open the entry map, choose a repair pad, and spawn.**
The blocker was a missing `UPDATE_STATS (0x1C)` on team switch — decoded from the user's own working
Python capture (`Wulf-Forge/logs/server-test.out.log`): the working server replies to a team-switch
`0x25` with **3 UDP packets** `D_ACK(0x02) → UPDATE_STATS(0x1C) → REINCARNATE(0x25 code 17)`; mine sent
only ack + the code-17 confirm, so the client showed "you changed teams" but the roster list never
updated and the Entry-Map/Respawn selector stayed disabled. Now `Connection::HandleUdpReincarnateRequest`
emits `BuildUdpUpdateStats(pid, team)` on UDP (byte-exact: `1C 00000004 00000006 0002 0021 0003 0005
0009 00010000 00010000 0000000A`). TDD: `BringupPackets.UdpUpdateStats…`, `Connection.InGameUdpTeamSwitch…`.

Two follow-up fixes after the user drove a live spawn (investigated with the Python source AND a Ghidra
client decompile, per the user):
- **Sideways repair pad → fixed.** Root cause: `WriteEntity` (the `VIEW_UPDATE 0x0F` snapshot) wrote
  `DEF|POS|HEALTH` but **never rotation**, so map fixtures arrived with no orientation and rendered at a
  default heading. The reference marks loaded fixtures ROT-dirty and sends rotation. Added `kMaskRotation`
  (bit 3) + `WriteVec3(rot, kRotConfig)` (COMPRESSOR_ROT max 6.3/range 12.6) in mask-bit order
  (POS→ROT→HEALTH). Confirmed against client `Net_HandleTankSpawn @0x46D260` (rot stored at entity
  `+0x30/+0x34/+0x38`). TDD: `ViewUpdateSnapshotIncludesRotationSoFixturesAreNotSideways`.
- **Team switch now broadcast to other clients.** `MvpOnlineBridge::HandleTeamSwitch` broadcasts a
  TCP-framed `UPDATE_STATS (0x1C)` to every OTHER session (the requester already got it on UDP), so peers'
  rosters update. TDD: `MvpOnlineBridge.TeamSwitchBroadcastsUpdateStatsToOtherClients`. 101/101 CTest, lint PASS.

**Open (M6 — real-time movement relay):** moving tank positions are not yet relayed. Reference flow
(confirmed Python + Ghidra): client sends control INPUTS `ACTION_DUMP 0x09` / `ACTION_UPDATE 0x0A`
(`Net_SendActionUpdate @0x46C860`); server simulates @10 Hz and broadcasts `UPDATE_ARRAY 0x0E` to others
(self gets `VIEW_UPDATE 0x0F`), bit-packed with a 4-bit priority header + 13–16-bit quantized pos/vel/rot
and a 10-bit update mask (`Net_ApplyWorldSnapshot @0x47D760`). Per `m5-direct-world-host`, source positions
from the engine world rather than a Python-style sim.

### ✅ M5.2 — UDP reliable-stream handshake + full client-opcode whitelist (2026-06-16)
The crux that blocked team-select/spawn on real clients. **Root cause (live evidence):** the client
spams `0x03` (D_HANDSHAKE, 199-byte "Beacon Stream"/"Squad Things" stream defs, incrementing timestamp)
right after WANT_UPDATES, but the server **never answered** — so the client's gameplay streams stayed
paused and the entry-map/team-select never activated. Two layered causes, both fixed:
- **`0x03`/`0x0B` were silently dropped at the UDP gate.** `IsKnownOpcode` only listed 23 opcodes;
  `TryRouteLinkedUdpFrame` rejects any non-whitelisted opcode (`UDP packet ignored; no matching pending
  session`). Per user request ("have a handler for all opcodes … in the whitelist") the `Opcode` enum +
  `kKnown` now list **every** client-emitted opcode (35): added DebugString 0x00, Ack 0x02, DHandshake
  0x03, ActionDump 0x09, ActionUpdate 0x0A, ClientPing 0x0B, UdpPing 0x0C, ChatComm 0x20, DropRequest
  0x2B, Viewpoint 0x35, BeaconRequest 0x3A, Kudos 0x4F. Unknown opcodes a connection doesn't act on are
  accepted + no-op'd (logged via `LogUdpPacket`), not dropped. TDD: `ProtoValidate.KnownOpcodes` updated.
- **Server now answers the handshake** (matches the Python "Unpause Streams (Critical for the client to
  accept data)" path). `OnUdpPacket(0x03)` → `EmitUdpStreamHandshake`: emits 4 datagrams — `0x02` ack
  (6B) + `0x03` stream defs for 4 streams (128B) + `0x04` unpause stream 1 + unpause stream 3 (4B each).
  `OnUdpPacket(0x0B)` → `0x0C` pong. `StepResult` gained `udp_datagrams`; acceptor `SendStepUdp` flushes
  them (linked **and** pre-link). TDD: 4 `UdpHandshake.*` builder tests. 98/98 CTest, lint PASS.

**Live two-client smoke (this run):** server `:2627`, world `bpass` loaded (`entities=34`); both admin
clients connected (sessions 2,3), logged in, `WANT_UPDATES → InGame`, sent `0x03` **once**, server
logged `UDP stream handshake queued (ack+defs+unpause 1,3) pid=2/3` + the 6/128/4/4 datagrams, and the
client **stopped re-spamming `0x03`** (advanced to steady `0x33` heartbeat + receiving `entities=34`
snapshots). No SEH/crash. **Open:** user-driven team-select (`0x25` mode 1) → repair-pad spawn.

### ✅ M5.1e — entry-map render fix + self-connection re-seam (2026-06-16)
Two evidenced fixes after a live rendering-client smoke + full Ghidra RE of the handshake (see
`memory/m4-tick-seam-render-gated.md`):
- **Entry map now loads on a real client.** Root cause (empirical byte-diff vs the working Python
  server): the accept burst sent HELLO **VERSION (sub 0)** between `UDP_CONFIG` and `SESSION_KEY`.
  VERSION is a client->server packet; echoing it back desynced the client's HELLO parser so it never
  read the session key. Removed it to match Python's `UDP_CONFIG -> SESSION_KEY`. The external
  `-root` client now connects, logs in, and **renders the bpass map** (screenshot-confirmed). TDD:
  `Connection.AcceptBurstIsUdpConfigThenSessionKeyNoVersion`. 81/81 CTest, lint PASS.
- **Server tick re-seamed off the render gate.** `Client_Main`'s loop calls `Client_RenderFrame`
  only when `DAT_005b83f4` (window-active) is set; our hidden window means it is ~never called, so
  the M4 tick (hooked there) died during login/connect. Moved the tick to **`Net_ServiceConnection`
  @ 0x46b830** (called every loop iteration, all states): detour calls the original then runs the
  guarded server tick (MVP bridge + self-connection drive). Tick now survives (300+ ticks vs 1-2).
- **Self-connection now links.** The injected instance connects to its own `:2627`; the UDP key-echo
  (sent by the render-gated login screen, dormant headless) is now driven from the tick via
  `Net_SendHelloName @ 0x46b690` once the engine stores the key (`DAT_00678267==1`). Added handshake-
  aware **batched-UDP splitting** (the engine flushes "Hello There" 0x08 + key-echo 0x13 in one
  datagram). Session 1 reaches `AwaitingUsername`. **Still open:** drive the self-connection's
  LOGIN (0x21 user/pass) to reach in-game so the engine owns the world. Added verbose UDP/TCP hex
  wire logging (DEBUG).

### ✅ M5.4-min(a) — direct world-host: engine loads + ticks its own world headless (2026-06-16)
**Decision (user):** pursue **direct in-process world hosting** ("trick the game into game mode")
over the self-connection-login path — call the engine's own world-entry directly on the tick thread.
See `memory/m5-direct-world-host.md`. Achieved: the headless engine resets its session and loads the
`bpass` world; its main loop then ticks the engine's OWN physics on the loaded world (no reimplemented
sim, no local player/camera).
- **TDD (host-tested):** `WorldBootstrap` — a pure sequencing state machine (Idle → Reset → Load →
  Spawn → Complete, one engine action per tick), mirroring the `Connection` "pure brain" pattern;
  + a `world_host` config flag (`[server]`, default OFF). 11 new gtests (sequence/idempotence/parse).
  Build = **91/91 CTest**, `lint.ps1` = **PASS**.
- **Engine glue (DLL, SEH-guarded tick):** `ProcessWorldHostTick` runs `Game_ResetSession(0)` →
  `Client_SetCurrentWorld(bpass)` after a settle delay. **SpawnEntity is a logged placeholder** —
  deferred to M5.4-min(b) (needs verified asm register-handoff wrappers).
- **"Game mode" = world loaded (evidence-based):** the engine's own `Net_HandleWorldStats @ 0x46cf50`
  does exactly `Game_ResetSession(0)` + `Client_SetCurrentWorld(...)` with **no** screen-mode flip;
  physics ticks in `Interp_UpdateAllEntities` the moment `DAT_006785e4 != 0`. So the separate
  `Screen_SwitchMode(3)` step was dropped — the screen-mode enum is the local rendering client's
  camera/HUD, which a headless server has no use for.
- **Root-caused a hang (systematic debugging + cdb):** a first smoke froze the engine thread inside
  `Client_SetCurrentWorld`. `cdb -p <pid> -c "~*kn"` showed the stuck stack was in **our DLL**:
  `_RTC_CheckEsp → _CrtDbgReportW → MessageBoxW` — an `/RTC1` ESP-mismatch modal dialog. Cause:
  `Client_SetCurrentWorld` is **NOT `__fastcall`** (Ghidra mislabels it). True convention, verified
  from its own call site: **ECX=worldFlag, EDX=map, stack=[worldType, seed], caller-cleans 8**
  (plain `RET`). A `__fastcall` cast left an 8-byte ESP imbalance → RTC dialog → deadlock. Fixed with
  a `__declspec(naked)` asm thunk (`src/dll/server/engine_thunks.cpp`); that one x86-asm file is
  excluded from clang-tidy (the host x64 triple rejects `naked`); cppcheck still covers it.
  See `memory/client-setcurrentworld-abi.md`.
- **Smoke (injected, controller-run, cleaned up):** world-host bootstrap completes
  (`Game_ResetSession` → `Client_SetCurrentWorld` → **world loaded** → bootstrap complete); process
  stable, loop ticks `t63 → 346+`, no crash/fault. **Verified live via cdb:** `DAT_006785e4` =
  `0x0945a3d0` (world map **non-null** → loaded) and `DAT_00677f34` (OidTable) non-null (ready for
  spawns). Repo `config/headless.toml` stays `world_host` OFF; smoke used the build copy.
### ✅ M5.4-min(b) — spawn one authoritative entity into the loaded world (2026-06-16)
The world-host now spawns a real engine entity after the load, completing the
`Reset → Load → Spawn` sequence. The `WorldBootstrap` SpawnEntity step is wired to engine
glue; **verified live** that the engine's own object lands in its world list + spatial index.
- **Asm register-handoff thunks** (`engine_thunks.cpp`, all verified from disassembly — every one
  is plain-`RET`/caller-clean, none is standard `__thiscall`/`__fastcall`):
  - `EngineObjCreate` → `Obj_Create @ 0x419a70`: **ECX=creator, EBX=oid**, 6 caller-cleaned stack
    args (is_local, type, owner, team, deco5, deco6), returns entity in **EAX**.
  - `EngineObjInitFromSpawn` → `Obj_InitFromSpawn @ 0x419880`: **entity in EAX**, 6 caller-cleaned
    stack args (pos x,y,z + euler). Pushes the entity into `*DAT_006785e4` AND the spatial index.
- **LoseOid gate (root-caused via cdb):** first spawn returned null. `Obj_Create` calls
  `LoseOid_IsHidden`, which requires `creator > DAT_0067cd0c` (the lose-OID threshold; read **0** on a
  fresh world). We passed `creator=0` → `0 < 0` false → null. Fix: pass a positive creator (the oid).
- **No local-camera grab:** `Obj_InitFromSpawn` only enters-world if entity OID == `DAT_005b83e0`
  (left −1 by `Game_ResetSession`); our oid=1 ≠ −1, so it stays a non-local object. Confirmed.
- **Smoke (injected, cleaned up):** full sequence completes (reset → load → Obj_Create →
  Obj_InitFromSpawn → spawned); process stable, loop ticks to **2874+**, no crash/fault. **Verified
  live via cdb:** world-list **count = 1** (head==tail, single node); the node's entity has
  **unit_type=1 (tank), OID=1, pos=(2437,3269,−180)** exactly as spawned, **vel=(0,0,0)** (at rest on
  the team-1 pad terrain — physically correct). WorldMap dims read back 5600.0 (real bpass).
  Build = **91/91 CTest**, `lint.ps1` = **PASS**.
- **Next:** read the engine entity structs back per tick (the engine is now the source of truth) and
  wire the **M6.1 authoritative relay** (snapshot `DAT_006785e4` → clients), then **M5.2** per-entity
  control injection so client inputs drive their server-side tank. Also: default `world_host` on once
  the relay path is in (repo config stays off for now).

### ✅ M6.1-min(a) — read the engine's authoritative world by value (2026-06-16)
The engine is now the source of truth, and we can read its live world state on the tick thread —
the foundation for the replication relay.
- **TDD (host-tested):** `ExtractEntitySnapshot(const uint8_t* entity) -> MvpEntitySnapshot` reads the
  M5.0 contract offsets (oid@+0xb4, type@+0x8, pos@+0xc, vel@+0x18, rot@+0x30, health@+0xd0,
  energy@+0xd4, team@+0xf0) via alignment-safe memcpy. Offsets are named `static constexpr` members
  (`EntitySnapshotOffsets`) shared with the test. 2 new gtests (synthetic buffer, incl. negatives).
- **Engine glue:** `ReadEngineWorld()` walks `DAT_006785e4` → `[WorldMap+0]` Util_List
  (count@+0, head@+4) → nodes (entity@+8, next@+0), capped at 4096, calling `ExtractEntitySnapshot`
  per entity → `vector<MvpEntitySnapshot>` by value. Engine-thread-only; runs inside the SEH-guarded
  tick. A throttled readback log proves it each second.
- **Smoke (injected, cleaned up):** with the spawned tank present, the tick logs
  `engine world readback: 1 entity → entity[0] oid=1 type=1 team=1 pos=2437.0,3269.0,-180.0` — real
  engine data read by value, matching the cdb-verified struct, no fault. Build = **93/93 CTest**,
  `lint.ps1` = **PASS** (cppcheck/clang-tidy analyze with 64-bit models, so `DerefU32` returns
  `uint32` to dodge a spurious truncation finding; the asm-only `engine_thunks.cpp` stays clang-tidy
  excluded).
### ✅ M6.1-min(b) — authoritative relay wired: clients receive the engine world (2026-06-16)
The replication path now sources its `VIEW_UPDATE` entities from the live engine world instead of MVP
placeholder data, so a connecting client sees the server's real objects.
- **TDD (host-tested):** `MvpOnlineBridge::SetWorldProvider(std::function<vector<MvpEntitySnapshot>()>)`
  — when set, `EntitySnapshots()` returns the provider's result, REPLACING the placeholder pads/session
  tanks in every `VIEW_UPDATE`. New gtest `WorldProviderOverridesSnapshotWithEngineEntities`: a session
  joins + WANT_UPDATES, and the emitted snapshot carries exactly the provider's one engine tank
  (oid/type/team), not the fallback pads.
- **Glue wiring:** exposed the bridge as a process singleton (`ProcessMvpBridge()`); when the world-host
  bootstrap completes, the tick arms the provider with `[]{ return ReadEngineWorld(); }` (runs on the
  tick thread during emission). The existing `BuildViewUpdateSnapshot` encoder + per-session fanout are
  reused unchanged.
- **Smoke (injected, cleaned up):** logs `world-host bootstrap complete` →
  `authoritative relay armed: clients now receive the engine world`, and the readback shows the real
  tank (`oid=1 type=1 pos=2437,3269,-180`); no fault. Build = **94/94 CTest**, `lint.ps1` = **PASS**.
  (Socket tests can transiently flake under ctest right after a smoke — TIME_WAIT on the ephemeral
  binds; they pass once the OS settles / in a single-process run.)
- **End-to-end note:** the bridge logic (provider → VIEW_UPDATE) is host-proven and the live provider
  returns the real entity, so a connecting client receives the engine world by composition. The final
  confirmation — an external rendering client visibly seeing the server's tank — is a controller smoke
  (as with the M5.1e entry-map render check).
- **Next:** per-tick relay cadence + per-client create/update/destroy diffing (currently emits on
  join); then **M5.2** per-entity control injection so client inputs drive their server-side tank;
  health/energy level↔absolute normalization (M5.0 trap #5); default `world_host` on.

## Milestone 3 (Approach A, head-chop — superseded, kept for the boot-path map it produced)
Plan: `docs/superpowers/plans/2026-06-16-headless-wulfram-server-m3-head-chop.md`.
- [x] **M3.1** — generator captures real hook-site bytes (RVA→file-offset); `binary_manifest.h` has 13 sites
      with real `wulfram2.exe` bytes; self-check now validates them. Commit `ab2c7b2`. 15/15 ctest, pytest 2/2.
- [x] **M3.2** — MinHook wrapper (`engine_hooks`) + loader↔InitThread ready handshake (pid-keyed named
      event; loader waits 10s + tears down before `ResumeThread`). Commit `89abbe3`. 16/16 ctest.
- [x] **M3.3** — 11 head-seam no-op detours, ABI-correct (incl. `__thiscall`→`__fastcall`+dummy-EDX and
      `__fastcall` Snd), **verified via dumpbin disasm** (`ret 4`/bare `ret`/register reads). Commit `c85dfcd`.
- [x] **M3.4** — render-driver defense: detour `Render_SwitchActiveDriver` to install a non-null no-op
      driver object into `DAT_00677e54` (no-op vtable/thunks) + return 1. Commit `390677b`. Correct per RE,
      but not yet exercised at runtime (blocked upstream — see M3.5). Temp loop-seam observation detour: `ae4df20`.
- [⚠] **M3.5** — headless-boot smoke: head-chop machinery VERIFIED working (all 11 stubs install, handshake
      completes, game resumes, `Winsys_InitGlideRenderer` stubbed cleanly) — but boot is **BLOCKED before the
      loop seam by an environmental registry-permission wall**: the game requires write access to
      `HKCU\Software\Wulfram` / `HKEY_USERS\.DEFAULT` on first run (`Cfg_RegOpenOrCreateSubkey @ 0x47e0e2` via
      `WebLaunch_SetWorkingDirectory @ 0x4a4db0`, early in `Client_Main`, before the render path). No AV.
      Notes: `docs/superpowers/notes/2026-06-16-m3-headless-boot.md`. Commit `91b30e8`.
      **DECISION NEEDED** to unblock: (a) stub/bypass the registry-config call in our DLL [recommended — a headless
      server doesn't need the client registry], (b) pre-seed the registry keys, or (c) one-time elevated run.
      Also flagged: Windows Defender quarantined `loader.exe` once (DLL-injection heuristic); a project-folder
      exclusion resolved it.
- Deferred to follow-on plans: **M3** head chop, **M4** loop hijack + fixed timestep + SEH,
  **M5** Net object + sessions, **M6** physics drive, **M7** multi-client + game rules.

## Process
Subagent-driven: fresh implementer per task + two-stage review (spec compliance, then code quality).
Codex reviewed the design spec (2026-06-15); findings folded in (DllMain loader-lock fix, binary
pinning, engine contract table, fixed-timestep, token sessions).

## Toolchain (verified)
VS 2022 x86 (`vcvars32.bat`) ✓, VS-bundled cmake 3.31.6 ✓, ninja ✓, python 3.12 ✓, git ✓.
Installing: LLVM/clang-tidy (x64), cppcheck.

## Log
- 2026-06-15 — Published to GitHub as private `cyberbalsa/wulfram2-server`. Rewrote all commit
  history to the GitHub noreply identity (removed a stray `fffics@rit.edu`). Consolidated work onto
  `master`. Installed LLVM/clang-tidy 22.1.7 (`C:\Program Files\LLVM`) and cppcheck 2.21.0.
- 2026-06-15 — Task 0, Task 1 + hardening complete. Rust evaluated/rejected. GoogleTest + clang-tidy
  + cppcheck adopted per user direction. PROGRESS.md started.
