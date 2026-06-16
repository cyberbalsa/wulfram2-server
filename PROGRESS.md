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
