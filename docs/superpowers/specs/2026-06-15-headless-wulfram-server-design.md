# Wulfram II Headless Server — Design

**Date:** 2026-06-15
**Status:** Design (Codex review 2026-06-15 incorporated; pending final user review)
**Location:** `C:\Users\balsa\desktop\WulframII\Wulf_Forge_Headless\`

## Summary

Turn the original `wulfram2.exe` client into a dedicated, authoritative game server by
**reusing its own compiled physics, entity, and protocol code** — instead of re-porting that
logic into Python (the current `Wulf-Forge` approach in `wulfsim/`).

We inject a C++ DLL into a `wulfram2.exe` process, let the client initialize normally with its
rendering/audio/input "head" neutralized, then replace its main loop with a server loop that
drives **all** connected players' entities through the binary's authentic physics functions and
broadcasts state using the binary's own packet serialization.

The existing Python `Wulf-Forge` server is **retired** as a runtime component. Its packet maps
(`packets.toml`), physics findings (`docs/server-settings-and-tank-physics.md`), and the Ghidra
exports (`reverseengineering/`) remain the **specification and reference** for this work.

## Goals

- Authoritative physics that is **bit-identical to the real client** by construction (it *is* the
  client's code), eliminating drift between client prediction and server simulation.
- A single headless process that handles networking, roster, game rules, and physics for N clients.
- A reproducible 32-bit Windows build using the toolchain already proven in `wulfram-lua/`.

## Non-Goals

- No rendering, audio, or input ever runs server-side (the "head" is chopped).
- No COM/DirectX surface emulation (the per-frame render path is never executed).
- Not a continuation of the Python `wulfsim/` bit-exact port (superseded by binary reuse).
- Cross-platform server (must run on Windows x86 to host the x86 PE).

## Key Facts (from Ghidra, project W2VULK)

- `wulfram2.exe`: x86 32-bit PE, **image base `0x00400000`**, pre-ASLR era → internal function
  addresses are **load-stable**, so direct function-pointer calls to hardcoded addresses are valid.
- **96% reverse-engineered**: 6,228 of 6,506 functions named, `Subsystem_Verb` convention.
- Main loop seam: `App_RunGameAndExit @ 0x004a0b70` → `Client_RunMainLoop()` → `App_ExitGracefully()`.
- **Head** (to neutralize): DirectDraw (`DirectDrawCreateEx/Create`), Glide (`glide2x.dll`,
  `win32_glide.dll`), FMOD (`FSOUND_*` in `fmod.dll`), DirectInput (`DirectInputCreateA`), Win32
  window + message pump (`CreateWindowExA`, `PeekMessageA`), GDI.
- **Body** (to reuse): physics (`Vehicle_ApplyThrustForces`, `EntityPhysics_IntegrateStep`,
  `VehicleTuning_ComputeControlScalars`), entity/spawn logic, and **raw Winsock** networking
  (`socket/bind/sendto/recvfrom/recv/send`, `select`) wrapped by the client's `Net_*` functions.

## De-Risking Findings (Ghidra scout, 2026-06-15)

The pre-spec scout resolved the three open risks favorably:

1. **Loop hijack is trivial.** `Client_RunMainLoop @ 0x004a0aa0` is a flat
   `while (quitFlag == 0) { service active state; Tex_UpdateStreamingFrame; Input_PollDeviceState;
   Input_ProcessEventQueue; sound; Anim_TickAllObjects; Client_RenderFrame(); }` loop. We replace it
   wholesale. (Note: the physics tick is driven inside the *active-state* vtable update, not inline
   here — the server loop calls the sim/physics functions directly instead.)

2. **The server-role networking is already compiled into the binary** and callable:
   - `Net_InitAccept @ 0x00507ff0` → `Net_InitMultiUdpIpAccept @ 0x00507ee0` → `Net_InitAcceptSocket @ 0x00507810`.
   - `Net_InitMultiUdpIpAccept` does `socket(AF_INET, SOCK_DGRAM)` + `bind` + non-blocking +
     `FD_SET` per configured IP (log: `(Net::init_multi_udp_ip_accept)`); falls back to a single
     accept socket. `Net_InitAcceptSocket` creates+binds a (TCP) listen socket.
   - Currently these are only wired to `DbgNet_Init` (debug-net), **not** the game path — so we
     reuse the primitives, supplying our own roster/accept orchestration.
   - Reusable Net support: `Net_SetSocketNonBlocking`, `Net_FdSetAdd`, `Net_GetWsaErrorString`,
     `Net_InitConnection`, `Net_InitConnectionManager`, `Net_InitSocketContext`, plus the `Net_*`
     packet (de)serializers.
   - This downgrades the original "is `Net_*` separable for server role?" risk to "reuse the
     binary's own bind/listen/accept."

3. **No turnkey dedicated-server mode exists.** `-server <host>` / `-betaserver` are **client**
   connect args (`ClientBoot_ParseServerArgs @ 0x0043ef0b`, `Cmd_ResolveStartupArgs @ 0x004185cb`);
   default host `localhost`, default port `0xa43` = **2627** (same port Wulf-Forge used). So the
   server **orchestration loop is genuinely new C++** — but every primitive it needs (sockets,
   serialization, spawn, physics) already exists in the binary.

### Head-stub init seams (confirmed, named & isolated)

These `*_Init` functions are the chop points — detour each to a no-op that returns success:

| Function | Address | Subsystem |
|---|---|---|
| `Render_InitDriverAndViewports` | `0x00485b20` | render driver/viewports (top-level) |
| `Winsys_D3D_Init` | `0x004a8880` | Direct3D |
| `Winsys_D3D_InitDevice` | `0x004a8280` | Direct3D device |
| `Winsys_DX_Init` | `0x004b3190` | DirectX umbrella |
| `Winsys_GDI_Init` | `0x004b5270` | GDI |
| `Winsys_InitGlideRenderer` | `0x004b8850` | 3dfx Glide |
| `DirectDraw_InitAndSetCooperativeLevel` | `0x004b23a0` | DirectDraw |
| `DirectInput_InitMouse` | `0x004b15b0` | DirectInput mouse |
| `DirectInput_InitJoystick` | `0x004b1b50` | DirectInput joystick |
| `Winsys_Input_InitWin32State` | `0x004b7b50` | Win32 input |
| `Snd_InitDevice` | `0x00489fb0` | FMOD audio device |
| `Voice_InitSystem` | `0x0048b680` | voice chat |

**Body inits to KEEP (never stub):** `World_InitState @ 0x00417330`, `WorldState_InitGlobal @ 0x004e77d0`,
`CollisionSystem_InitGlobals @ 0x004e6fb0`, `VehicleInfo_InitTables @ 0x004e5b50`,
`VehicleModel_InitAll @ 0x004e95b0`, `Vehicle_InitThrustParams @ 0x004f9a60`,
`EntityInfo_InitGlobalTypes @ 0x004e3bd0`, `SpatialRoot_InitFromMap @ 0x004e8760`, the `Net_Init*`
family above, `Time_InitGlobalTimer @ 0x00503750`.

The exact set and each seam's required success return value are finalized in Milestone 3 by reading
the init call sites (`App_InitInstance @ 0x0046fbd0` and below).

## Architecture

```
loader.exe
  └─ CreateProcess("wulfram2.exe", CREATE_SUSPENDED)
     ├─ inject wulf_headless.dll  (LoadLibrary via remote thread)
     └─ ResumeThread

wulfram2.exe  (single process, in-memory)
  DllMain(wulf_headless.dll):           # MINIMAL — runs under the loader lock
     DisableThreadLibraryCalls; store HMODULE; CreateThread(InitThread); return TRUE
     (NO MinHook, NO LoadLibrary, NO logging backend, NO sync primitives here)
  InitThread (off the loader lock):
     1. Validate target binary (PE timestamp/SizeOfImage/CheckSum + expected bytes
        at every hook site & called address). Mismatch → FATAL log + ExitProcess.
     2. Bring up logging backend.
     3. MinHook init + install detours.
  Client init runs (on the EXE's own main thread), EXCEPT:
     head *_Init seams → hooked → return success WITHOUT touching hardware
        (return a minimal VALID object/global where callers dereference it — never null)
  Client_RunMainLoop → hooked → ServerLoop() runs on the EXE main thread
     (the original single-threaded context; ALL engine calls happen here):
     fixed-timestep accumulator at the native rate (clamped to 1 tick max):
       1. drain UDP datagrams from all listen sockets (non-blocking)
       2. authenticate by session token → map to entity; Net_* deserialize input
          (each engine call wrapped in __try/__except + breadcrumb)
       3. apply spawns/joins via client's own spawn functions (per-client context)
       4. for each entity in the shared world:
            VehicleTuning_ComputeControlScalars
            Vehicle_ApplyThrustForces
            EntityPhysics_IntegrateStep   (+ collision/clamp as the client does)
       5. Net_* serialize world state → sendto() broadcast to all sessions
```

**Threading rule:** every call into engine code happens on the **original EXE main
thread** inside the `Client_RunMainLoop` replacement (the engine is single-threaded).
The logging backend's async flush runs on its own thread and **never touches engine
globals**. Networking I/O is non-blocking and serviced from the same sim thread.

### Components

1. **`loader/` — `loader.exe`**
   Launches `wulfram2.exe` suspended, injects `wulf_headless.dll`, resumes. Reuses the injection
   pattern from `Wulf-Forge/wulfram-lua/` (loader) but as an independent target. Reads a small
   config (exe path, bind port, map, tick rate). Performs a first-pass **binary-version check**
   against an expected manifest before injecting; refuses to inject a non-matching build.

2. **`dll/` — `wulf_headless.dll`**
   - **`DllMain` (minimal)**: `DisableThreadLibraryCalls`, store `HMODULE`, `CreateThread(InitThread)`,
     return `TRUE`. Does **nothing** that touches the loader lock, COM, the CRT beyond trivial, or
     sync primitives. (Codex finding: hooking inside `DllMain` deadlocks under the loader lock.)
   - **`InitThread`**: runs after the loader lock releases. Validates the binary (see Binary Pinning),
     brings up logging, then `MH_Initialize` + installs/enables detours.
   - **Head stubs**: detour bodies for video/audio/input init that return the success the caller
     expects **without touching hardware**, returning a **minimal valid object/global where the
     caller dereferences it — never null** (Codex finding: hidden COM/HWND deref in body-init).
   - **Server loop**: the `Client_RunMainLoop` replacement, on the EXE main thread. Fixed-timestep
     accumulator; owns listen sockets, the **session table**, per-tick sim drive, and broadcast.
   - **Engine bindings**: thin, ABI-correct C++ wrappers over the binary's functions/globals via the
     generated address table. Each `__thiscall`/`__cdecl`/`__stdcall` signature is explicit and
     assembly-verified; every call is wrapped in `__try/__except` with a breadcrumb (see below).

3. **`gen/addresses.h` (+ generator)**
   A header of `typedef`'d function-pointer constants and global-variable offsets, **generated from**
   `Wulf-Forge/reverseengineering/programs/wulfram2.exe/functions.tsv`. A small script (Python, run
   at configure time or committed) keeps the C++ in sync with ongoing Ghidra naming. Single source
   of truth = the RE export.

### Data flow

Client → UDP datagram → `recvfrom` → `Net_*` parse → input applied to that client's entity →
shared-world physics tick (authentic functions) → `Net_*` serialize → `sendto` to all clients.

We reuse the binary's **own server-role socket setup** (`Net_InitMultiUdpIpAccept` /
`Net_InitAcceptSocket` — bind/listen/non-blocking/`FD_SET`, confirmed present) plus its `Net_*`
packet (de)serializers (fixed-point encoding, opcode layout). The server **orchestration** —
accepting connections, the roster, per-tick drive, and broadcast — is new C++ in the loop
replacement, since the binary has no dedicated-server main of its own.

## Build System

- **CMake + MSVC, 32-bit (Win32) only** — matches `wulfram2.exe` and reuses the toolchain already
  working in `wulfram-lua/`.
- **MinHook** vendored via `FetchContent` (fallback: vcpkg `x86-windows` triplet).
- New self-contained CMake project rooted at `Wulf_Forge_Headless/`:

```
Wulf_Forge_Headless/
  CMakeLists.txt          # top-level, enforces 32-bit, fetches MinHook, /W4 /WX, clang-tidy
  CMakePresets.json       # debug/release presets, sanitizer + lint toggles
  .clang-tidy             # lint ruleset
  loader/                 # loader.exe target (+ binary-version pre-check)
  dll/
    dllmain.cpp           # minimal stub → InitThread
    init/                 # InitThread: binary pinning, logging bringup, MinHook install
    log/                  # logging subsystem (levels, ring buffer, file + DebugView sink)
    hooks/                # MinHook detours (head *_Init seams + Client_RunMainLoop)
    net/                  # listen sockets (reused Net_*), session table, protocol schema
    sim/                  # fixed-timestep loop + per-tick physics drive
    engine/               # ABI-correct bindings, SEH/breadcrumb shims, contracts.md
  gen/
    addresses.h           # generated (function ptrs + global offsets)
    binary_manifest.h     # generated (PE stamps + .text hash + hook-site bytes)
    gen_addresses.py      # functions.tsv → addresses.h + manifest
  config/                 # bind port, map, tick rate, exe path, log level
  logs/                   # runtime log output
  docs/superpowers/specs/ # this document
```

## Hooking & Injection Toolchain (decisions)

- **MinHook** for the ~3–6 inline detours (head `*_Init` seams + `Client_RunMainLoop`). Tiny, MIT,
  x86-native, trivially vendored. (Detours would also work — now fully MIT/free, not x86-limited —
  but is heavier than needed; PolyHook2 is overkill.)
- **Direct function pointers** at fixed addresses for physics/spawn/`Net_*` calls — no hooking lib
  needed because the image base is stable.
- **Suspended-inject** loader so the DLL is resident before any client init runs (deterministic).
- **Hooks are installed from `InitThread`, never `DllMain`** (loader-lock deadlock avoidance).

## Binary Pinning (mandatory, before any hook)

Hardcoded addresses are only valid for one exact image. The loader and `InitThread` both validate:

- **Manifest**: expected PE `TimeDateStamp`, `SizeOfImage`, `CheckSum`, and a SHA-256 of the `.text`
  section, captured once for the known-good `wulfram2.exe`.
- **Hook-site bytes**: the first 8–16 bytes at every hooked address and every called address must
  match expected signature bytes recorded alongside `addresses.h`.
- On any mismatch → `FATAL` log via `OutputDebugStringA` + `ExitProcess`; never run with stale
  pointers. Versioned headers (`addresses_v1.h`, …) support multiple known builds.

## Engine Interaction Contract

Calling the binary's functions outside their original client-loop context is the central risk. We
treat every reused function as a foreign API with an explicit contract:

- **Contract table** (`engine/contracts.md` + asserts): for each reused function — required
  pre-initialized globals/subsystems, the thread it must run on, what it allocates and **who frees
  it**, reentrancy, and exceptions it may raise. Built incrementally as functions are adopted.
- **Single sim thread**: all engine calls happen on the EXE main thread inside the loop replacement.
  No engine call from any other thread (logging/net flush threads stay out of engine memory).
- **ABI-correct wrappers**: explicit `__thiscall`/`__cdecl`/`__stdcall` typedefs; `this` in `ECX`
  for `__thiscall`; debug builds assembly-inspect each wrapper and `static_assert` the signature.
- **SEH boundary**: every engine call goes through a `__try/__except(EXCEPTION_EXECUTE_HANDLER)`
  shim that, on fault, logs exception code/address + the breadcrumb (last opcode/entity/function),
  writes a minidump, and **terminates** rather than continuing with corrupted state.
- **Breadcrumb**: a thread-local record of the last engine function entered, active entity id, and
  last packet opcode, updated at each call site (cheap; powers crash diagnostics).
- **"Current player" singleton audit** (before multi-client): enumerate engine globals matching
  `local|player|self|cam|current`; for each, decide redirect-per-entity vs. per-client context
  frame. Regression test: two simultaneous spawns, neither corrupts the other.
- **Message pump**: if any kept body-init or tick path needs an `HWND`/`GetMessage` (e.g. DirectInput
  acquisition, timers), create a hidden `WS_EX_TOOLWINDOW` window with a `GetMessage`/`Dispatch` loop
  on a dedicated thread before body-init — provides a window without rendering.
- **Anti-tamper audit**: check `wulfram2.exe` for `IsDebuggerPresent`/timing/code-integrity self-checks
  that injection might trip; neutralize or avoid as needed.

## Networking & Sessions

- **Server-role sockets** stood up via the binary's own `Net_InitMultiUdpIpAccept` /
  `Net_InitAcceptSocket` (after the `Net` connection object is fully laid out — see below).
- **Net connection object layout** must be **fully reversed before Milestone 5**: size, allocator,
  socket handle, buffer pointers, cursor offsets (`+0x18/+0x24/+0x30…`), session state. A construction
  helper initializes every field as the engine would; a round-trip packet-corpus test must pass
  before any live client traffic.
- **Session table** keyed by a **server-assigned token** issued in the join handshake — **not** the
  UDP source address (spoofable). Maps token → entity handle, last-seen, input sequence number,
  disconnect timeout. Packets without a valid token are rejected. This is both correctness (entity
  ownership) and baseline security. Deserialization treats all UDP input as untrusted (bounds-checked,
  fuzzed against the corpus).
- **Protocol schema**: a machine-readable schema (opcode, direction, fields, types, endianness,
  var-length encoding, sequence/ack) is produced from `packets.toml` + `Net_*` decompiles **before
  Milestone 5**; prerequisite for the client-join test and deserializer fuzzing.

## Timing

- **Fixed-timestep accumulator** at the client's native rate (e.g. 20–30 Hz). Delta into
  `EntityPhysics_IntegrateStep` is **clamped to one tick**; physics is never driven by socket-receive
  timing. If the engine reads its own `Time_*` globals internally, measure drift and re-anchor.

## Logging & Diagnostics (first-class requirement)

Verbose, structured logging is a primary requirement — we are driving a black-box binary, so
observability is how we debug it.

- **Dedicated logging subsystem** (`dll/log/`) with severity levels (`TRACE/DEBUG/INFO/WARN/ERROR/FATAL`),
  compile-time minimum level, and runtime level via `config/`. Default build = `DEBUG`, very verbose.
- **Sinks:** timestamped rotating file in `logs/`, plus `OutputDebugStringA` (viewable in DebugView)
  and a console when attached. Thread-safe; never blocks the tick loop (ring buffer / async flush).
- **What gets logged:**
  - Loader: process create, injection, resume, every step with the win32 error on failure.
  - Hook install: each detour address, original bytes, trampoline result, enable/disable.
  - Head stubs: every stubbed `*_Init` call, args, and the success value returned.
  - Boot trace: each kept body-init reached (so we can see exactly how far init got before any crash).
  - Net: bind/listen address+port, every accept/join/leave, per-tick packet counts, malformed
    packets (hex dump under `TRACE`).
  - Sim: per-entity inputs and resulting transform deltas (rate-limited / sampled at `TRACE`).
- **Macro form:** `LOG_DEBUG("net", "client %d joined from %s:%d", id, ip, port)` with category tags;
  zero-cost when below the active level. `__FILE__:__LINE__` and tick number on every line.
- **Crash diagnostics:** install an unhandled-exception filter that writes a minidump (reuse
  `dbghelp.dll` / `MiniDumpWriteDump`, already imported) plus the last N log lines and the
  last opcode/entity/function touched.

## Build Quality: Warnings & Linting (first-class requirement)

- **Warnings as errors:** MSVC `/W4 /WX` on our code (the generated `addresses.h` and any vendored
  third-party headers are excluded via `system` include / pragma push so MinHook's warnings don't
  fail our build).
- **Static analysis:** `clang-tidy` (`.clang-tidy` ruleset, run via CMake `CXX_CLANG_TIDY` and in
  CI) plus optional `cppcheck`. MSVC `/analyze` available as a secondary pass.
- **Sanitizers (debug preset):** AddressSanitizer where the 32-bit MSVC toolchain supports it;
  `/RTC1` runtime checks and `/sdl` otherwise.
- **Formatting:** `.clang-format` enforced.
- **Tooling install:** the implementation phase will install whatever the toolchain needs
  (MSVC Build Tools / clang-tidy / cppcheck / CMake / MinHook via FetchContent). User has
  pre-authorized installs.

## Error Handling

- Hook install failures (MinHook init/enable) → abort startup with a clear `FATAL` log; never run a
  partially-hooked process.
- Address mismatch (function not found in `functions.tsv` / unexpected bytes at address) → fail
  fast at generation time, not at runtime.
- Per-client socket errors → log `WARN`, drop that client, keep the world running.
- Crash-in-engine-call → caught by the per-call `__try/__except` shim → minidump + last-N-log-lines
  + breadcrumb (last opcode/entity/function) → **terminate** (never continue corrupted).
- Binary-version mismatch (manifest or hook-site bytes) → `FATAL` + `ExitProcess` before any hook.

## Testing Strategy

- **Address table**: generation unit-tested against a known slice of `functions.tsv`.
- **Binary pinning**: manifest + hook-site byte checks unit-tested; a deliberately-wrong byte must
  trip `FATAL`/exit.
- **Boot smoke test**: inject, confirm init completes with head stubbed and **no access violation
  anywhere in the body-init chain** (boot trace proves it), no window/GPU/audio, and
  `Client_RunMainLoop` is reached and replaced.
- **Net object round-trip**: packet corpus encode/decode through the engine's `Net_*` matches
  expected bytes before any live traffic; deserializer fuzzed against malformed input.
- **Single-client loopback**: a real `wulfram2.exe` client (rendering on) connects to the headless
  server on localhost; verify token handshake, join, movement, and state broadcast.
- **Two-client corruption test**: two simultaneous spawns; assert neither entity's state corrupts
  the other (validates the singleton audit).
- **Physics parity**: drive identical inputs through the headless server and through the existing
  `phys_sim`/`wulfsim` reference; transforms must match (this is the core correctness claim).
- **Multi-client**: 2+ clients, verify independent authoritative movement and no cross-talk.

## Milestones

0. Toolchain + logging foundation: CMake skeleton, `/W4 /WX` + clang-tidy wired, logging subsystem
   functional (file + DebugView sinks, async flush off-thread), MinHook fetched.
1. Loader + injection + **binary pinning**: `CREATE_SUSPENDED` → version-check → inject DLL →
   resume. `DllMain` is the minimal stub; `InitThread` validates manifest + hook-site bytes (a wrong
   byte must abort), brings up logging, then `MH_Initialize`. Step-by-step logging.
2. `gen_addresses.py` + `addresses.h` (+ expected hook-site bytes) from `functions.tsv`; ABI-correct
   binding typedefs compile; address/byte self-check logs.
3. Head chop: detour the confirmed `*_Init` seams to logged no-ops returning **minimal valid
   objects**; add hidden message-pump if any init needs an `HWND`; boot trace proves the full
   body-init chain runs with **no access violation** and reaches the main-loop seam, no window/GPU/audio.
4. Loop hijack: replace `Client_RunMainLoop`; **fixed-timestep** empty server tick at native rate;
   `__try/__except` + breadcrumb shim live around a sample engine call.
5. Net object layout fully reversed + protocol schema documented; stand up listen sockets via reused
   `Net_InitMultiUdpIpAccept`/`Net_InitAcceptSocket`; `Net_*` round-trip corpus passes; **token
   session table**; one real client completes the join handshake.
6. Physics drive: spawn + per-entity authentic physics on the sim thread; single-client movement is
   authoritative; physics-parity test vs `wulfsim` passes.
7. **Singleton audit** + multi-client (two-client corruption test) + game rules (roster, cargo)
   ported from `Wulf-Forge` semantics.

## Risks & Open Questions

Codex review (2026-06-15) reclassified the dominant risk from "address stability" to **behavioral**:
hidden dependencies, global state, ownership, threading, and protocol semantics. Mitigations are now
baked into the Engine Interaction Contract, Binary Pinning, Networking & Sessions, and Timing sections.

**Now mitigated by design (verify in the cited milestone):**

- **`DllMain` loader-lock deadlock** → `DllMain` is a minimal stub; all hooking/logging/sync moved to
  `InitThread`. *(Milestone 1)*
- **Stale hardcoded addresses** → mandatory binary pinning (manifest + hook-site bytes) before any
  hook; versioned headers. *(Milestone 1)*
- **Engine functions out of context / reentrancy / threading** → single sim thread on the EXE main
  thread; contract table; no engine access from other threads. *(Milestones 4–6)*
- **`__thiscall`/ABI errors** → explicit assembly-verified wrappers + `static_assert`. *(Milestone 2)*
- **Hidden COM/HWND deref in "safe" body-init** → stubs return minimal valid objects (never null);
  optional hidden message pump; boot trace must show zero AVs. *(Milestone 3)*
- **In-engine SEH faults** → per-call `__try/__except` + breadcrumb + minidump + terminate. *(M4)*
- **Socket-paced physics instability** → fixed-timestep accumulator, clamped delta. *(Milestone 4)*
- **Net connection object layout** → fully reversed + construction helper + round-trip corpus before
  live traffic. *(Milestone 5)*
- **UDP spoofing / entity ownership** → token-based session table, not source address. *(Milestone 5)*
- **Single-player singleton collisions** → "current player" global audit + two-client corruption
  test before multi-client. *(Milestone 7)*

**Still genuinely open:**

- **Entity lifetime/ownership**: who allocates/frees engine-spawned entity objects, and the cleanup
  path on disconnect — to be documented in the contract table during Milestone 6.
- **Anti-tamper**: audit `wulfram2.exe` for `IsDebuggerPresent`/timing/self-integrity checks that
  injection might trip. *(Milestone 1 audit)*
- **Stack alignment**: 32-bit MSVC defaults to 4-byte; FP/SSE2 paths in physics may assume 8-byte.
  Watch for faults inside FP code; align wrapper frames if needed. *(Milestone 6)*
- **DLL vs EXE static-init ordering**: keep DLL-side globals from touching engine memory before the
  EXE's own initializers run (the `InitThread` deferral largely handles this; confirm).
- **Game rules gap**: roster/cargo/map semantics currently in Python `Wulf-Forge`; reimplement in
  C++ or drive through the client's own systems. *(Milestone 7)*

## Reference Material (retained, not runtime)

- `Wulf-Forge/packets.toml`, `Wulf-Forge/network/` — protocol layout reference.
- `Wulf-Forge/docs/server-settings-and-tank-physics.md` — BEHAVIOR packet & physics flow.
- `Wulf-Forge/reverseengineering/programs/wulfram2.exe/functions.tsv` — address source of truth.
- `Wulf-Forge/wulfram-lua/` — injection + CMake/FetchContent template.
- Ghidra project `analysis/W2VULK` (live MCP) — ongoing naming, struct layouts.
```
