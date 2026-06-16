# Wulfram II Headless Server — Milestone 4: Loop Hijack → Server Tick (Plan)

> Subagent-driven, **tight single-purpose reviewed steps** (the M3 autonomous runs overran — keep each task scoped, report-only where it says report-only, no architecture pivots without sign-off). Codex-review the loop-hijack + SEH code.

**Goal:** Convert the now-headless-booting `wulfram2.exe` from running its own client loop into running **our fixed-timestep server tick** — driving sim/net but **never rendering** — with a structured-exception boundary so an engine fault is captured, not silently fatal. Networking/sessions/physics-drive are M5+.

**Builds on:** M3 (Approach B) — the process boots fully headless (software renderer, hidden window) and currently runs `Client_Main`'s **inline** render loop (NOT `Client_RunMainLoop @ 0x4a0aa0`, which is `DAT_00677f1d`-gated and not taken). The `Client_RunMainLoop` observation detour is installed but not hit. So **M4 hijacks the inline loop**, wherever it actually spins.

**Key constraint:** keep everything that M3 verified working (headless boot, hidden window, env bypasses). Don't regress the boot.

---

## Tasks

### M4.0 — RE discovery: locate the inline loop + hijack point (READ-ONLY)
**Hard scope:** Ghidra only, report only, no code/commits/changes, do not exceed scope.
- Decompile `Client_Main @ 0x004186d0`. Find the inline loop that spins after init (the one consuming CPU in the M3 boot). Identify, per iteration: which calls are **render** (`Client_RenderFrame` and friends — to SKIP), which are **input/window pump** (`Input_Poll*`, `PeekMessage`/`DispatchMessage` — likely SKIP or minimal), which are **sim/animation/timing** (`Anim_TickAllObjects`, the active-state vtable tick, `Time_*` — to KEEP/drive), and which are **net** (to KEEP).
- Determine the cleanest **hijack point**: (a) detour the whole loop function if it's a separate function, or (b) detour `Client_RenderFrame` to a no-op (cheapest — let the real loop run but skip rendering), or (c) find a per-frame "tick" function to detour. Compare options; the loop body may not be a standalone function (it's inline in `Client_Main`), so option (b)/(c) (detour the render call + maybe the input poll) may be simpler than replacing the loop.
- Report: the loop structure (per-iteration call list with addresses + keep/skip/drive classification), the recommended hijack mechanism, the exact function(s) to detour, and how the loop terminates (the quit flag `DAT_00678539` seen earlier) so a server can run indefinitely.

### M4.1 — Skip rendering + establish the server-tick seam
- Based on M4.0: install the minimal detours so the inline loop runs **without rendering** (e.g. detour `Client_RenderFrame` → no-op; if needed, neutralize the per-frame present/blit). Keep sim/anim/net running. This turns the booted client into a "spinning headless tick" that does everything but draw.
- Verify (controller-run smoke): process boots headless, stays alive, CPU lower than full-render (no render work), no AV, no window. Document.

### M4.2 — Fixed-timestep pacing
- Make the tick deterministic: pace the loop to the native rate (config `tick_hz`, default 20), clamping the delta fed to the sim/physics. If the engine reads its own `Time_*` globals, drive/anchor them consistently. Do NOT let the tick free-run at software-render speed.
- Verify: tick rate measured ~tick_hz; sim time advances at the intended rate.

### M4.3 — SEH boundary + breadcrumb (per the spec's reliability requirement)
- Wrap the per-tick engine calls in a structured-exception boundary (`__try/__except`) that, on fault, logs exception code/address + a breadcrumb (last tick #, last engine fn) + writes a minidump (`dbghelp` already linked), then terminates cleanly rather than a silent/ugly crash.
- Verify: a deliberately-faulted test path (or a forced AV in a guarded test) is caught + logged + minidumped.

### M4.4 — Integration smoke + docs
- Controller-run: boot headless, confirm the server tick runs at the fixed rate with rendering skipped, stable for 60s+, no AV, no window, clean teardown. Document in `docs/superpowers/notes/`.
- **Exit criterion:** the headless process runs our fixed-timestep, render-free tick indefinitely and stably, with the SEH boundary live. (Actual client connections + sim authority = M5/M6.)

---

## Deferred to later milestones (per the design spec)
- **M5** — Net connection-object layout + `Net_InitAccept*` accept loop + token session table + a real client connects (loopback self-host).
- **M6** — per-entity authentic physics drive (`Vehicle_ApplyThrustForces`/`EntityPhysics_IntegrateStep`) + parity vs `wulfsim`.
- **M7** — multi-client + game rules (roster/cargo), "current player" singleton audit.

## Risks
- The loop is inline in `Client_Main`, so "replace the loop body" is awkward; prefer detouring the render/present call(s) to skip drawing while letting the engine's own loop spin. M4.0 decides.
- Skipping rendering might leave per-frame state the sim path reads (unlikely — sim ran fine during M3's full-render boot); verify no regression.
- Don't break the M3 headless boot. Each step is controller-verified before the next.
