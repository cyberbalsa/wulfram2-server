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
the security-critical paths (PE validator, injector). Next: **Milestone 3 — head-chop** (stub the 12 `*_Init`
seams, capture real hook-site bytes, prove headless boot to the loop seam).
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
