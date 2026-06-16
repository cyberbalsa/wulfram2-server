# Implementation Notes & Discoveries

Running log of non-obvious findings made while building the headless server. Newest first.

## Tooling / build
- **MinHook v1.3.4 ships its own `CMakeLists.txt`** (v1.3.3 did not). So `FetchContent_MakeAvailable(minhook)`
  defines the `minhook` target itself; our `if(NOT TARGET minhook)` source-build block is now a defensive
  fallback for older tags. Lib lands as `minhook.x32d.lib`.
- **clang-tidy vs MSVC compile_commands:** MSVC emits `/Zc:preprocessor`, which clang flags as
  `clang-diagnostic-unused-command-line-argument`; with `.clang-tidy` `WarningsAsErrors: '*'` that aborts every
  file. Fixed in `lint.ps1` with `--extra-arg=-Qunused-arguments` (+ `-Wno-unknown-warning-option`).
- **`build.ps1`/`lint.ps1` require PowerShell 7 (`pwsh`)** — they use `?.`/PS7 syntax that Windows PowerShell
  5.1 cannot parse. The pre-push hook hard-requires `pwsh` and fails loudly with an install hint if absent
  (silent fallback to `powershell.exe` would falsely block pushes).
- **Hooks pinned to LF** via `.gitattributes` so a fresh clone's `#!/bin/sh` shebang survives `autocrlf=true`.
  Activate hooks per clone with `git config core.hooksPath .githooks`.

## Process
- **Codex reviewer cannot open a shell here** (sandbox `CreateProcessAsUserW: 1312`). Feed it the spec/diff
  **inline** in the prompt; it reviews from text. Reserve Codex for substantive/risky code (parsers, injection,
  ABI, DllMain), not trivial tasks.
- **Concurrency lesson:** ensure a subagent has fully terminated before dispatching the next — two agents
  committing to `master` in the same working tree at once is avoidable risk (git serialized cleanly this time).
- **Quality gate runs on every push** (pre-push). Batch docs-only commits and let them ride up with the next
  code push so the ~1–2 min gate runs once per batch instead of per markdown edit.

## Paths
- **Canonical clean client install: `./w2/`** (repo-relative; gitignored, proprietary binaries).
  The loader, `gen_addresses.py` (`--exe`), `config/headless.toml`, and the Task 9 smoke test should
  target `./w2/wulfram2.exe` — NOT the old `..\Game\` dirty install. The pinning manifest must be
  generated from the exact build placed in `./w2/`.

## Binary facts (wulfram2.exe, from Ghidra W2VULK) — for upcoming tasks
- Image base `0x00400000`, x86, pre-ASLR → fixed-address function pointers are valid.
- Loop seam: `App_RunGameAndExit @ 0x004a0b70` → `Client_RunMainLoop @ 0x004a0aa0` (flat while-loop).
- Server-role networking already compiled in: `Net_InitAccept @ 0x00507ff0` → `Net_InitMultiUdpIpAccept @ 0x00507ee0`
  → `Net_InitAcceptSocket @ 0x00507810` (bind/listen/non-blocking). `__thiscall` on a `Net` object.
- 12 head `*_Init` seams to stub (render/D3D/DX/GDI/Glide/DDraw/DInput/FMOD/Voice); default port `0xa43` = 2627.
