# Wulfram II Headless Server — Milestone 3: Head-Chop (Implementation Plan)

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development (fresh subagent per task + two-stage review; Codex review on the hooking/ABI code). Steps use `- [ ]` checkboxes.

**Goal:** Make `wulfram2.exe` initialize **headlessly** — no GPU/window/audio — by injecting `wulf_headless.dll` and detouring the render/audio/input `*_Init` seams to no-op success stubs, so the game boots all the way to its main-loop seam (`Client_RunMainLoop @ 0x004a0aa0`) with zero access violations. This is the prerequisite for M4 (hijacking the loop).

**Architecture:** Builds on the M0–M2 foundation (loader injects the DLL; `InitThread` runs off the loader lock and already does a binary self-check). M3 adds, inside `InitThread` *before the game's init runs to completion*: MinHook initialization, real hook-site-byte validation, and inline detours on the 11 stubbable head seams (returning the exact success values their callers expect), plus a non-null no-op stub for the render driver vtable. No loop hijack yet (that's M4).

**Tech Stack:** C++17, MSVC x86, MinHook v1.3.4 (already vendored), the existing `wfh/engine_abi.hpp` typedefs, `gen_addresses.py`, GoogleTest + the clang-tidy/cppcheck/git-hook gate.

**Design input (READ — all addresses/ABIs/return values come from here):** `docs/superpowers/notes/2026-06-16-m3-head-chop-discovery.md`. Key finding: **head and body init are decoupled** — no body-init/sim/net reads any head-written global — so 11/12 seams are plain "return success, set nothing" stubs. The one coupling is the render driver vtable `DAT_00677e54` (draw-path only).

**Scope:** M3 only (head-chop + headless boot to the loop seam). M4 (loop hijack + fixed timestep) and beyond are later plans.

---

## Timing note (when do detours need to be installed?)
The injected DLL loads while the game's main thread is SUSPENDED; the loader then resumes it, and the game runs `App_InitInstance → Client_Bootstrap → Client_Main`. `InitThread` runs concurrently on its own thread the moment the DLL loads. **The detours must be installed before the game thread reaches the head `*_Init` calls.** Because the game is resumed only *after* injection returns, and InitThread installs hooks as its first real action, there is a window — but it is racy. **Decision for M3: the loader must keep the main thread suspended until InitThread signals "hooks installed."** Add a simple cross-process/in-process ready signal (a named event, or have InitThread set a flag the loader polls before `ResumeThread`). This plan includes that handshake (Task M3.2).

---

## File structure (created/modified)
```
src/dll/
  hooks/
    engine_hooks.hpp/.cpp   # MinHook init + install/enable/disable helpers, hook registry
    head_stubs.hpp/.cpp     # the 11 detour functions (correct ABI) + their install list
    render_driver_stub.hpp/.cpp  # non-null no-op driver object for DAT_00677e54
  init.cpp                  # MODIFY: after self-check, install head detours, signal ready
include/wfh/
  engine_hooks.hpp          # public surface if needed
gen/
  gen_addresses.py          # MODIFY: --hook-bytes reads real bytes by RVA→file-offset
  binary_manifest.h         # REGENERATED: real hook-site bytes for the 11 seams + loop
  addresses.h               # REGENERATED: ensure Render_SwitchActiveDriver + globals present
loader/ (injector.cpp)      # MODIFY: suspend→inject→WAIT for ready→resume handshake
tests/                      # gtest for hook registry logic + pytest for byte capture
```

---

## Tasks

### Task M3.1 — Generator: capture real hook-site bytes (RVA→file-offset)
**Files:** `gen/gen_addresses.py`, `gen/binary_manifest.h` (regen), `tests/test_gen_addresses.py`.
- [ ] **TDD:** extend `test_gen_addresses.py` — craft a PE32 with one section (RVA + raw-pointer + size) and a known byte at a function VA; run generator with `--hook-bytes 16` and assert `binary_manifest.h` emits `inline constexpr HookSite kSites[]` with the right name/address/bytes and `site_count==N`.
- [ ] Implement byte capture: for each wanted seam address (VA), convert VA→RVA (`VA - image_base`), map RVA→file offset via the section headers (find the section whose `[VirtualAddress, VirtualAddress+VirtualSize)` contains the RVA; `fileoff = RVA - VirtualAddress + PointerToRawData`), read `--hook-bytes` bytes. Emit `inline constexpr std::uint8_t kSite_<name>[] = {...}; ` + an `inline constexpr HookSite kSites[] = {{ "<name>", 0xADDR, kSite_<name>, N }, ...};` and `kBinaryManifest.sites = kSites, site_count = N`.
- [ ] A `gen/hook_sites.txt` lists which functions get byte capture: the 11 stubbable seams + `Client_RunMainLoop` + `Render_SwitchActiveDriver`.
- [ ] Regenerate from `./w2/wulfram2.exe`; `.\build.ps1` green (the InitThread self-check now validates real bytes — site_count>0). pytest + lint PASS. Commit.

### Task M3.2 — MinHook scaffolding + loader↔InitThread ready handshake
**Files:** `src/dll/hooks/engine_hooks.{hpp,cpp}`, `src/dll/init.cpp`, `src/loader/injector.cpp`.
- [ ] `engine_hooks`: `HooksInit()` → `MH_Initialize`; `InstallDetour(void* target, void* detour, void** orig)` → `MH_CreateHook`+`MH_EnableHook` with logging of target addr + status; `HooksShutdown()`. Thin wrapper over MinHook; log every step (`WFH_INFO/FATAL`).
- [ ] **Ready handshake (fixes the suspend/resume race):** InitThread, after installing hooks, signals readiness via a named Win32 event (e.g. `Local\\WulfHeadlessReady_<pid>`); the loader, after injecting, `WaitForSingleObject`s that event (with a timeout) BEFORE `ResumeThread`. So the game's init never runs before detours are live. Implement the event create (InitThread) + open/wait (loader). On timeout, loader logs FATAL + tears down.
- [ ] InitThread order becomes: logging → self-check (real bytes now) → `HooksInit()` → install head detours (Task M3.3) → install render-driver defense (M3.4) → signal ready → return.
- [ ] Smoke (gtest can't cover injected hooks): the integration test in M3.5 covers it. Unit-test any pure registry logic. Build green, lint PASS, commit.

### Task M3.3 — Head-seam detours (correct ABIs, return success)
**Files:** `src/dll/hooks/head_stubs.{hpp,cpp}`.
Detour each seam to a stub that logs once and returns the success value (NO call to original). Use `wfh::addr::<name>` + `wfh::abi::*` typedefs. **Mind the 3 non-cdecl ABIs.** From the discovery:
| Seam | ABI | Stub returns |
|---|---|---|
| Render_InitDriverAndViewports | `__cdecl(void*)` | (void) |
| Winsys_D3D_Init | `__cdecl(void*,int)` | (void) |
| Winsys_D3D_InitDevice | `__thiscall(this,bool)` | `1` (TRUE, low byte set) |
| Winsys_DX_Init | `__cdecl(char*,int)` | (void) |
| Winsys_GDI_Init | `__cdecl(int,int)` | (void) |
| Winsys_InitGlideRenderer | `__cdecl(uint)` | (void) |
| DirectDraw_InitAndSetCooperativeLevel | `__cdecl(void)` | `1` |
| DirectInput_InitMouse | `__cdecl(void)` | `1` |
| DirectInput_InitJoystick | `__cdecl(void)` | `0` (= no joystick) |
| Winsys_Input_InitWin32State | `__cdecl(void)` | (void) |
| Snd_InitDevice | `__fastcall(int* ECX)` | `1` (AL=1) |
- [ ] **Do NOT detour `Voice_InitSystem`** (non-standard EDI-`this`; it's a child of `Snd_InitDevice` and never runs once the parent is stubbed).
- [ ] For `__thiscall`/`__fastcall` detours under MSVC: declare the detour with the matching convention (`static <ret> __thiscall Stub_...(void* self, ...)`, `static <ret> __fastcall Stub_...(int* ecx)`). Verify generated asm matches the convention (MinHook needs the detour ABI to match the target). Codex-review this file (ABI correctness is the risk).
- [ ] Each stub: `WFH_DEBUG("hook", "stubbed <name>")` then return. An install list iterated by InitThread.
- [ ] Build green, lint PASS, commit. (Behavior verified in M3.5.)

### Task M3.4 — Render driver vtable defense
**Files:** `src/dll/hooks/render_driver_stub.{hpp,cpp}`.
- [ ] Provide a non-null no-op stub for `DAT_00677e54` (driver vtable ptr) so any stray `(*DAT_00677e54[idx])()` on a kept path doesn't null-deref. Simplest robust approach per discovery: **short-circuit `Render_SwitchActiveDriver @ 0x00485f70`** to return `1` without dispatching the driver (it already early-returns when `DAT_00678491==0`). Evaluate both: (a) detour `Render_SwitchActiveDriver` → return 1; (b) additionally point `DAT_00677e54` at a static zeroed struct (≥0x100 bytes) whose vtable is no-op thunks. Implement (a) as primary; add (b) as defense if M3.5 reveals any draw-path deref.
- [ ] Build green, lint PASS, commit.

### Task M3.5 — Headless-boot integration smoke + boot trace
**Files:** boot-trace logging in `init.cpp`/stubs (optional `WFH_INFO` markers at each kept body-init via lightweight detours OR rely on the game's own log), `docs/superpowers/notes/2026-06-16-m3-headless-boot.md`.
- [ ] Run `loader.exe ./w2/wulfram2.exe`; confirm via `build/logs/headless.log`: hooks installed, each head seam stubbed when hit, and the game reaches `Client_RunMainLoop` (add a temporary detour on `Client_RunMainLoop` that logs "reached loop seam" then — for M3 only — calls the original or returns, so we observe arrival without yet replacing the loop; M4 replaces it).
- [ ] Assert: **no window appears, no GPU/DirectDraw device created, no audio device** (the stubs prevented them), and **no access violation** anywhere in the body-init chain. If an AV occurs, capture the faulting address + last boot-trace marker (the minidump/breadcrumb infra from the spec) and diagnose.
- [ ] Kill the process; document results in the notes doc. Commit notes.
- [ ] **Exit criteria for M3:** headless boot reaches the loop seam, zero AVs, no head devices created, self-check validates real hook-site bytes.

---

## Risks & notes
- **ABI detours (M3.3)** are the main risk — `__thiscall`/`__fastcall` detour signatures must exactly match or the stack corrupts. Codex-review + verify generated asm. MinHook handles the trampoline; we never call originals (full no-op), which simplifies (no trampoline-call ABI concerns).
- **Vtable dispatch:** renderer/sound inits are reached via vtables, but the vtable entries point at the named functions, so a prologue detour intercepts them regardless of call site. Confirmed by discovery.
- **Suspend/resume race (M3.2 handshake)** is essential — without it the game thread could pass a seam before its detour is live.
- **`DAT_00678491` guard:** `Render_SwitchActiveDriver` early-returns when it's 0 — check whether normal boot sets it before the switch; if so, the detour-to-return-1 approach is the reliable one.
- Keep `Voice_InitSystem` untouched (EDI-`this`).
- Hook-site self-check (real bytes) now meaningfully validates the binary before hooking — if bytes mismatch, abort (already wired in InitThread).
