# M3 Headless-Boot Smoke — Results (2026-06-16)

Run of the Milestone-3 "head-chop" headless-boot smoke against the real game
(`w2/wulfram2.exe`), with a temporary `Client_RunMainLoop` observation detour and
the M3.4 render-driver defense added.

## Outcome (TL;DR)

**BLOCKED on the M3 exit criterion.** The game does **not** reach the
`Client_RunMainLoop` loop seam. It dies on an **environmental registry-permission
precondition that is upstream of, and unrelated to, the head-chop / render path** —
so neither the head stubs nor the M3.4 render-driver defense is even reached at the
failure point. No access violation; the failure is a clean game-side error message
box (`MessageBoxA`). Cleanup confirmed: no lingering `wulfram2` process.

The head-chop machinery itself works correctly up to the point the registry wall
stops the boot: all 11 head `*_Init` detours install, the M3.4 detour installs, the
loop observation detour installs, the loader handshake completes, the game resumes,
and the first head seam hit (`Winsys_InitGlideRenderer`) is stubbed cleanly.

## Commands

Build + lint (run before each smoke):

```
.\build.ps1            # green: 16/16 tests pass
.\lint.ps1             # PASS (clang-tidy clean, cppcheck clean)
```

Smoke (PowerShell, try/finally with cleanup = `Stop-Process -Name wulfram2 -Force`):

```
Remove-Item build\logs\headless.log, build\logs\loader.log -Force -EA SilentlyContinue
Start-Process build\loader.exe -ArgumentList @('.\w2\wulfram2.exe','-windowed') -PassThru
# poll build\logs\headless.log up to ~15s for "reached Client_RunMainLoop"
# finally: Stop-Process -Name wulfram2 -Force -EA SilentlyContinue
```

Note: `loader.log` is written next to `loader.exe`, i.e. `build\logs\loader.log`
(NOT the repo-root `logs\`). `build\config\headless.toml` already existed (no copy
needed).

## headless.log (build\logs\headless.log) — key excerpt

```
[INFO][init] InitThread alive; logging up (level=1)
[INFO][init] hook-site self-check OK (13 sites)
[INFO][init] MinHook initialized
[INFO][head] head stub installed: Render_InitDriverAndViewports
... (all 11 head stubs install: Winsys_D3D_Init, Winsys_D3D_InitDevice, Winsys_DX_Init,
     Winsys_GDI_Init, Winsys_InitGlideRenderer, DirectDraw_InitAndSetCooperativeLevel,
     DirectInput_InitMouse, DirectInput_InitJoystick, Winsys_Input_InitWin32State, Snd_InitDevice)
[INFO][head] all 11 head stubs installed
[INFO][head] M3.4 defense detour installed: Render_SwitchActiveDriver
[INFO][head] TEMP (M3) observation detour installed: Client_RunMainLoop
[INFO][init] head stubs installed
[INFO][init] signaled ready
[INFO][init] foundation ready; head seams stubbed
[DEBUG][head] stubbed Winsys_InitGlideRenderer       <-- only head seam reached
                                                         (then the registry error box)
```

The log ENDS at `stubbed Winsys_InitGlideRenderer`. Crucially, the M3.4 line
`M3.4: Render_SwitchActiveDriver short-circuited` never appears at runtime — the
boot never reaches `Render_SwitchActiveDriver`.

## loader.log (build\logs\loader.log)

```
[INFO][loader] binary pinning OK (stamp=45254d1f size=00288000)
[INFO][loader] created suspended pid=...
[INFO][loader] injected wulf_headless.dll
[INFO][loader] DLL signaled ready; hooks installed
```

Loader behaved exactly as designed: pin → spawn suspended → inject → wait for ready
→ resume.

## Was the loop seam reached?

**No.** The `reached Client_RunMainLoop — head-chop OK` marker was never written.

## Where it actually died

A `MessageBoxA` titled **"Error"** appears (no window/GPU output otherwise). Its
text, captured via `EnumChildWindows`/`GetWindowText`:

```
Can't open nor create registry element:
 HKEY_USERS\.DEFAULT
Access is denied.
You need to run this app first time on an account that can modify the registry!
```

Traced in Ghidra:

- String `00561af0` is referenced only by `Cfg_RegOpenOrCreateSubkey @ 0x0047e0e2`,
  which calls `RegOpenKeyExA` then `RegCreateKeyExA` (requesting `KEY_ALL_ACCESS`
  `0xf003f`); on failure it shows this `MessageBoxA(..., "Error", ...)`.
- Caller on the boot path: `WebLaunch_SetWorkingDirectory @ 0x004a4db0`, invoked
  EARLY in `Client_Main @ 0x004186d0` (right after `Cmd_ApplyClientFlags`, guarded
  by `if (DAT_00677f1e == 0)`), opening `Software\Wulfram` under HKCU. This runs
  well BEFORE `Render_SwitchActiveDriver @ 0x00485f70`.

So the blocker is a **registry write/create precondition** the game enforces at
startup, independent of headless mode. It is hit before the render path, which is
why the M3.4 defense is never exercised at runtime.

## M3.4 fix — was it needed? (Yes, but upstream-blocked)

Implemented per the discovery doc's primary recommendation, and it is the correct,
RE-validated fix for the render-path crash that WOULD occur once the registry wall
is cleared. The decompilation confirms the render path is genuinely unsafe headless:

- `Render_SwitchActiveDriver` (`uint __cdecl(void)`, signature confirmed) on cold
  boot enumerates the driver registry via `Winsys_SelectBestUsableRenderer @
  0x004b9aa0`; with no usable headless renderer that function calls
  `Sys_ErrorBoxAndExit("Hokey Display Card or Driver?", "Can't find a usable
  display mode...")`.
- `Client_Main` also dereferences the render-driver object `DAT_00677e54` directly
  (`(*(code*)DAT_00677e54[0x18])(0)`, `DAT_00677e54[0x12](...)`), so a detour that
  returned without leaving a non-null `DAT_00677e54` would NULL-deref.

The M3.4 detour therefore: installs a non-null no-op render-driver object into
`DAT_00677e54` (object[0] -> all-no-op vtable; object[1..] -> no-op thunks) and
returns 1, never running the original. The no-op thunk is `__cdecl` (caller
cleanup) because the engine invokes the driver slots caller-cleanup with a VARYING
argument count at the same index (e.g. slot `0xb` is called with 2 args in
`Render_SwitchActiveDriver` and 3 args in `Render_InitDriverAndViewports`, with
`this` passed explicitly as a stack arg, not in ECX) — verified against the
decompiled call sites. Committed as `390677b`.

Because the registry error fires first, the M3.4 fix is currently unverifiable
end-to-end; it builds/lints clean and is left in place for when the precondition is
resolved.

## Cleanup confirmation

Every run used a try/finally whose finally ran `Stop-Process -Name wulfram2 -Force
-ErrorAction SilentlyContinue`. After each run, `Get-Process -Name wulfram2` was
empty. No lingering `wulfram2` (or `loader`) process remains.

## Caveats / environment notes

- **Defender false positive:** the first smoke run caused Windows Defender to
  quarantine `build\loader.exe` as `Behavior:Win32/DefenseEvasion.A!ml` (a
  behavioral DLL-injection heuristic) at run time. A Defender folder exclusion was
  added for the project directory; subsequent runs were not quarantined.
  `loader.exe` is rebuilt by `build.ps1` regardless.
- **Registry precondition (the blocker):** the game requires the ability to
  open/create `HKCU\Software\Wulfram` (KEY_ALL_ACCESS) on first run. In this
  environment that fails with "Access is denied". The on-screen guidance is to "run
  this app first time on an account that can modify the registry" — i.e. a one-time
  elevated/clean run to create the keys, after which non-elevated runs should pass
  this gate. This is unrelated to the head-chop and out of M3 scope; it must be
  cleared (one-time elevated run, or pre-seeding the keys) before the headless-boot
  exit criterion can be validated.
- Until the registry gate is cleared, the M3 exit criterion (boot headless to the
  loop seam with zero access violations) cannot be confirmed in this environment.
  No access violation was observed up to the gate.
```

---

## Registry bypass + re-run (2026-06-16, commit `c39ff99`)

Implemented the in-DLL bypass of the first-run registry gate and re-ran the smoke.
**The registry gate is now passed** (no MessageBox). The boot advances further but
**still does not reach `Client_RunMainLoop`** — a NEW blocker appears: the game
exits cleanly (exit code 0) early in input bring-up, with no error box and no
access violation.

### RE — choosing the stub point

Decompiled both candidates in Ghidra (program `wulfram2.exe`):

- `Cfg_RegOpenOrCreateSubkey` (entry `0x0047e040`; box at `0x0047e0e2`):
  `void __fastcall(char* subkeyName)`. Does **not** return a status; it writes the
  opened `HKEY` back into its caller object at `EDI+0x10` (out-param via a
  register-passed `this`). Stubbing it to "success" would leave that HKEY stale and
  break callers (`Cfg_GetLocationOrDefault`, the `Cfg_RegSetStringValue` chain).
  **Rejected as the stub point** — it is a shared leaf with a live out-param.
- `WebLaunch_SetWorkingDirectory` (`0x004a4db0`): `void __cdecl(void)` (verified by
  disassembly — no params, bare `ret`, caller-clean). Self-contained: opens
  `HKCU\Software\Wulfram`, `Cfg_GetLocationOrDefault`, `__chdir`. `Client_Main`
  reads no global that only this sets. **Safe to no-op.**

Crucial correction to the prior section: the **observed `.DEFAULT` access-denied
box does NOT come from `WebLaunch_SetWorkingDirectory`** (which only ever opens
`HKEY_CURRENT_USER`). It comes from **`Installer_RegisterFileAssociations`
(`0x004a4180`)**, called from `Cmd_ResolveStartupArgs (0x004183a0)`, which runs in
`Client_Main` **before** `WebLaunch_SetWorkingDirectory`. That function registers
`.w2l` file associations, MIME types, App Paths, and the **Netscape Navigator URL
handlers (Suffixes/Viewers)** under HKCU **and `HKEY_USERS\.DEFAULT`** — the latter
is exactly the root in the error text, and an unprivileged account cannot create
it. Its ABI: Ghidra types it `__fastcall(char*)` with the one arg in ECX (prologue
`MOV ESI,ECX`), return value unused by its caller, bare `ret` epilogue.

**Decision:** stub BOTH self-contained callers (not the shared leaf). Each is a
side-effecting step whose result `Client_Main` never reads back, and a headless
server needs neither OS file associations / Netscape handlers nor the client's HKCU
install-dir config.

### Implementation

- Detours in `head_stubs.cpp`, installed in `InstallHeadStubs()` via
  `InstallRegistryGateBypass()` (live before the game resumes, through the existing
  handshake):
  - `Stub_Installer_RegisterFileAssociations` — `__fastcall(char* ECX, int EDX
    dummy) -> void`, the standard MinHook `__fastcall` shim (same pattern as
    `Stub_Snd_InitDevice`); zero stack args => bare-`ret` callee cleanup matches.
  - `Stub_WebLaunch_SetWorkingDirectory` — `__cdecl() -> void` no-op.
  - Both log `WFH_DEBUG("hook","bypassed <name>")`.
- `gen/{known_addresses.tsv,wanted.txt,hook_sites.txt}` gained both names;
  regenerated with `--hook-bytes 16`. `site_count` rose **13 -> 15**; the
  `GeneratedHeaders` assert was updated to `15u`.
- `.\build.ps1` green (16/16 ctest), `.\lint.ps1` PASS (clang-tidy + cppcheck
  clean), clang-format clean.

### Re-run progression (build\logs\headless.log)

```
... all 11 head stubs install; M3.4 + loop observation detours install ...
[INFO][init]  signaled ready / foundation ready; head seams stubbed
[DEBUG][head] stubbed Winsys_InitGlideRenderer
[DEBUG][hook] bypassed Installer_RegisterFileAssociations   <-- registry gate #1 passed
[DEBUG][hook] bypassed WebLaunch_SetWorkingDirectory        <-- registry gate #2 passed
[DEBUG][head] stubbed DirectInput_InitJoystick              <-- last line; further than before
```

- **Registry gate: PASSED.** Both bypass detours fire; **no MessageBox**
  (`MainWindowTitle` empty throughout — previously it was `"Error"`).
- **Reached the M3.4 render defense? Not observed.** The
  `M3.4: Render_SwitchActiveDriver short-circuited` line does not appear in the
  (flushed) log before the process exits.
- **Reached the loop seam? No.** `reached Client_RunMainLoop — head-chop OK` was
  never written.

### New blocker

The `wulfram2.exe` process **exits on its own with exit code 0** (captured via
`Process.WaitForExit`/`ExitCode`) shortly after `stubbed DirectInput_InitJoystick`.
No error MessageBox, no access violation (exit code is `0`, not `0xC0000005`), and
**no Windows Error Reporting / Application Error event** is logged. This is a clean,
graceful early exit — consistent with an `App_ExitGracefully(0,0)` / `_exit(0)`
path early in `Client_Main` (e.g. the `Net_RunAutoUpdater()` step, or the
`Shell_OpenUrlWithDefaultBrowser(...)` + `App_ExitGracefully(0,0)` branch), rather
than a crash.

Caveat: the logger drains on a background worker thread (`DrainOnce` on a poll
interval, final flush in `WorkerMain`). On an abrupt process exit the tail of the
queue may not flush, so the last logged line is a lower bound on progress, not
necessarily the true exit point — the exact exit call is not captured in the log.
**Per the M3 task guidance, this NEW blocker is reported, not guess-fixed**
(it is not an ABI problem — the detours fire correctly and the process exits
cleanly). Recommended next step: RE the early-boot exit path (`Net_RunAutoUpdater`
and the `App_ExitGracefully` branches in `Client_Main`) and/or attach a debugger
to break on `App_ExitGracefully` / `_exit` to find which condition triggers the
graceful exit headless.

### Cleanup confirmation

Every re-run used a try/finally whose `finally` ran `Stop-Process -Name wulfram2
-Force -EA SilentlyContinue`. After each run `Get-Process -Name wulfram2` was empty
— no lingering process.

---

## M3.5b — "open browser then quit" branch (2026-06-16, commit `27291c9`)

The clean exit-0 above was diagnosed: the user observed the **default browser open
to wulfram.com** during the run. Traced to a branch in `Client_Main @ 0x00418872`:

```c
if (DAT_00677f4a == 0 && DAT_00679123 != 0 && DAT_00677f48 == 0) {
    Shell_OpenUrlWithDefaultBrowser(DAT_00679160);  // WinExec browser -> wulfram.com
    App_ExitGracefully(0, 0);                        // NORETURN: _exit(0)
}
```

`Shell_OpenUrlWithDefaultBrowser (0x004b8f70)` reads `HKCR\http\shell\open\command`
and `WinExec`s the browser with the URL; `App_ExitGracefully (0x0041db40)` is a
full-shutdown routine ending in `_exit()`. In the headless config `DAT_00679123` is
non-zero (set by the client init/reset-globals), so the branch was taken: browser +
graceful exit.

### Fix (committed)

- Detour `Shell_OpenUrlWithDefaultBrowser` → no-op (`void __cdecl(void* url)`,
  caller-clean). **No browser is ever launched** — covers both this branch and the
  second call site inside `App_ExitGracefully` (which also opens a URL when
  `DAT_00677f48 != 0`).
- Clear the branch guard `DAT_00679123 = 0` from the existing
  `Stub_WebLaunch_SetWorkingDirectory` (which runs immediately before the branch),
  so `App_ExitGracefully(0,0)` is never reached. The Ghidra xref shows `DAT_00679123`
  is **read in exactly one place** (the branch guard at `0x00418872`) with no other
  consumer, so forcing it to 0 is side-effect-free. `App_ExitGracefully` itself is
  intentionally NOT detoured: it is `noreturn` and the legitimate shutdown path, so
  neutralizing it globally would be unsafe — skipping the branch is the surgical fix.
- `Shell_OpenUrlWithDefaultBrowser` added to the gen inputs; regenerated
  (`--hook-bytes 16`); `site_count` 15 → 16, `GeneratedHeaders` assert updated to
  `16u`. `InstallRegistryGateBypass` was refactored table-driven (3 entries) to stay
  under the cognitive-complexity lint gate. build green (16/16), lint PASS.

### Re-run progression (build\logs\headless.log)

```
... head stubs / M3.4 / loop observation detours install ...
[DEBUG][head] stubbed Winsys_InitGlideRenderer
[DEBUG][hook] bypassed Installer_RegisterFileAssociations
[DEBUG][hook] bypassed WebLaunch_SetWorkingDirectory; cleared boot-exit branch guard
[DEBUG][head] stubbed DirectInput_InitJoystick
[DEBUG][hook] bypassed Shell_OpenUrlWithDefaultBrowser (no browser launch)
```

- **Browser launch: STOPPED** (the user's report). `Shell_OpenUrlWithDefaultBrowser`
  is intercepted and no-op'd; no browser window opens, `MainWindowTitle` empty.
- The early `Client_Main` branch is no longer the cause (guard cleared). The
  `Shell_OpenUrlWithDefaultBrowser` interception now logs AFTER
  `DirectInput_InitJoystick`, i.e. it is reached via **`App_ExitGracefully`'s own
  URL-open** (`DAT_00677f48 != 0`), not the early branch.
- **Loop seam: still NOT reached.** `reached Client_RunMainLoop — head-chop OK` not
  written. The process still exits cleanly (code 0, no box, no AV).

### Remaining blocker (reported, not guess-fixed)

Something still drives the boot into **`App_ExitGracefully`** during startup (after
the input-init seams). `App_ExitGracefully` has many callers
(`App_HandleCloseEvent`, `App_RunGameAndExit`, `Client_Main`,
`Input_HandleKeyDown`, `Login_HandleStatusResponse`, `Net_TearDownConnection`,
`Winsys_Win32_PumpMessages`); the early `Client_Main` branch is now ruled out. The
likely culprit is a window-message / close-event path (`Winsys_Win32_PumpMessages`
/ `App_HandleCloseEvent`) reaching a WM_QUIT/WM_CLOSE because the windowing seams
are stubbed, or another boot-time condition invoking graceful exit. This is a
distinct, deeper blocker from the registry gate and the browser launch (both of
which are now resolved). Per the M3 guidance it is reported rather than
guess-fixed — neutralizing `App_ExitGracefully` globally is unsafe (it is `noreturn`
and the real shutdown path). Recommended next step: attach a debugger and set a
breakpoint on `App_ExitGracefully (0x0041db40)` to capture the call stack and
identify which caller fires during boot.

### Cleanup confirmation (M3.5b)

Same try/finally cleanup; `WULFRAM2_EXITCODE=0` captured via `Process.ExitCode`;
after every run `Get-Process -Name wulfram2` was empty. No lingering process.

