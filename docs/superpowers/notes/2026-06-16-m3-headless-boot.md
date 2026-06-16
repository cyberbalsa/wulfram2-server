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

