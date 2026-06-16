# Milestone 3 "Head-Chop" — Ghidra Discovery (wulfram2.exe)

Design input for M3 (stub the render/audio/input `*_Init` seams so the game boots headless,
then hijack the loop). From a Ghidra W2VULK scout, 2026-06-16.

## Headline finding (de-risks M3)
**No kept body-init / sim / physics / net function reads any global that a head seam writes.**
Verified by `get_xrefs_to` on every head-written global — all readers are render/HUD/cockpit/draw
domain. Head and body are decoupled → plain "return success, set nothing" stubs are safe for 11/12 seams.

## Per-seam stub table
| Seam | Addr | Conv | Success return for stub | Notes |
|---|---|---|---|---|
| Render_InitDriverAndViewports | 0x00485b20 | `__cdecl(driver*)` | **void** (return nothing) | writes driver vtable `DAT_00677e54` + viewports — see "the one coupling" |
| Winsys_D3D_Init | 0x004a8880 | `__cdecl(void*,int)` | void | writes into passed driver obj only |
| Winsys_D3D_InitDevice | 0x004a8280 | **__thiscall**(this,bool) | **return 1** (low byte set) | failure path returns low-byte 0 |
| Winsys_DX_Init | 0x004b3190 | `__cdecl(char*,int)` | void | removes a `Sys_ErrorBoxAndExit` failure path |
| Winsys_GDI_Init | 0x004b5270 | `__cdecl(int,int)` | void | |
| Winsys_InitGlideRenderer | 0x004b8850 | `__cdecl(undefined4)` | void | skips external glide DLL load |
| DirectDraw_InitAndSetCooperativeLevel | 0x004b23a0 | `__cdecl(void)` | **return 1** | caller treats 0 as fatal |
| DirectInput_InitMouse | 0x004b15b0 | `__cdecl(void)` | **return 1** (TRUE) | |
| DirectInput_InitJoystick | 0x004b1b50 | `__cdecl(void)` | **return 0** ok (= no joystick) | already self-no-ops if none |
| Winsys_Input_InitWin32State | 0x004b7b50 | `__cdecl(void)` | void | zeroes keystate; calls InitMouse |
| Snd_InitDevice | 0x00489fb0 | **__fastcall**(int* in ECX) | **return 1** (AL=1) | parent of Voice_InitSystem |
| Voice_InitSystem | 0x0048b680 | **EDI-`this`** (non-standard) | **DO NOT stub independently** | child of Snd_InitDevice; dies when parent stubbed |

## Init ordering (as executed)
`App_InitInstance 0x46fbd0 → Client_Bootstrap 0x46fa00 (render/winsys head hub) → Client_Main 0x4186d0 (body/sim hub + main loop)`.
Renderer/sound `*_Init` are dispatched via vtables, not called directly: driver vtable `DAT_00677e54`
(selected by name in `Render_SwitchActiveDriver 0x00485f70`) and FMOD-instance vtable `DAT_006784c8`.

Sequence: Glide-init [HEAD] → WorldState_InitGlobal [BODY] → InitJoystick [HEAD] → World_InitState [BODY]
→ EntityInfo_InitGlobalTypes [BODY] → VehicleInfo_InitTables/VehicleModel_InitAll [BODY]
→ Render_SwitchActiveDriver→Render_InitDriverAndViewports + selected Winsys_{D3D,DX,GDI}_Init + Win32/InitMouse [HEAD]
→ Net_Init* [BODY/net, straddles head] → Snd_InitDevice→Voice_InitSystem [HEAD]
→ CollisionSystem_InitGlobals [BODY, AFTER head] → main loop.
`SpatialRoot_InitFromMap 0x4e8760` is NOT in boot — runs at map-load via `SpatialIndex_RebuildGlobal`.

## The one coupling: render driver vtable `DAT_00677e54`
Read by many kept render/HUD draws via `(*DAT_00677e54[idx])(...)` — all on the draw path we replace.
A NULL driver is acceptable IF the replacement loop never enters draw. For defense-in-depth, prefer a
**minimal non-null no-op stub driver object** (zeroed struct ≥0x100 bytes, vtable of no-op thunks) assigned
to `DAT_00677e54`. Also: `Spatial_ResetRootBucketsAndCellFlags 0x42b0f9` reads `*(DAT_00677e54+0xd8)` but
only from `Render_SwitchActiveDriver`'s re-switch branch (never cold-init, never sim tick) — inert headless.

## M3 approach recommendation
- Hook the 11 named seams with MinHook detours returning the values above (mind the 3 non-cdecl ABIs:
  `__thiscall` D3D_InitDevice, `__fastcall` Snd_InitDevice, EDI-`this` Voice — handle via correct detour signatures).
- Consider short-circuiting `Render_SwitchActiveDriver 0x00485f70` to return 1 without dispatching the driver
  vtable (or ensure `DAT_00678491==0` so it early-returns), instead of/in addition to stubbing the leaf seams.
- Capture real hook-site bytes (first 8–16) for each seam + `Client_RunMainLoop` into `binary_manifest.h`
  (extend `gen_addresses.py` `--hook-bytes`) so the self-check validates them before hooking.
- Boot-trace each kept body-init reached → prove zero access violations to the main-loop seam.
