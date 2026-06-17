# Dev Console — live engine poke

A localhost-only TCP command socket the injected server opens for **live, in-process poking of the
running engine** — read/write memory, call engine functions, walk the stack — without rebuilding or
attaching `cdb`, and **without touching the game client**. Dev tooling only.

- **Port:** `6969` by default (`[server] dev_port` in `headless.toml`; set `dev_port = 0` to disable).
- **Bind:** `127.0.0.1` only.
- **Safety:** every read / write / call is SEH-guarded — a bad address returns an error string instead of
  crashing the server. `call` runs on the **engine tick thread** so it never races the engine.
- **Requires:** `world_host = true` to have the engine host a world (so there are entities to poke).
- **Source:** `src/dll/server/net/dev_console.cpp` (socket + parser + peek/poke),
  `src/dll/server/dev_engine.cpp` (`call`/`bt`), `tools/dev_poke.py` (client).

## Connecting

**Preferred — the Python client** (handles hex/float/fixed-point math + the socket):

```bash
python tools/dev_poke.py <command> ...
```

**Raw — bash (Git Bash `/dev/tcp`), one-off:**

```bash
exec 3<>/dev/tcp/127.0.0.1/6969
printf 'peek 0x4f9e20 16\n' >&3 ; timeout 2 cat <&3 ; exec 3<&- 3>&-
```

A connected client gets a banner; type `help` for the in-band command list.

## Raw socket commands

The wire protocol is line-based ASCII. Addresses are hex (with or without `0x`); `peek` length is decimal;
byte payloads are hex strings.

| Command | Description |
|---|---|
| `help` / `?` | List commands. |
| `peek <hexaddr> <len>` | Hex + ASCII dump of `len` bytes (decimal, ≤ 4096). SEH-guarded. |
| `poke <hexaddr> <hexbytes>` | Write raw bytes (≤ 4096). Flips page protection, flushes the icache. SEH-guarded. |
| `call <hexaddr> <conv> [hexargs...]` | Invoke a function on the **engine tick thread**; returns `EAX`. `conv` ∈ `cdecl\|stdcall\|thiscall\|fastcall`. ≤ 16 stack args. SEH-guarded. |
| `bt` | Engine tick-thread callstack (EBP walk); `wulfram2+RVA` annotated for code in `0x400000..0x688000`. |
| `bp <hexaddr>` | *(Increment 2b — not yet)* trace breakpoint via VEH int3. |
| `bc <hexaddr>` | *(2b)* clear a breakpoint. |
| `hook <hexaddr>` | *(2b)* logging hook (a log-and-continue breakpoint). |

### `call` convention → register/stack mapping

| Convention | arg0 | arg1 | remaining args |
|---|---|---|---|
| `cdecl` / `stdcall` | stack | stack | stack (pushed right-to-left) |
| `thiscall` | `ECX` (this) | stack | stack |
| `fastcall` | `ECX` | `EDX` | stack |

The invoker restores `ESP` from its frame, so it is correct for both caller-clean (cdecl) and callee-clean
(stdcall/thiscall/fastcall) targets. A faulting call returns `call FAULTED …` (no crash); a tick that never
runs returns `call timed out …`.

## Python tool (`tools/dev_poke.py`) commands

Socket commands (need the server running):

| Command | Description |
|---|---|
| `peek <addr> <len>` | Raw hex dump. |
| `poke <addr> <hex>` | Write raw bytes. |
| `u32 / i32 / f32 / fixed / ptr <addr>` | Typed read (little-endian; `fixed` = fixed16.16 → float; `ptr` = u32 as `0x…`). |
| `write-u32 / write-f32 / write-fixed <addr> <val>` | Typed write. |
| `deref <base> <off>...` | Follow a pointer chain → final address. |
| `entity <addr>` | Decode an entity: `oid`, `pos`, `rot`, `health`, `physObj`. |
| `world` | Walk the engine world list and decode every entity. |
| `call <addr> <conv> [hexargs...]` | Same as the socket `call`. |
| `bt` | Engine-thread callstack. |
| `raw "<line>"` | Send an arbitrary command line. |

Pure number conversion (no socket, for reliable math):

| Command | Description |
|---|---|
| `conv f2h <float>` | float → little-endian hex (e.g. `1.0` → `0000803f`). |
| `conv h2f <hex>` | little-endian hex → float. |
| `conv tofixed <float>` | float → fixed16.16 hex (e.g. `1.0` → `00000100`). |
| `conv fromfixed <hex>` | fixed16.16 hex → float. |

## Engine reference (verified offsets)

Image base `0x00400000` (module `0x00400000..0x00688000`).

**Entity** (`world`/`entity` decode these):

| Offset | Field |
|---|---|
| `+0x0c` | position `float[3]` (x, y, z) |
| `+0x30` | rotation `float[3]` euler radians |
| `+0xb4` | oid (`i32`) |
| `+0xbc` | physics-object pointer |
| `+0xd0` | health (`float`) |

**Physics object** (`*(entity+0xbc)`): pos `float[3]` @ `+0x10`, rot `float[3]` @ `+0x1c`.

**World list walk:** `DAT_006785e4` → WorldMap; `[WorldMap+0]` → Util_List (`count@+0`, `head@+4`);
node `{next@+0, data@+8}`.

## Example — drive a tank's physics live (M6)

```bash
python tools/dev_poke.py world                                   # find the tank entity + physObj
# feed a control input: tuning slot = *( *(physObj+8) ) + n*0x20 + 0x10 ; raw = input * *(physObj+0xc)
python tools/dev_poke.py write-fixed <forward-slot> 1.0
python tools/dev_poke.py call 0x004f9e20 thiscall <model> <tankVehicle>   # Vehicle_UpdateThrustSimulation
python tools/dev_poke.py call <EntityPhysics_IntegrateStep@0x4f2890> cdecl <entity> <dt>
python tools/dev_poke.py world                                   # watch pos change
```

See `memory/` (`dev-console-live-poke`, `m6-tank-physics-drive-recipe`) for the full engine map.
