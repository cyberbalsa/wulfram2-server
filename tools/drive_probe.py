#!/usr/bin/env python3
"""Live dev-console drive test: after the on-join BEHAVIOR load, apply a forward control
input to the test tank and run the engine's OWN per-tank thrust step
(Vehicle_UpdateThrustSimulation @ 0x4f9e20), letting the engine's global world tick
integrate the resulting forces. Watches the entity position to confirm the tank actually
moves -- i.e. that feeding BEHAVIOR was sufficient for thrust.

Recipe (verified in Ghidra, see memory/m6-tank-physics-drive-recipe):
  step(model, tankVehicle): ECX=model, stack=tankVehicle
  ComputeControlScalars reads input from the tuning table: table=*(tankVehicle+8),
  base=*(table), forward input slot2 SCALED at base+2*0x20+0x10 = base+0x50,
  value = input * divisor (divisor = *(tankVehicle+0xc)). Forward scalar lands at model+0x70.
  ApplyThrustForces accumulates force onto the physObj; the global tick integrates it.

Controller addresses come from the DLL's "M6 drive controller built" log line. Pass them
as args or let it default to the most recent run's values.

Usage:
  python tools/drive_probe.py <tankVehicleHex> <modelHex> [input] [iterations]
  python tools/drive_probe.py 0x72708F80 0x03D9D950 1.0 40
"""
from __future__ import annotations

import os
import re
import struct
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from dev_poke import Dev, parse_addr  # noqa: E402

UPDATE_THRUST = 0x004F9E20  # Vehicle_UpdateThrustSimulation __thiscall(model; stack tankVehicle)

ENT_POS = 0x0C
ENT_PHYSOBJ = 0xBC
ENT_HEALTH = 0xD0
PHYS_VEL = 0x08  # physObj velocity dbl[3] @ +0x08 (per recipe)


def eax(resp: str) -> int:
    m = re.search(r"eax=0x([0-9a-fA-F]+)", resp)
    return int(m.group(1), 16) if m else -1


def call(dev: Dev, addr: int, conv: str, *args: int) -> str:
    line = f"call 0x{addr:x} {conv}" + "".join(f" 0x{a & 0xFFFFFFFF:x}" for a in args)
    return dev.cmd(line)


def f32(dev: Dev, addr: int) -> float:
    return struct.unpack("<f", dev.peek(addr, 4))[0]


def vec3_f32(dev: Dev, addr: int) -> list[float]:
    raw = dev.peek(addr, 12)
    return [round(struct.unpack_from("<f", raw, i * 4)[0], 3) for i in range(3)]


def vec3_f64(dev: Dev, addr: int) -> list[float]:
    raw = dev.peek(addr, 24)
    return [round(struct.unpack_from("<d", raw, i * 8)[0], 4) for i in range(3)]


def main(argv: list[str]) -> int:
    tank = parse_addr(argv[1]) if len(argv) > 1 else 0x72708F80
    model = parse_addr(argv[2]) if len(argv) > 2 else 0x03D9D950
    inp = float(argv[3]) if len(argv) > 3 else 1.0
    iters = int(argv[4]) if len(argv) > 4 else 40

    force_guard = len(argv) > 5 and argv[5] == "guard"

    dev = Dev()
    vtable = dev.read_u32(tank)
    entity = dev.read_u32(tank + 4)
    tbl_obj = dev.read_u32(tank + 8)
    divisor = dev.read_i32(tank + 0xC)  # INT 50, not a float
    guard = f32(dev, tank + 0x18)
    print(f"tankVehicle=0x{tank:08x} vtable=0x{vtable:08x} (expect 0x543128)")
    print(f"  entity=0x{entity:08x}  tableObj=0x{tbl_obj:08x}  divisor={divisor}  +0x18 guard={guard}")
    if entity == 0 or tbl_obj == 0:
        print("!! controller looks stale (entity/table null) — rebuild it first")
        return 1
    if force_guard and guard == 0.0:
        print(f"  poking TankVehicle+0x18 = 1.0 to pass the thrust gate -> {dev.write_f32(tank + 0x18, 1.0)}")
    base = dev.read_u32(tbl_obj)
    fwd_slot = base + 2 * 0x20 + 0x10  # slot2 forward, scaled-read slot
    physobj = dev.read_u32(entity + ENT_PHYSOBJ)
    health = f32(dev, entity + ENT_HEALTH)
    print(f"  base=0x{base:08x}  fwd_slot=0x{fwd_slot:08x}  physObj=0x{physobj:08x}  health={health}")
    raw_input = inp * (divisor if divisor != 0 else 1)
    print(f"  forward input={inp} -> raw {raw_input} written to fwd_slot each tick\n")

    print(f"pos BEFORE: {vec3_f32(dev, entity + ENT_POS)}  vel: {vec3_f64(dev, physobj + PHYS_VEL)}")
    for i in range(iters):
        dev.write_f32(fwd_slot, raw_input)               # forward input
        call(dev, UPDATE_THRUST, "thiscall", model, tank)  # engine thrust step
        if i % 8 == 0 or i == iters - 1:
            pos = vec3_f32(dev, entity + ENT_POS)
            vel = vec3_f64(dev, physobj + PHYS_VEL)
            scal = [round(f32(dev, model + off), 4) for off in (0x58, 0x5C, 0x68, 0x6C, 0x70)]
            print(f"  it{i:2d}: pos={pos} vel={vel}  model[+58,+5c,+68,+6c,+70]={scal}")
        time.sleep(0.05)  # let the engine's global world tick integrate
    print(f"\npos AFTER:  {vec3_f32(dev, entity + ENT_POS)}  vel: {vec3_f64(dev, physobj + PHYS_VEL)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
