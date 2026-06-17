#!/usr/bin/env python3
"""Client + number helpers for the injected Wulfram server's dev console (default :6969).

Why this exists: LLMs are unreliable at hex/float/fixed-point math and at parsing hex
dumps. This tool does it deterministically and talks to the dev socket, so commands like
"read the float at entity+0x0c" or "write 1.0 as fixed16.16 to <slot>" are one call.

Usage (CLI):
  python tools/dev_poke.py peek 0x4f9e20 16          # hex dump
  python tools/dev_poke.py u32 0x6785e4              # read u32 (little-endian)
  python tools/dev_poke.py i32 0x...                 # read signed i32
  python tools/dev_poke.py f32 0x...                 # read 32-bit float
  python tools/dev_poke.py fixed 0x...               # read fixed16.16 -> float
  python tools/dev_poke.py ptr 0x...                 # read u32 as 0x-pointer
  python tools/dev_poke.py deref 0x... 0xbc 0x10     # *( *(base+0xbc) + 0x10 ) chain
  python tools/dev_poke.py entity 0x09567308         # decode entity (pos/rot/physObj/health/oid)
  python tools/dev_poke.py poke 0x... deadbeef       # write raw hex bytes
  python tools/dev_poke.py write-f32 0x... 1.0       # write a float
  python tools/dev_poke.py write-fixed 0x... 1.0     # write fixed16.16
  python tools/dev_poke.py raw "peek 0x4f9e20 8"     # send an arbitrary line
  # pure math (no socket):
  python tools/dev_poke.py conv f2h 1.0              # float  -> little-endian hex
  python tools/dev_poke.py conv h2f 0000803f         # hex    -> float
  python tools/dev_poke.py conv tofixed 1.0          # float  -> fixed16.16 hex
  python tools/dev_poke.py conv fromfixed 00010000   # fixed16.16 hex -> float

Importable too:  from dev_poke import Dev ; d = Dev() ; d.read_f32(0x...)
"""
from __future__ import annotations

import re
import socket
import struct
import sys

HOST = "127.0.0.1"
PORT = 6969

# Engine struct offsets (verified live; see memory/m6-tank-physics-drive-recipe).
ENT_POS = 0x0C      # float[3]
ENT_ROT = 0x30      # float[3] euler radians
ENT_OID = 0xB4      # i32
ENT_PHYSOBJ = 0xBC  # ptr
ENT_HEALTH = 0xD0   # float

# Engine world list walk: DAT_006785e4 -> WorldMap; [WorldMap+0] -> Util_List
# (count@+0, head@+4); node {next@+0, data@+8}.
WORLD_MAP_PTR = 0x006785E4
LIST_HEAD = 4
NODE_NEXT = 0
NODE_ENTITY = 8


# --- pure number helpers ----------------------------------------------------

def parse_addr(text: str) -> int:
    """Parse an address as hex, with or without a 0x prefix."""
    text = text.strip().lower()
    if text.startswith("0x"):
        text = text[2:]
    return int(text, 16)


def f32_to_hex(value: float) -> str:
    """float -> little-endian 4-byte hex (wire/poke order)."""
    return struct.pack("<f", value).hex()


def hex_to_f32(text: str) -> float:
    return struct.unpack("<f", bytes.fromhex(text))[0]


def to_fixed1616(value: float) -> str:
    """float -> fixed16.16 raw as little-endian hex."""
    raw = int(round(value * 65536.0)) & 0xFFFFFFFF
    return struct.pack("<I", raw).hex()


def from_fixed1616(text: str) -> float:
    raw = struct.unpack("<I", bytes.fromhex(text))[0]
    if raw >= 0x80000000:
        raw -= 0x100000000
    return raw / 65536.0


def parse_dump(text: str) -> bytes:
    """Reconstruct raw bytes from the dev console's 'ADDR: aa bb .. |ascii|' dump lines."""
    out = bytearray()
    for line in text.splitlines():
        match = re.match(r"\s*0x[0-9a-fA-F]+:\s*(.*?)\s*\|", line)
        if not match:
            continue
        for token in match.group(1).split():
            if re.fullmatch(r"[0-9a-fA-F]{2}", token):
                out.append(int(token, 16))
    return bytes(out)


# --- dev-console client -----------------------------------------------------

class Dev:
    def __init__(self, host: str = HOST, port: int = PORT, idle: float = 0.35):
        self.idle = idle
        self.sock = socket.create_connection((host, port), timeout=3.0)
        self._read()  # consume the connect banner

    def _read(self) -> str:
        self.sock.settimeout(self.idle)
        chunks: list[bytes] = []
        try:
            while True:
                chunk = self.sock.recv(8192)
                if not chunk:
                    break
                chunks.append(chunk)
        except socket.timeout:
            pass
        return b"".join(chunks).decode("ascii", "replace")

    def cmd(self, line: str) -> str:
        self.sock.sendall((line + "\n").encode("ascii"))
        return self._read()

    def peek(self, addr: int, length: int) -> bytes:
        resp = self.cmd(f"peek 0x{addr:08x} {length}")
        data = parse_dump(resp)
        if not data:
            raise RuntimeError(f"peek 0x{addr:08x} {length} -> {resp.strip()!r}")
        return data

    def poke(self, addr: int, data: bytes) -> str:
        return self.cmd(f"poke 0x{addr:08x} {data.hex()}").strip()

    def read_u32(self, addr: int) -> int:
        return struct.unpack("<I", self.peek(addr, 4))[0]

    def read_i32(self, addr: int) -> int:
        return struct.unpack("<i", self.peek(addr, 4))[0]

    def read_f32(self, addr: int) -> float:
        return struct.unpack("<f", self.peek(addr, 4))[0]

    def read_fixed1616(self, addr: int) -> float:
        return self.read_i32(addr) / 65536.0

    def write_u32(self, addr: int, value: int) -> str:
        return self.poke(addr, struct.pack("<I", value & 0xFFFFFFFF))

    def write_f32(self, addr: int, value: float) -> str:
        return self.poke(addr, struct.pack("<f", value))

    def write_fixed1616(self, addr: int, value: float) -> str:
        return self.write_u32(addr, int(round(value * 65536.0)) & 0xFFFFFFFF)

    def deref_chain(self, base: int, *offsets: int) -> int:
        """Follow a pointer chain: read u32 at base, add next offset, deref, ... and
        return the FINAL address (base + last offset, after dereferencing the earlier
        ones). With no offsets, returns base."""
        addr = base
        for off in offsets[:-1]:
            addr = self.read_u32(addr + off)
        return addr + (offsets[-1] if offsets else 0)

    def world_entities(self, cap: int = 64) -> list:
        """Walk the engine's authoritative world list and decode each entity."""
        world_map = self.read_u32(WORLD_MAP_PTR)
        if world_map == 0:
            return []
        lst = self.read_u32(world_map)
        if lst == 0:
            return []
        count = self.read_u32(lst)
        node = self.read_u32(lst + LIST_HEAD)
        out: list = []
        steps = 0
        while node != 0 and steps < min(count, cap):
            ent = self.read_u32(node + NODE_ENTITY)
            if ent != 0:
                out.append(self.entity(ent))
            node = self.read_u32(node + NODE_NEXT)
            steps += 1
        return out

    def entity(self, ent: int) -> dict:
        return {
            "addr": f"0x{ent:08x}",
            "oid": self.read_i32(ent + ENT_OID),
            "pos": [round(self.read_f32(ent + ENT_POS + 4 * i), 3) for i in range(3)],
            "rot": [round(self.read_f32(ent + ENT_ROT + 4 * i), 4) for i in range(3)],
            "health": round(self.read_f32(ent + ENT_HEALTH), 2),
            "physObj": f"0x{self.read_u32(ent + ENT_PHYSOBJ):08x}",
        }


# --- CLI --------------------------------------------------------------------

def _conv(args: list[str]) -> int:
    op = args[0]
    val = args[1]
    if op == "f2h":
        print(f32_to_hex(float(val)))
    elif op == "h2f":
        print(hex_to_f32(val))
    elif op == "tofixed":
        print(to_fixed1616(float(val)))
    elif op == "fromfixed":
        print(from_fixed1616(val))
    else:
        print(f"unknown conv op '{op}' (f2h/h2f/tofixed/fromfixed)", file=sys.stderr)
        return 2
    return 0


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(__doc__)
        return 1
    op = argv[1]
    rest = argv[2:]

    if op == "conv":
        return _conv(rest)

    dev = Dev()
    if op == "peek":
        length = int(rest[1], 0)  # accept decimal or 0x-hex length
        print(dev.cmd(f"peek 0x{parse_addr(rest[0]):08x} {length}").rstrip())
    elif op == "raw":
        print(dev.cmd(rest[0]).rstrip())
    elif op == "bt":
        print(dev.cmd("bt").rstrip())
    elif op == "call":
        # call <addr> <conv> [hexargs...]  (executed on the engine tick thread)
        print(dev.cmd("call " + " ".join(rest)).rstrip())
    elif op == "u32":
        v = dev.read_u32(parse_addr(rest[0]))
        print(f"0x{v:08x} ({v})")
    elif op == "i32":
        print(dev.read_i32(parse_addr(rest[0])))
    elif op == "f32":
        print(dev.read_f32(parse_addr(rest[0])))
    elif op == "fixed":
        print(dev.read_fixed1616(parse_addr(rest[0])))
    elif op == "ptr":
        print(f"0x{dev.read_u32(parse_addr(rest[0])):08x}")
    elif op == "deref":
        offs = [parse_addr(x) for x in rest[1:]]
        addr = dev.deref_chain(parse_addr(rest[0]), *offs)
        print(f"0x{addr:08x}")
    elif op == "entity":
        info = dev.entity(parse_addr(rest[0]))
        for key, value in info.items():
            print(f"  {key}: {value}")
    elif op == "world":
        ents = dev.world_entities()
        print(f"{len(ents)} engine entit{'y' if len(ents) == 1 else 'ies'}")
        for ent in ents:
            print(f"  {ent}")
    elif op == "poke":
        print(dev.poke(parse_addr(rest[0]), bytes.fromhex(rest[1])))
    elif op == "write-f32":
        print(dev.write_f32(parse_addr(rest[0]), float(rest[1])))
    elif op == "write-fixed":
        print(dev.write_fixed1616(parse_addr(rest[0]), float(rest[1])))
    elif op == "write-u32":
        print(dev.write_u32(parse_addr(rest[0]), parse_addr(rest[1])))
    else:
        print(f"unknown op '{op}'", file=sys.stderr)
        print(__doc__)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
