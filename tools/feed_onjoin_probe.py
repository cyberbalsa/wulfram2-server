#!/usr/bin/env python3
"""Live dev-console probe: feed the server's own BEHAVIOR (and optionally TRANSLATION)
body through the engine's CLIENT-side on-join handlers, exactly as the engine's own
receive path does (Net_ProcessOrderedReceiveQueue @ 0x504a2c):

    membuf = _malloc(0x20)
    body   = _malloc(len);  poke body bytes
    BitBuf_ConstructWithChunk(membuf, mode=1, body, len, owner=0)   # thiscall, ECX=membuf
    Net_HandleBehavior(0, 0, membuf)                                # cdecl, packet=membuf
    MemBuff_FreeAllHunks(membuf);  _free(membuf)                    # cleanup (mirrors recv)

This populates the vehicle tuning the thrust step reads (the headless server booted a
world but never "joined", so its tuning was all zero -> thrust = 0). See
memory/m6-tank-physics-drive-recipe + the RE workflow re-membuff-onjoin.

The body bytes come from behavior_body.bin / translation_body.bin (dumped by the
DISABLED gtest BringupPackets.DISABLED_DumpOnJoinBodies). Requires world_host=true and
the dev console live on :6969.

Usage:
  python tools/feed_onjoin_probe.py behavior     # feed BEHAVIOR only (default), with before/after
  python tools/feed_onjoin_probe.py translation  # ALSO feed TRANSLATION (needs DAT_006782e4 valid!)
"""
from __future__ import annotations

import os
import re
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from dev_poke import Dev  # noqa: E402

# --- engine VAs (verified from Ghidra; wulfram2.exe base 0x400000) -----------
MALLOC = 0x0050C8EB             # void* __cdecl _malloc(size_t)
FREE = 0x0050C292              # void  __cdecl _free(void*)
CONSTRUCT = 0x00508A50         # BitBuf_ConstructWithChunk __thiscall(this, mode, data, len, owner) RET 0x10
FREE_ALL_HUNKS = 0x00509A30    # MemBuff_FreeAllHunks __thiscall(this)
HANDLE_BEHAVIOR = 0x0046DC00   # void __cdecl Net_HandleBehavior(p1, p2, packet)
HANDLE_TRANSLATION = 0x0046E980  # void __cdecl Net_HandleTranslationTable(p1, p2, packet)

# verification anchors (from the re-membuff-onjoin workflow)
BEHAVIOR_SCALAR_BLOCK = 0x00679170  # 11 floats + doubles written directly by Net_HandleBehavior
MODEL_LIST_HEAD = 0x005C41C8        # DAT_005c41c8 -> model list (node{next@0,data@8})
TUNING_OBJ_PTR = 0x0067CD58         # DAT_0067cd58 -> tuning-table object pointer
THROTTLE_SLOT_OFF = 0xD8            # slot6 raw float within the slot-array base
THRUST_SLOT_OFF = 0xF8              # slot7 raw float


def eax(resp: str) -> int:
    m = re.search(r"eax=0x([0-9a-fA-F]+)", resp)
    if not m:
        raise RuntimeError(f"call did not return eax: {resp.strip()!r}")
    return int(m.group(1), 16)


def call(dev: Dev, addr: int, conv: str, *args: int) -> str:
    line = f"call 0x{addr:x} {conv}"
    for a in args:
        line += f" 0x{a & 0xFFFFFFFF:x}"
    resp = dev.cmd(line)
    print(f"  $ {line}\n    -> {resp.strip()}")
    return resp


def emalloc(dev: Dev, size: int) -> int:
    ptr = eax(call(dev, MALLOC, "cdecl", size))
    if ptr == 0:
        raise RuntimeError(f"_malloc({size}) returned NULL")
    return ptr


def feed(dev: Dev, body: bytes, handler: int, name: str) -> None:
    print(f"\n=== feeding {name} ({len(body)} bytes) through handler 0x{handler:x} ===")
    data = emalloc(dev, len(body))
    print(f"  body buffer = 0x{data:08x}")
    poke_resp = dev.poke(data, body)
    print(f"  poke body -> {poke_resp}")
    membuf = emalloc(dev, 0x20)
    print(f"  membuf = 0x{membuf:08x}")
    call(dev, CONSTRUCT, "thiscall", membuf, 1, data, len(body), 0)
    call(dev, handler, "cdecl", 0, 0, membuf)
    # cleanup mirrors the engine recv path
    call(dev, FREE_ALL_HUNKS, "thiscall", membuf)
    call(dev, FREE, "cdecl", membuf)


def hexword(dev: Dev, addr: int) -> int:
    return dev.read_u32(addr)


def read_doubles(dev: Dev, addr: int, count: int) -> list[float]:
    raw = dev.peek(addr, count * 8)
    return [struct.unpack_from("<d", raw, i * 8)[0] for i in range(count)]


def snapshot(dev: Dev, tag: str) -> None:
    print(f"\n--- tuning snapshot [{tag}] ---")
    block = dev.peek(BEHAVIOR_SCALAR_BLOCK, 0x40)
    nz = sum(1 for b in block if b != 0)
    floats = [struct.unpack_from("<f", block, 0x10 + i * 4)[0] for i in range(11)]
    print(f"  0x679170 block: {nz}/64 non-zero bytes; "
          f"floats@+0x10: {[round(f, 4) for f in floats]}")

    obj = hexword(dev, TUNING_OBJ_PTR)
    print(f"  *(0x67cd58) tuning-obj ptr = 0x{obj:08x}")
    if obj:
        lvl2 = hexword(dev, obj)
        print(f"  *(0x67cd58) -> *[0] = 0x{lvl2:08x}")
        for label, base in (("*(obj)", obj), ("*(*(obj))", lvl2)):
            if base and 0x100000 < base < 0x7FFFFFFF:
                try:
                    thr = struct.unpack("<f", dev.peek(base + THROTTLE_SLOT_OFF, 4))[0]
                    tru = struct.unpack("<f", dev.peek(base + THRUST_SLOT_OFF, 4))[0]
                    print(f"    [{label}=0x{base:08x}] +0xD8 throttle={thr:.4f}  +0xF8 thrust={tru:.4f}")
                except Exception as exc:  # noqa: BLE001
                    print(f"    [{label}=0x{base:08x}] peek failed: {exc}")

    head = hexword(dev, MODEL_LIST_HEAD)
    print(f"  model list head *(0x5c41c8) = 0x{head:08x}")
    if head:
        model = hexword(dev, head + 8)  # node.data
        print(f"    first model record = 0x{model:08x}")
        if model:
            cfg = read_doubles(dev, model + 0x10, 7)
            print(f"    model+0x10 config doubles = {[round(d, 4) for d in cfg]}")


def main(argv: list[str]) -> int:
    mode = argv[1] if len(argv) > 1 else "behavior"
    here = os.path.dirname(os.path.abspath(__file__))
    root = os.path.dirname(here)
    beh = open(os.path.join(root, "behavior_body.bin"), "rb").read()

    dev = Dev()
    print(f"connected to dev console; mode={mode}")
    print(f"model registry live? *(0x5c41c8) = 0x{hexword(dev, MODEL_LIST_HEAD):08x} "
          f"(non-zero => VehicleModel_InitAll ran)")

    snapshot(dev, "BEFORE")
    feed(dev, beh, HANDLE_BEHAVIOR, "BEHAVIOR")
    if mode == "translation":
        tr = open(os.path.join(root, "translation_body.bin"), "rb").read()
        print(f"\n!! DAT_006782e4 (send obj for the 0x33 ACK) = 0x{hexword(dev, 0x006782e4):08x} "
              f"-- if 0, the ACK send may fault")
        feed(dev, tr, HANDLE_TRANSLATION, "TRANSLATION")
    snapshot(dev, "AFTER")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
