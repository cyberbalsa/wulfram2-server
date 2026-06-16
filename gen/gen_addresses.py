#!/usr/bin/env python3
"""Generate addresses.h and binary_manifest.h for the headless build.

Reads a name->address table (TAB-separated) plus the target PE32 exe and emits
two committed headers under --out:

  addresses.h        -- constexpr std::uint32_t <name> = 0x...; in wfh::addr
  binary_manifest.h  -- inline constexpr wfh::BinaryManifest kBinaryManifest{...}
                        with the target exe's real PE identity.

Hook-site byte capture (--hook-bytes N, N>0) reads the first N opening bytes of
each function named in --hook-sites directly from the PE file on disk. For a
function VA we compute RVA = VA - image_base, find the containing section, then
file_offset = RVA - VirtualAddress + PointerToRawData, and read N bytes there.
Those bytes are emitted as per-site `inline constexpr std::uint8_t kSite_<name>[]`
arrays plus an `inline constexpr HookSite kSites[]` table referenced by
kBinaryManifest. With --hook-bytes 0 (or no --hook-sites) the manifest keeps the
sites=nullptr, site_count=0 path.
"""
import argparse
import shutil
import struct
import subprocess
import sys
from pathlib import Path


def eprint(*args):
    print(*args, file=sys.stderr)


def parse_tsv(path):
    """Parse name<TAB>0xADDR rows. Skip blanks and an optional header row."""
    table = {}
    for raw in Path(path).read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line:
            continue
        parts = line.split("\t")
        if len(parts) < 2:
            # Tolerate stray whitespace-separated rows too.
            parts = line.split()
        if len(parts) < 2:
            continue
        name, addr = parts[0].strip(), parts[1].strip()
        # Skip an optional "name<TAB>address" header row.
        if name.lower() == "name" and not addr.lower().startswith("0x"):
            continue
        try:
            value = int(addr, 0)
        except ValueError:
            eprint(f"warning: skipping unparseable address for {name!r}: {addr!r}")
            continue
        table[name] = value
    return table


def read_pe_stamps(path):
    """Return (time_date_stamp, size_of_image, check_sum, image_base) as uint32s."""
    data = Path(path).read_bytes()
    if len(data) < 0x40 or data[0:2] != b"MZ":
        raise ValueError(f"{path}: not an MZ/DOS image")
    (e_lfanew,) = struct.unpack_from("<I", data, 0x3C)
    # Normal, well-formed PEs put 'PE\0\0' exactly at e_lfanew. Some hand-crafted
    # images carry an e_lfanew that does not match where the NT headers were
    # actually placed; in that case locate the signature directly so we still read
    # the genuine COFF/Optional header fields rather than zeroed DOS-stub bytes.
    pe_off = e_lfanew
    if not (pe_off + 4 <= len(data) and data[pe_off:pe_off + 4] == b"PE\x00\x00"):
        pe_off = data.find(b"PE\x00\x00", 0x40)
        if pe_off < 0:
            raise ValueError(
                f"{path}: missing 'PE\\0\\0' signature (e_lfanew={e_lfanew:#x})")
    if pe_off + 24 + 0x44 > len(data):
        raise ValueError(f"{path}: truncated; PE header at {pe_off:#x} out of range")
    # COFF FileHeader TimeDateStamp is at pe_off + 8.
    (time_date_stamp,) = struct.unpack_from("<I", data, pe_off + 8)
    # OptionalHeader begins at pe_off + 24 (4 sig + 20 file header). PE32 offsets:
    opt = pe_off + 24
    (image_base,) = struct.unpack_from("<I", data, opt + 28)
    (size_of_image,) = struct.unpack_from("<I", data, opt + 56)
    (check_sum,) = struct.unpack_from("<I", data, opt + 64)
    return time_date_stamp, size_of_image, check_sum, image_base


def _locate_pe_header(data, path):
    """Return the file offset of the 'PE\\0\\0' signature, mirroring read_pe_stamps."""
    if len(data) < 0x40 or data[0:2] != b"MZ":
        raise ValueError(f"{path}: not an MZ/DOS image")
    (e_lfanew,) = struct.unpack_from("<I", data, 0x3C)
    pe_off = e_lfanew
    if not (pe_off + 4 <= len(data) and data[pe_off:pe_off + 4] == b"PE\x00\x00"):
        pe_off = data.find(b"PE\x00\x00", 0x40)
        if pe_off < 0:
            raise ValueError(
                f"{path}: missing 'PE\\0\\0' signature (e_lfanew={e_lfanew:#x})")
    if pe_off + 24 + 0x44 > len(data):
        raise ValueError(f"{path}: truncated; PE header at {pe_off:#x} out of range")
    return pe_off


def read_pe_sections(path):
    """Return the list of section dicts {va, vsize, raw_size, ptr_raw} from the PE.

    Section headers are 40 bytes each, starting at e_lfanew + 24 + SizeOfOptionalHeader
    (4 sig + 20 COFF FileHeader + the optional header). NumberOfSections is the
    COFF FileHeader field at pe_off + 6. Per-header layout: Name[8], VirtualSize(u32@8),
    VirtualAddress(u32@12), SizeOfRawData(u32@16), PointerToRawData(u32@20).
    """
    data = Path(path).read_bytes()
    pe_off = _locate_pe_header(data, path)
    (num_sections,) = struct.unpack_from("<H", data, pe_off + 6)
    (size_of_optional,) = struct.unpack_from("<H", data, pe_off + 20)
    sec_off = pe_off + 24 + size_of_optional
    sections = []
    for i in range(num_sections):
        base = sec_off + i * 40
        if base + 40 > len(data):
            raise ValueError(f"{path}: truncated section header #{i}")
        (vsize,) = struct.unpack_from("<I", data, base + 8)
        (va,) = struct.unpack_from("<I", data, base + 12)
        (raw_size,) = struct.unpack_from("<I", data, base + 16)
        (ptr_raw,) = struct.unpack_from("<I", data, base + 20)
        sections.append({"va": va, "vsize": vsize, "raw_size": raw_size, "ptr_raw": ptr_raw})
    return sections


def capture_hook_bytes(path, image_base, sections, address, length):
    """Read `length` opening bytes of the function at absolute VA `address`.

    RVA = address - image_base. The containing section satisfies
    VirtualAddress <= RVA < VirtualAddress + max(VirtualSize, SizeOfRawData);
    then file_offset = RVA - VirtualAddress + PointerToRawData.
    """
    data = Path(path).read_bytes()
    if address < image_base:
        raise ValueError(f"VA {address:#x} is below image base {image_base:#x}")
    rva = address - image_base
    for sec in sections:
        span = max(sec["vsize"], sec["raw_size"])
        if sec["va"] <= rva < sec["va"] + span:
            file_off = rva - sec["va"] + sec["ptr_raw"]
            if file_off + length > len(data):
                raise ValueError(
                    f"file offset {file_off:#x}+{length} past EOF for VA {address:#x}")
            return data[file_off:file_off + length]
    raise ValueError(f"no section contains RVA {rva:#x} for VA {address:#x}")


BANNER = (
    "// GENERATED by gen/gen_addresses.py -- DO NOT EDIT.\n"
    "// Regenerate: python gen/gen_addresses.py --tsv ... --exe ... --wanted ... --out gen\n"
)


def emit_addresses(out_dir, table, wanted):
    lines = [BANNER]
    lines.append("#pragma once\n")
    lines.append("#include <cstdint>\n")
    lines.append("\n")
    lines.append("namespace wfh {\n")
    lines.append("namespace addr {\n")
    lines.append("\n")
    missing = [name for name in wanted if name not in table]
    if missing:
        eprint("error: wanted names absent from tsv: " + ", ".join(missing))
        sys.exit(2)
    for name in wanted:
        lines.append(f"constexpr std::uint32_t {name} = 0x{table[name]:08x};\n")
    lines.append("\n")
    lines.append("}  // namespace addr\n")
    lines.append("}  // namespace wfh\n")
    (Path(out_dir) / "addresses.h").write_text("".join(lines), encoding="utf-8")


def emit_manifest(out_dir, stamps, sites):
    """Emit binary_manifest.h. `sites` is a list of (name, address, bytes) tuples;
    when empty the manifest keeps the sites=nullptr, site_count=0 path."""
    time_date_stamp, size_of_image, check_sum, image_base = stamps
    lines = [BANNER]
    lines.append("#pragma once\n")
    lines.append('#include "wfh/binary_manifest.hpp"\n')
    lines.append("\n")
    lines.append("#include <cstdint>\n")
    lines.append("\n")
    lines.append("namespace wfh {\n")
    lines.append("\n")
    # `inline constexpr` (not `static constexpr`): `static` at namespace scope gives
    # every translation unit its own copy of the symbol; `inline` yields a single
    # shared definition across TUs, matching kBinaryManifest below.
    if sites:
        # One byte-signature array per site (real on-disk opening bytes), then a
        # single HookSite table referencing them. All `inline constexpr` so there is
        # exactly one definition across translation units.
        for name, _addr, raw in sites:
            byte_list = ", ".join(f"0x{b:02x}" for b in raw)
            lines.append(
                f"inline constexpr std::uint8_t kSite_{name}[] = {{ {byte_list} }};\n")
        lines.append("\n")
        lines.append("inline constexpr HookSite kSites[] = {\n")
        for name, addr, raw in sites:
            lines.append(
                f'    {{ "{name}", 0x{addr:08x}, kSite_{name}, {len(raw)} }},\n')
        lines.append("};\n")
        lines.append("\n")
        lines.append(
            "inline constexpr BinaryManifest kBinaryManifest{"
            f" 0x{time_date_stamp:08x}, 0x{size_of_image:08x},"
            f" 0x{check_sum:08x}, 0x{image_base:08x}, kSites, {len(sites)} }};\n"
        )
    else:
        lines.append("inline constexpr const HookSite* kSites = nullptr;\n")
        lines.append(
            "inline constexpr BinaryManifest kBinaryManifest{"
            f" 0x{time_date_stamp:08x}, 0x{size_of_image:08x},"
            f" 0x{check_sum:08x}, 0x{image_base:08x}, kSites, 0 }};\n"
        )
    lines.append("\n")
    lines.append("}  // namespace wfh\n")
    (Path(out_dir) / "binary_manifest.h").write_text("".join(lines), encoding="utf-8")


def clang_format_files(paths):
    """Run clang-format -i on the given files if the tool is on PATH.

    The repo's pre-commit hook rejects non-clang-format-clean headers. Running it
    here keeps generation idempotent with that gate. If clang-format is absent the
    output is still valid C++ (it compiles under /W4 /WX) -- only the cosmetic
    layout may differ.
    """
    exe = shutil.which("clang-format")
    if not exe:
        common = Path("C:/Program Files/LLVM/bin/clang-format.exe")
        exe = str(common) if common.exists() else None
    if not exe:
        eprint("note: clang-format not found; emitted headers are unformatted")
        return
    for p in paths:
        subprocess.run([exe, "-i", str(p)], check=False)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--tsv", required=True, help="name<TAB>0xADDR table")
    ap.add_argument("--exe", required=True, help="target PE32 exe to read stamps from")
    ap.add_argument("--wanted", required=True, help="names to emit (one per line)")
    ap.add_argument("--out", required=True, help="output directory")
    ap.add_argument("--hook-bytes", type=int, default=0,
                    help="opening bytes to capture per hook site (0 = none)")
    ap.add_argument("--hook-sites", default=None,
                    help="file listing function names to byte-capture (one per line)")
    args = ap.parse_args(argv)

    table = parse_tsv(args.tsv)
    wanted = [ln.strip() for ln in Path(args.wanted).read_text(encoding="utf-8").splitlines()
              if ln.strip()]
    try:
        stamps = read_pe_stamps(args.exe)
    except ValueError as exc:
        eprint(f"error: {exc}")
        return 2

    # Capture real opening bytes for each named hook site when requested. Without
    # --hook-sites or with --hook-bytes 0 the manifest keeps the nullptr/0 path.
    sites = []
    if args.hook_sites and args.hook_bytes and args.hook_bytes > 0:
        image_base = stamps[3]
        try:
            sections = read_pe_sections(args.exe)
        except ValueError as exc:
            eprint(f"error: {exc}")
            return 2
        site_names = [ln.strip()
                      for ln in Path(args.hook_sites).read_text(encoding="utf-8").splitlines()
                      if ln.strip()]
        missing = [n for n in site_names if n not in table]
        if missing:
            eprint("error: hook-site names absent from tsv: " + ", ".join(missing))
            return 2
        for name in site_names:
            addr = table[name]
            try:
                raw = capture_hook_bytes(args.exe, image_base, sections, addr, args.hook_bytes)
            except ValueError as exc:
                eprint(f"error: capturing {name} @ {addr:#x}: {exc}")
                return 2
            sites.append((name, addr, raw))

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    emit_addresses(out_dir, table, wanted)
    emit_manifest(out_dir, stamps, sites)
    # Normalize with clang-format if available so the committed headers match the
    # repo's pre-commit format gate exactly (idempotent regeneration).
    clang_format_files(
        [out_dir / "addresses.h", out_dir / "binary_manifest.h"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
