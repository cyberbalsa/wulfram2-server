import subprocess, sys, struct, pathlib
GEN = pathlib.Path(__file__).resolve().parents[1] / "gen" / "gen_addresses.py"

def make_min_pe(path):
    e_lfanew = 0x80
    dos = bytearray(0x100); dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, e_lfanew)
    nt = bytearray()
    nt += b"PE\x00\x00"
    # FileHeader: Machine=0x14C, NumSections=1, TimeDateStamp=0x11223344, ptr/sym=0, NumSyms=0, SizeOfOptHdr=0xE0, Chars=0x0102
    nt += struct.pack("<HHIIIHH", 0x14C, 1, 0x11223344, 0, 0, 0xE0, 0x0102)
    opt = bytearray(0xE0)
    struct.pack_into("<H", opt, 0, 0x10B)         # Magic = PE32
    struct.pack_into("<I", opt, 28, 0x00400000)   # ImageBase
    struct.pack_into("<I", opt, 56, 0x00300000)   # SizeOfImage
    struct.pack_into("<I", opt, 64, 0x000ABCDE)   # CheckSum
    nt += opt
    path.write_bytes(dos + nt)

def make_pe_with_text_section(path, func_bytes, func_rva=0x1010,
                              section_va=0x1000, ptr_raw=0x400, raw_size=0x1000):
    """Craft a PE32 with one real .text section and func_bytes laid at func_rva.

    Layout mirrors make_min_pe (e_lfanew=0x80, SizeOfOptionalHeader=0xE0) but
    appends one 40-byte section header after the optional header and writes the
    raw section data on disk at PointerToRawData. The function's bytes land at
    file_offset = func_rva - section_va + ptr_raw.
    """
    e_lfanew = 0x80
    dos = bytearray(0x80); dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, e_lfanew)
    nt = bytearray()
    nt += b"PE\x00\x00"
    # FileHeader: Machine=0x14C, NumSections=1, TimeDateStamp, 0,0, SizeOfOptHdr=0xE0, Chars
    nt += struct.pack("<HHIIIHH", 0x14C, 1, 0x11223344, 0, 0, 0xE0, 0x0102)
    opt = bytearray(0xE0)
    struct.pack_into("<H", opt, 0, 0x10B)         # Magic = PE32
    struct.pack_into("<I", opt, 28, 0x00400000)   # ImageBase
    struct.pack_into("<I", opt, 56, 0x00300000)   # SizeOfImage
    struct.pack_into("<I", opt, 64, 0x000ABCDE)   # CheckSum
    nt += opt
    # One section header (.text): Name[8], VirtualSize, VirtualAddress,
    # SizeOfRawData, PointerToRawData, then reloc/lineno/chars padding to 40 bytes.
    sec = bytearray(40)
    sec[0:5] = b".text"
    struct.pack_into("<I", sec, 8, raw_size)      # VirtualSize
    struct.pack_into("<I", sec, 12, section_va)   # VirtualAddress
    struct.pack_into("<I", sec, 16, raw_size)     # SizeOfRawData
    struct.pack_into("<I", sec, 20, ptr_raw)      # PointerToRawData
    nt += sec
    blob = bytearray(dos + nt)
    # Grow file to cover the raw section and drop func_bytes at the mapped offset.
    end = ptr_raw + raw_size
    if len(blob) < end:
        blob += bytearray(end - len(blob))
    file_off = func_rva - section_va + ptr_raw
    blob[file_off:file_off + len(func_bytes)] = bytes(func_bytes)
    path.write_bytes(blob)


def test_captures_hook_site_bytes(tmp_path):
    # func VA = image_base(0x00400000) + func_rva(0x1010) = 0x00401010
    func_bytes = [0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x10, 0x53, 0x56]
    tsv = tmp_path / "addrs.tsv"
    tsv.write_text("Client_RunMainLoop\t0x00401010\nSnd_InitDevice\t0x00401018\n")
    exe = tmp_path / "wulfram2.exe"
    # Snd_InitDevice at func_rva 0x1018 -> 8 distinct bytes right after.
    make_pe_with_text_section(exe, func_bytes + [0x57, 0x8B, 0xF1, 0x33, 0xC0, 0x90, 0x90, 0x90])
    wanted = tmp_path / "wanted.txt"; wanted.write_text("Client_RunMainLoop\nSnd_InitDevice\n")
    sites = tmp_path / "hook_sites.txt"; sites.write_text("Client_RunMainLoop\nSnd_InitDevice\n")
    out = tmp_path / "out"; out.mkdir()
    r = subprocess.run([sys.executable, str(GEN), "--tsv", str(tsv), "--exe", str(exe),
                        "--wanted", str(wanted), "--hook-sites", str(sites),
                        "--out", str(out), "--hook-bytes", "8"],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    manifest = (out / "binary_manifest.h").read_text()
    # Normalize whitespace so clang-format's line wrapping (it breaks long byte
    # lists across lines) does not make substring assertions brittle.
    flat = " ".join(manifest.split())
    low = flat.lower()
    # Per-site byte arrays (single cross-TU defs) and the kSites table must appear.
    assert "inline constexpr std::uint8_t kSite_Client_RunMainLoop[]" in flat, manifest
    assert "inline constexpr std::uint8_t kSite_Snd_InitDevice[]" in flat, manifest
    assert "inline constexpr HookSite kSites[]" in flat, manifest
    # The exact captured opening bytes must be present (in order).
    assert "0x55, 0x8b, 0xec, 0x83, 0xec, 0x10, 0x53, 0x56" in low, manifest
    # site_count == number of sites (2 here); nullptr path must be gone.
    assert "ksites, 2}" in low, manifest
    assert "ksites = nullptr" not in low
    # Names wired into the table.
    assert '"Client_RunMainLoop"' in flat


def test_generates_headers(tmp_path):
    tsv = tmp_path / "addrs.tsv"
    tsv.write_text("Client_RunMainLoop\t0x004a0aa0\nSnd_InitDevice\t0x00489fb0\n")
    exe = tmp_path / "wulfram2.exe"; make_min_pe(exe)
    wanted = tmp_path / "wanted.txt"; wanted.write_text("Client_RunMainLoop\nSnd_InitDevice\n")
    out = tmp_path / "out"; out.mkdir()
    r = subprocess.run([sys.executable, str(GEN), "--tsv", str(tsv), "--exe", str(exe),
                        "--wanted", str(wanted), "--out", str(out), "--hook-bytes", "0"],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    addr = (out / "addresses.h").read_text().lower()
    assert "0x004a0aa0" in addr and "client_runmainloop" in addr
    manifest = (out / "binary_manifest.h").read_text().lower()
    assert "0x11223344" in manifest and "0x00300000" in manifest and "kbinarymanifest" in manifest
    # kSites must be a single cross-TU definition (inline constexpr), not per-TU static.
    assert "inline constexpr const hooksite* ksites = nullptr;" in manifest
    assert "static constexpr const hooksite* ksites" not in manifest
