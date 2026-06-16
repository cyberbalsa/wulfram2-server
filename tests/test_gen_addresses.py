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
