#include "wfh/pe_validate.hpp"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iterator>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

namespace wfh {

auto ReadPeHeaderFacts(const std::filesystem::path& exe_path) -> ReadFactsResult {
    ReadFactsResult out;
    std::ifstream in(exe_path, std::ios::binary);
    if (!in) {
        out.error = "cannot open exe";
        return out;
    }
    std::vector<char> buf((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    if (buf.size() < sizeof(IMAGE_DOS_HEADER)) {
        out.error = "file too small";
        return out;
    }

    // Copy each header into a properly aligned local before reading fields. The file is
    // buffered as char[], so overlaying a header struct with reinterpret_cast would alias
    // and (at e_lfanew offsets) misalign it — undefined behavior. memcpy after a bounds
    // check is the portable, alignment-safe way to parse on-disk PE structures.
    IMAGE_DOS_HEADER dos{};
    std::memcpy(&dos, buf.data(), sizeof(dos));
    if (dos.e_magic != IMAGE_DOS_SIGNATURE) {
        out.error = "not a DOS image";
        return out;
    }
    // e_lfanew is a signed LONG; reject negatives before widening to size_t so a
    // hostile/corrupt file cannot wrap the offset arithmetic.
    if (dos.e_lfanew < 0) {
        out.error = "bad e_lfanew";
        return out;
    }
    const auto nt_off = static_cast<std::size_t>(dos.e_lfanew);
    if (nt_off > buf.size() || sizeof(IMAGE_NT_HEADERS32) > buf.size() - nt_off) {
        out.error = "bad e_lfanew";
        return out;
    }

    // nt_off is bounds-checked above to leave room for a full IMAGE_NT_HEADERS32.
    IMAGE_NT_HEADERS32 nt{};
    // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    std::memcpy(&nt, buf.data() + nt_off, sizeof(nt));
    if (nt.Signature != IMAGE_NT_SIGNATURE) {
        out.error = "not a PE image";
        return out;
    }
    if (nt.FileHeader.Machine != IMAGE_FILE_MACHINE_I386) {
        out.error = "not an x86 image";
        return out;
    }
    // Machine == I386 does not by itself prove the optional header uses the PE32 layout
    // whose field offsets we trust below. Require the PE32 optional-header magic, and
    // require the file header to actually declare an optional header large enough to
    // contain every field we read (CheckSum is the last/highest such field).
    if (nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        out.error = "not a PE32 image";
        return out;
    }
    if (nt.FileHeader.SizeOfOptionalHeader <
        offsetof(IMAGE_OPTIONAL_HEADER32, CheckSum) + sizeof(nt.OptionalHeader.CheckSum)) {
        out.error = "optional header too small";
        return out;
    }

    out.facts.time_date_stamp = nt.FileHeader.TimeDateStamp;
    out.facts.size_of_image = nt.OptionalHeader.SizeOfImage;
    out.facts.check_sum = nt.OptionalHeader.CheckSum;
    out.facts.image_base = nt.OptionalHeader.ImageBase;
    out.ok = true;
    return out;
}

auto ValidateHeaders(const PeHeaderFacts& actual, const BinaryManifest& expected)
    -> ValidateResult {
    if (actual.time_date_stamp != expected.time_date_stamp) {
        return {false, "PE TimeDateStamp mismatch (wrong wulfram2.exe build)"};
    }
    if (actual.size_of_image != expected.size_of_image) {
        return {false, "PE SizeOfImage mismatch"};
    }
    if (actual.check_sum != expected.check_sum) {
        return {false, "PE CheckSum mismatch"};
    }
    if (actual.image_base != expected.image_base) {
        return {false, "PE ImageBase mismatch (relocation?)"};
    }
    return {true, {}};
}

auto CompareBytes(const std::uint8_t* actual, const std::uint8_t* expected, std::uint32_t length)
    -> ValidateResult {
    if (length == 0) {
        return {true, {}};
    }
    if (actual == nullptr || expected == nullptr) {
        return {false, "hook-site byte compare with null pointer"};
    }
    if (std::memcmp(actual, expected, length) != 0) {
        return {false, "hook-site byte mismatch"};
    }
    return {true, {}};
}

namespace {
// True only if [address, address+length) is entirely committed and readable in this
// process. Reading an unmapped/guarded/cross-page-unmapped VA would otherwise fault — and
// a wrong target (the very case this validator exists to catch) is exactly when that
// happens. Returns false instead of crashing the host process.
auto IsRangeReadable(std::uintptr_t address, std::uint32_t length) -> bool {
    if (length == 0) {
        return true;
    }
    // Guard against address + length wrapping the pointer width.
    if (address > UINTPTR_MAX - length) {
        return false;
    }
    const std::uintptr_t end = address + length;
    std::uintptr_t cursor = address;
    while (cursor < end) {
        MEMORY_BASIC_INFORMATION mbi{};
        // NOLINTNEXTLINE(performance-no-int-to-ptr,cppcoreguidelines-pro-type-reinterpret-cast)
        if (VirtualQuery(reinterpret_cast<LPCVOID>(cursor), &mbi, sizeof(mbi)) == 0) {
            return false;
        }
        if (mbi.State != MEM_COMMIT) {
            return false;
        }
        constexpr DWORD kReadable = PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ |
                                    PAGE_EXECUTE_READWRITE | PAGE_WRITECOPY |
                                    PAGE_EXECUTE_WRITECOPY;
        if ((mbi.Protect & kReadable) == 0 || (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) != 0) {
            return false;
        }
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        const auto region_base = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
        cursor = region_base + mbi.RegionSize;
    }
    return true;
}
}  // namespace

auto ValidateHookSitesInProcess(const BinaryManifest& manifest) -> ValidateResult {
    for (std::uint32_t i = 0; i < manifest.site_count; ++i) {
        // sites is a contiguous C array emitted by the generator; index access is intended.
        // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        const HookSite& site = manifest.sites[i];
        const auto site_va = static_cast<std::uintptr_t>(site.address);
        // Confirm the range is mapped+readable before touching it so a stale/wrong manifest
        // fail-stops the comparison instead of faulting the process.
        if (!IsRangeReadable(site_va, site.length)) {
            std::string err = "hook-site unreadable at ";
            err += site.name != nullptr ? site.name : "?";
            return {false, err};
        }
        // Read the live opening bytes at the site's fixed absolute VA. Reinterpreting a
        // hardcoded address as a byte pointer is the whole point of in-process pinning.
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast,performance-no-int-to-ptr)
        const auto* mem = reinterpret_cast<const std::uint8_t*>(site_va);
        const auto res = CompareBytes(mem, site.bytes, site.length);
        if (!res.ok) {
            std::string err = "hook-site mismatch at ";
            err += site.name != nullptr ? site.name : "?";
            return {false, err};
        }
    }
    return {true, {}};
}

}  // namespace wfh
