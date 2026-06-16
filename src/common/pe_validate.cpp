#include "wfh/pe_validate.hpp"

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

    // PE parsing requires reinterpreting the raw file bytes as the on-disk header
    // structs. Every dereference below is guarded by an explicit bounds check.
    // cppcheck-suppress invalidPointerCast  # intentional PE header overlay
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(buf.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        out.error = "not a DOS image";
        return out;
    }
    // e_lfanew is a signed LONG; reject negatives before widening to size_t so a
    // hostile/corrupt file cannot wrap the offset arithmetic.
    if (dos->e_lfanew < 0) {
        out.error = "bad e_lfanew";
        return out;
    }
    const auto nt_off = static_cast<std::size_t>(dos->e_lfanew);
    if (nt_off > buf.size() || sizeof(IMAGE_NT_HEADERS32) > buf.size() - nt_off) {
        out.error = "bad e_lfanew";
        return out;
    }

    // buf.data() + nt_off is a bounds-checked overlay of the NT headers onto the file image.
    // cppcheck-suppress invalidPointerCast  # intentional PE header overlay
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast,cppcoreguidelines-pro-bounds-pointer-arithmetic)
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS32*>(buf.data() + nt_off);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        out.error = "not a PE image";
        return out;
    }
    if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_I386) {
        out.error = "not an x86 image";
        return out;
    }

    out.facts.time_date_stamp = nt->FileHeader.TimeDateStamp;
    out.facts.size_of_image = nt->OptionalHeader.SizeOfImage;
    out.facts.check_sum = nt->OptionalHeader.CheckSum;
    out.facts.image_base = nt->OptionalHeader.ImageBase;
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
    if (std::memcmp(actual, expected, length) != 0) {
        return {false, "hook-site byte mismatch"};
    }
    return {true, {}};
}

auto ValidateHookSitesInProcess(const BinaryManifest& manifest) -> ValidateResult {
    for (std::uint32_t i = 0; i < manifest.site_count; ++i) {
        // sites is a contiguous C array emitted by the generator; index access is intended.
        // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        const HookSite& site = manifest.sites[i];
        // Read the live opening bytes at the site's fixed absolute VA. Reinterpreting a
        // hardcoded address as a byte pointer is the whole point of in-process pinning.
        const auto site_va = static_cast<std::uintptr_t>(site.address);
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
