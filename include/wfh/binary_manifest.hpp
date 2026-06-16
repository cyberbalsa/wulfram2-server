// NOLINTBEGIN(portability-avoid-pragma-once)
// pragma once is the project-wide include-guard convention; intentional.
#pragma once
// NOLINTEND(portability-avoid-pragma-once)
#include <cstdint>

namespace wfh {

// One expected byte signature at a known address (opening bytes of a hooked/called fn).
// Field order is the fixed ABI the generated kSites[] table is emitted against
// (name, address, bytes, length); we keep it stable rather than reorder for the
// analyzer's preferred packing, so the tail padding on 64-bit builds is intentional.
// This optin.performance.Padding diagnostic only fires now that the real manifest
// instantiates HookSite objects (previously sites was always nullptr).
// NOLINTNEXTLINE(clang-analyzer-optin.performance.Padding)
struct HookSite {
    const char* name;
    std::uint32_t address;      // absolute VA (image base 0x00400000)
    const std::uint8_t* bytes;  // expected opening bytes
    std::uint32_t length;
};

// Whole-binary identity manifest, emitted by gen_addresses.py into binary_manifest.h (Task 5).
struct BinaryManifest {
    std::uint32_t time_date_stamp;
    std::uint32_t size_of_image;
    std::uint32_t check_sum;
    std::uint32_t image_base;
    const HookSite* sites;
    std::uint32_t site_count;
};

}  // namespace wfh
