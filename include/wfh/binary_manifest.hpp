// NOLINTBEGIN(portability-avoid-pragma-once)
// pragma once is the project-wide include-guard convention; intentional.
#pragma once
// NOLINTEND(portability-avoid-pragma-once)
#include <cstdint>

namespace wfh {

// One expected byte signature at a known address (opening bytes of a hooked/called fn).
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
