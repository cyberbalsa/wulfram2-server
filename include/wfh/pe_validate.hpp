// NOLINTBEGIN(portability-avoid-pragma-once)
// pragma once is the project-wide include-guard convention; intentional.
#pragma once
// NOLINTEND(portability-avoid-pragma-once)
#include <cstdint>
#include <filesystem>
#include <string>

#include "wfh/binary_manifest.hpp"

namespace wfh {

struct PeHeaderFacts {
    std::uint32_t time_date_stamp = 0;
    std::uint32_t size_of_image = 0;
    std::uint32_t check_sum = 0;
    std::uint32_t image_base = 0;
};

struct ValidateResult {
    bool ok = false;
    std::string error;
};

struct ReadFactsResult {
    bool ok = false;
    std::string error;
    PeHeaderFacts facts;
};
auto ReadPeHeaderFacts(const std::filesystem::path& exe_path) -> ReadFactsResult;

auto ValidateHeaders(const PeHeaderFacts& actual, const BinaryManifest& expected) -> ValidateResult;
auto CompareBytes(const std::uint8_t* actual, const std::uint8_t* expected, std::uint32_t length)
    -> ValidateResult;

// In-process (DLL-side): verify every manifest hook-site's opening bytes in live memory.
auto ValidateHookSitesInProcess(const BinaryManifest& manifest) -> ValidateResult;

}  // namespace wfh
