// NOLINTBEGIN(portability-avoid-pragma-once)
// pragma once is the project-wide include-guard convention; intentional.
#pragma once
// NOLINTEND(portability-avoid-pragma-once)

#include "wfh/server/world_packets.hpp"  // MvpEntitySnapshot

#include <cstddef>
#include <cstdint>

namespace wfh::server {

// Size of the engine's entity struct (operator_new(0x170) + Entity_Construct).
constexpr std::size_t kEngineEntitySize = 0x170;

// Verified byte offsets into the engine entity struct (M5.0 data contract). Named
// static-constexpr members so the literals live in named constants (not flagged as
// magic numbers) and the extractor + its test share one source of truth.
struct EntitySnapshotOffsets {
    static constexpr std::size_t unit_type = 0x08;  // i32 type id
    static constexpr std::size_t pos_x = 0x0c;      // f32 x; y@+0x10, z@+0x14
    static constexpr std::size_t vel_x = 0x18;      // f32 engine-produced velocity
    static constexpr std::size_t rot_x = 0x30;      // f32 euler orientation
    static constexpr std::size_t oid = 0xb4;        // i32 object id (init 0xffffffff)
    static constexpr std::size_t health = 0xd0;     // f32 absolute health
    static constexpr std::size_t energy = 0xd4;     // f32 absolute energy/fuel
    static constexpr std::size_t team = 0xf0;       // i32 team id
};

// Read an engine entity struct (kEngineEntitySize bytes) into a by-value snapshot,
// pulling each field from its verified offset. Pure + alignment-safe (memcpy), so it
// is host-testable with a synthetic buffer; the live world walk (engine glue) calls
// it per entity. `entity` must point to at least kEngineEntitySize readable bytes.
[[nodiscard]] auto ExtractEntitySnapshot(const std::uint8_t* entity) -> MvpEntitySnapshot;

}  // namespace wfh::server
