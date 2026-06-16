#include "wfh/server/entity_snapshot.hpp"

#include <array>
#include <cstring>

namespace wfh::server {

namespace {

// Alignment- and aliasing-safe little-endian reads from the entity buffer. The
// engine is x86 (LE), so a raw memcpy reproduces the in-memory value exactly. The
// byte-offset read is inherently pointer arithmetic over the caller's buffer.
auto ReadI32(const std::uint8_t* base, std::size_t offset) -> std::int32_t {
    std::int32_t value = 0;
    // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    std::memcpy(&value, base + offset, sizeof(value));
    return value;
}

auto ReadF32(const std::uint8_t* base, std::size_t offset) -> float {
    float value = 0.0F;
    // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    std::memcpy(&value, base + offset, sizeof(value));
    return value;
}

// Read three consecutive floats (a vec3) starting at `offset`.
auto ReadVec3(const std::uint8_t* base, std::size_t offset) -> std::array<float, 3> {
    return {ReadF32(base, offset), ReadF32(base, offset + sizeof(float)),
            ReadF32(base, offset + (2 * sizeof(float)))};
}

}  // namespace

auto ExtractEntitySnapshot(const std::uint8_t* entity) -> MvpEntitySnapshot {
    using Off = EntitySnapshotOffsets;
    MvpEntitySnapshot snap;
    snap.net_id = ReadI32(entity, Off::oid);
    snap.unit_type = ReadI32(entity, Off::unit_type);
    snap.team = ReadI32(entity, Off::team);
    snap.pos = ReadVec3(entity, Off::pos_x);
    snap.vel = ReadVec3(entity, Off::vel_x);
    snap.rot = ReadVec3(entity, Off::rot_x);
    snap.health = ReadF32(entity, Off::health);
    snap.energy = ReadF32(entity, Off::energy);
    return snap;
}

}  // namespace wfh::server
