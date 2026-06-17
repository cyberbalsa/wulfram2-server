#include "wfh/server/entity_snapshot.hpp"

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <cstring>

namespace {

using wfh::server::EntitySnapshotOffsets;
using wfh::server::ExtractEntitySnapshot;
using wfh::server::kEngineEntitySize;
using wfh::server::MvpEntitySnapshot;

// A synthetic engine entity struct (0x170 bytes) with known values written at the
// verified field offsets, so the extractor can be tested without the live engine.
class FakeEntity {
public:
    void PutI32(std::size_t offset, std::int32_t value) {
        std::memcpy(bytes_.data() + offset, &value, sizeof(value));
    }
    void PutF32(std::size_t offset, float value) {
        std::memcpy(bytes_.data() + offset, &value, sizeof(value));
    }
    [[nodiscard]] auto data() const -> const std::uint8_t* { return bytes_.data(); }

private:
    std::array<std::uint8_t, kEngineEntitySize> bytes_{};
};

}  // namespace

TEST(ExtractEntitySnapshot, ReadsFieldsAtVerifiedOffsets) {
    const EntitySnapshotOffsets off;
    FakeEntity e;
    e.PutI32(off.unit_type, 1);
    e.PutF32(off.pos_x, 10.0F);
    e.PutF32(off.pos_x + 4, 20.0F);
    e.PutF32(off.pos_x + 8, 30.0F);
    e.PutF32(off.vel_x, 1.0F);
    e.PutF32(off.vel_x + 4, 2.0F);
    e.PutF32(off.vel_x + 8, 3.0F);
    e.PutF32(off.rot_x, 0.1F);
    e.PutF32(off.rot_x + 4, 0.2F);
    e.PutF32(off.rot_x + 8, 0.3F);
    e.PutI32(off.oid, 42);
    e.PutF32(off.health, 75.0F);
    e.PutF32(off.energy, 50.0F);
    e.PutI32(off.team, 2);

    const MvpEntitySnapshot snap = ExtractEntitySnapshot(e.data());

    EXPECT_EQ(snap.net_id, 42);
    EXPECT_EQ(snap.unit_type, 1);
    EXPECT_EQ(snap.team, 2);
    EXPECT_FLOAT_EQ(snap.pos.at(0), 10.0F);
    EXPECT_FLOAT_EQ(snap.pos.at(1), 20.0F);
    EXPECT_FLOAT_EQ(snap.pos.at(2), 30.0F);
    EXPECT_FLOAT_EQ(snap.vel.at(0), 1.0F);
    EXPECT_FLOAT_EQ(snap.vel.at(2), 3.0F);
    EXPECT_FLOAT_EQ(snap.rot.at(0), 0.1F);
    EXPECT_FLOAT_EQ(snap.rot.at(2), 0.3F);
    EXPECT_FLOAT_EQ(snap.health, 75.0F);
    EXPECT_FLOAT_EQ(snap.energy, 50.0F);
}

TEST(ExtractEntitySnapshot, ReadsNegativeAndZeroCoordinates) {
    const EntitySnapshotOffsets off;
    FakeEntity e;
    e.PutI32(off.oid, 7);
    e.PutF32(off.pos_x, -180.5F);
    e.PutF32(off.pos_x + 4, 0.0F);
    e.PutF32(off.pos_x + 8, 3269.0F);

    const MvpEntitySnapshot snap = ExtractEntitySnapshot(e.data());

    EXPECT_EQ(snap.net_id, 7);
    EXPECT_FLOAT_EQ(snap.pos.at(0), -180.5F);
    EXPECT_FLOAT_EQ(snap.pos.at(1), 0.0F);
    EXPECT_FLOAT_EQ(snap.pos.at(2), 3269.0F);
}
