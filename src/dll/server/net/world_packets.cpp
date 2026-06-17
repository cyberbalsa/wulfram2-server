#include "wfh/server/world_packets.hpp"

#include "wfh/log.hpp"
#include "wfh/proto/bitstream.hpp"
#include "wfh/proto/framing.hpp"
#include "wfh/proto/opcodes.hpp"
#include "wfh/server/bringup_packets.hpp"
#include "wfh/server/runtime.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <exception>
#include <filesystem>
#include <fstream>
#include <limits>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

// Every WFH_* logging call expands to the project's intentional do-while(0) guard
// macro that forwards a printf-style C variadic to Log::Write. Suppress the two
// macro-inherent findings file-wide so the call sites stay readable; all other
// checks remain on.
// NOLINTBEGIN(cppcoreguidelines-avoid-do-while,cppcoreguidelines-pro-type-vararg)
namespace wfh::server {

namespace {

using proto::BitWriter;
using proto::EncodeTcpFrame;
using proto::Opcode;

constexpr std::uint8_t kDefaultUnitType = 0;
constexpr std::int32_t kPowerCellUnitType = 25;
constexpr std::int32_t kRefuelPadUnitType = 26;
constexpr std::int32_t kRepairPadUnitType = 27;
constexpr std::int32_t kFlakTurretUnitType = 29;
constexpr std::int32_t kGunTurretUnitType = 30;
constexpr std::int32_t kUplinkUnitType = 20;
constexpr std::int32_t kDarklightUnitType = 35;
constexpr std::int32_t kCargoBoxUnitType = 19;
constexpr std::int32_t kDecorationUnitType = 37;
constexpr std::uint8_t kReincarnateOk = 0;
constexpr std::uint8_t kReincarnateInvalidEntry = 4;
constexpr std::uint8_t kReincarnateTeamSwitchOk = 17;
constexpr std::uint8_t kReincarnateInvalidTeam = 18;
constexpr std::uint32_t kSpawnVitalMultiplier = 1;
constexpr std::int32_t kMaxPlayerId = 0x7fffffff;
constexpr std::size_t kMaxSnapshotEntities = 255;
constexpr std::uint32_t kMaskDefinition = 1U << 0U;
constexpr std::uint32_t kMaskPosition = 1U << 1U;
constexpr std::uint32_t kMaskRotation = 1U << 3U;
constexpr std::uint32_t kMaskHealth = 1U << 5U;
constexpr std::uint32_t kFullSnapshotMask =
    kMaskDefinition | kMaskPosition | kMaskRotation | kMaskHealth;
constexpr unsigned kEntityMaskBits = 10;
constexpr unsigned kBankSelectorBits = 16;
constexpr unsigned kIdBits = 8;
constexpr unsigned kStatsBits = 10;
constexpr unsigned kLocalWeaponBits = 5;
constexpr unsigned kEntityCountBits = 8;
constexpr float kFallbackWorldWidth = 1000.0F;
constexpr float kFallbackWorldHeight = 1000.0F;
constexpr float kRepairPadHeightOffset = 200.0F;
constexpr float kTeamOnePadXFactor = 0.42F;
constexpr float kTeamTwoPadXFactor = 0.58F;
constexpr float kRepairPadYFactor = 0.50F;

constexpr std::size_t kTranslationSlotCount = 28;
constexpr std::size_t kVectorBankCount = 3;
constexpr std::size_t kVectorSlotsPerBank = 4;
constexpr std::size_t kFirstVectorSlot = 16;
constexpr std::size_t kVectorPosOffset = 0;
constexpr std::size_t kVectorVelOffset = 1;
constexpr std::size_t kVectorRotOffset = 2;
constexpr std::size_t kVectorSpinOffset = 3;
constexpr std::int32_t kNoDynamicTotal = 0;
constexpr std::int32_t kDefaultScalarBits = 16;
constexpr std::int32_t kWeaponIdBits = 5;
constexpr std::int32_t kSmallScalarBits = 8;
constexpr std::int32_t kVectorHeaderBits = 4;
constexpr std::int32_t kVectorTotalBits = 16;
constexpr std::size_t kSlotWeaponId = 1;
constexpr std::size_t kSlotUnitType = 2;
constexpr std::size_t kSlotTeam = 3;
constexpr std::size_t kSlotCargoUnitType = 4;
constexpr std::size_t kSlotHealth = 5;
constexpr std::size_t kSlotEnergy = 8;
constexpr std::size_t kSlotActionAim = 10;
constexpr std::size_t kSlotActionMove = 11;
constexpr std::size_t kSlotExtraVitalA = 13;
constexpr std::size_t kSlotExtraVitalB = 14;
constexpr float kPositionMax = 8192.0F;
constexpr float kPositionRange = 16384.0F;
constexpr float kVelocityMax = 1000.0F;
constexpr float kVelocityRange = 2000.0F;
constexpr float kRotationMax = 6.3F;
constexpr float kRotationRange = 12.6F;
constexpr float kSpinMax = 200.0F;
constexpr float kSpinRange = 400.0F;
constexpr float kUnitFloatMax = 1.0F;
constexpr float kUnitFloatRange = 1.0F;

constexpr int kBehaviorWeaponUnitCount = 4;
constexpr int kBehaviorWeaponSlotCount = 13;
constexpr int kBehaviorWeaponBoolCount = 5;
constexpr int kBehaviorWeaponIntCount = 5;
constexpr int kBehaviorUnitCount = 39;
constexpr int kBehaviorVehiclePhysicsCount = 2;
constexpr int kBehaviorHeaderUnknownCount = 11;
constexpr int kHardpointBlockCount = 4;
constexpr int kHardpointsPerBlock = 4;
constexpr std::size_t kVec2ElementCount = 2;
constexpr std::size_t kTankActiveValueCount = 7;
constexpr std::size_t kScoutActiveValueCount = 9;
constexpr std::size_t kBomberActiveValueCount = 11;
constexpr double kHardpointHalfExtent = 2.0;
constexpr double kHardpointZ = -0.5;
constexpr double kHardpointNormalZ = -0.75;
constexpr double kHardpointReactionRange = 5.0;
constexpr double kBehaviorTimeout = 5.0;
constexpr double kBehaviorHeaderTen = 10.0;
constexpr std::int32_t kBehaviorTeamSize = 20;
constexpr std::int32_t kBehaviorGlimpseMs = 25000;
constexpr std::int32_t kBehaviorPushMs = 35000;
constexpr double kBehaviorGravityForce = 100.0;
constexpr double kBehaviorUnitValue = 1.0;
constexpr double kWeaponTargetingCone = 1.0;
constexpr double kWeaponCooldown = 100.0;
constexpr double kWeaponRange = 1000.0;
constexpr double kWeaponVelocity = 500.0;
constexpr double kUnitScale = 1.0;
constexpr double kUnitRegen = 100.0;
constexpr std::int32_t kUnitMaxHealth = 100;
constexpr double kVehicleSpeed = 20.0;
constexpr double kVehicleAccel = 4.0;
constexpr std::int32_t kVehicleEngineTorque = 700;
constexpr std::int32_t kVehicleSuspensionStiffness = 550;
constexpr double kVehicleGroundFriction = 0.8;
constexpr double kVehicleTurnRate = 0.05;
constexpr double kVehicleSuspensionDampening = 1.3;
constexpr std::int32_t kVehicleMass = 33000;
constexpr double kActiveTurnAdjust = 4.5;
constexpr double kTankMoveAdjust = 85.0;
constexpr double kTankStrafeAdjust = 69.7;
constexpr double kVehicleMaxVelocity = 80.0;
constexpr double kLowFuelLevel = 2000.0;
constexpr double kTankHoverHeight = 9.75;
constexpr double kGravityPct = 1.0;
constexpr double kScoutMoveBackward = 38.0;
constexpr double kScoutStrafeAdjust = 72.0;
constexpr double kScoutMaxVelocity = 85.0;
constexpr double kScoutMaxAltitude = 4.9;
constexpr double kScoutSpeedHeightPickup = 3.5;
constexpr double kBomberAxMag = -2.5132741233144;
constexpr double kBomberAyMag = 2.35619449060725;
constexpr double kBomberForwardMag = 80.0;
constexpr double kBomberLowAirspeed = 45.0;
constexpr double kBomberAngFac = 0.5;
constexpr double kBomberTurnLow = 70.0;
constexpr double kBomberTurnHigh = 110.0;
constexpr double kBomberTurnZero = 340.0;
constexpr double kBomberVeryHigh = 1000.0;
constexpr double kBomberCeiling = 1800.0;

struct TranslationSpec {
    std::int32_t header_bits = kDefaultScalarBits;
    std::int32_t total_bits = kNoDynamicTotal;
    std::string_view max = "1000.0";
    std::string_view range = "2000.0";
};

struct QuantSpec {
    unsigned header_bits = 0;
    unsigned max_total_bits = 0;
    float max = 0.0F;
    float range = 0.0F;
};

struct QuantConfig {
    unsigned header_bits = 0;
    unsigned max_total_bits = 0;
    unsigned base_bits = 0;
    float max = 0.0F;
    float range = 0.0F;
};

struct LandSummary {
    float world_width = kFallbackWorldWidth;
    float world_height = kFallbackWorldHeight;
    float max_height = 0.0F;
};

auto Frame(Opcode opcode, BitWriter& writer) -> std::vector<std::uint8_t> {
    auto framed = EncodeTcpFrame(static_cast<std::uint8_t>(opcode), writer.Bytes());
    return framed.value_or(std::vector<std::uint8_t>{});
}

auto TranslationSpecs() -> std::array<TranslationSpec, kTranslationSlotCount> {
    std::array<TranslationSpec, kTranslationSlotCount> specs{};
    specs.fill(TranslationSpec{});
    specs.at(kSlotWeaponId) = TranslationSpec{kWeaponIdBits, kNoDynamicTotal, "0.0", "0.0"};
    specs.at(kSlotUnitType) = TranslationSpec{kSmallScalarBits, kNoDynamicTotal, "0.0", "0.0"};
    specs.at(kSlotTeam) = TranslationSpec{kSmallScalarBits, kNoDynamicTotal, "0.0", "0.0"};
    specs.at(kSlotCargoUnitType) = TranslationSpec{kSmallScalarBits, kNoDynamicTotal, "0.0", "0.0"};
    specs.at(kSlotHealth) = TranslationSpec{kStatsBits, kNoDynamicTotal, "1.0", "1.0"};
    specs.at(kSlotEnergy) = TranslationSpec{kStatsBits, kNoDynamicTotal, "1.0", "1.0"};
    specs.at(kSlotActionAim) = TranslationSpec{kDefaultScalarBits, kNoDynamicTotal, "1.0", "2.0"};
    specs.at(kSlotActionMove) = TranslationSpec{kDefaultScalarBits, kNoDynamicTotal, "1.0", "2.0"};
    specs.at(kSlotExtraVitalA) = TranslationSpec{kSmallScalarBits, kNoDynamicTotal, "1.0", "1.0"};
    specs.at(kSlotExtraVitalB) = TranslationSpec{kSmallScalarBits, kNoDynamicTotal, "1.0", "1.0"};

    const TranslationSpec pos{kVectorHeaderBits, kVectorTotalBits, "8192.0", "16384.0"};
    const TranslationSpec vel{kVectorHeaderBits, kVectorTotalBits, "1000.0", "2000.0"};
    const TranslationSpec rot{kVectorHeaderBits, kVectorTotalBits, "6.3", "12.6"};
    const TranslationSpec spin{kVectorHeaderBits, kVectorTotalBits, "200.0", "400.0"};
    for (std::size_t bank = 0; bank < kVectorBankCount; ++bank) {
        const std::size_t start = kFirstVectorSlot + (bank * kVectorSlotsPerBank);
        specs.at(start + kVectorPosOffset) = pos;
        specs.at(start + kVectorVelOffset) = vel;
        specs.at(start + kVectorRotOffset) = rot;
        specs.at(start + kVectorSpinOffset) = spin;
    }
    return specs;
}

auto MakeQuantConfig(const QuantSpec& spec) -> QuantConfig {
    QuantConfig cfg;
    cfg.header_bits = spec.header_bits;
    cfg.max_total_bits = spec.max_total_bits;
    cfg.max = spec.max;
    cfg.range = spec.range;
    if (spec.max_total_bits == 0) {
        cfg.base_bits = spec.header_bits;
        return cfg;
    }
    const unsigned resolution = 1U << spec.header_bits;
    cfg.base_bits = spec.max_total_bits > resolution ? (spec.max_total_bits - resolution + 1U) : 1U;
    return cfg;
}

auto Quantize(float value, const QuantConfig& cfg, unsigned priority) -> std::uint32_t {
    const unsigned bits = cfg.max_total_bits == 0 ? cfg.base_bits : cfg.base_bits + priority;
    if (value == 0.0F) {
        return 0;
    }
    const float min_value = cfg.max - cfg.range;
    value = std::clamp(value, min_value, cfg.max);
    const auto denom = static_cast<float>((1U << bits) - 2U);
    if (denom <= 0.0F || cfg.range == 0.0F) {
        return 1;
    }
    return static_cast<std::uint32_t>(((cfg.max - value) * denom) / cfg.range) + 1U;
}

auto QuantizedBits(const QuantConfig& cfg, unsigned priority) -> unsigned {
    return cfg.max_total_bits == 0 ? cfg.base_bits : cfg.base_bits + priority;
}

void WriteQuantizedPayload(BitWriter& writer, float value, const QuantConfig& cfg,
                           unsigned priority) {
    writer.WriteBits(Quantize(value, cfg, priority), QuantizedBits(cfg, priority));
}

void WriteQuantized(BitWriter& writer, float value, const QuantConfig& cfg, unsigned priority) {
    unsigned effective_priority = priority;
    if (cfg.max_total_bits == 0) {
        effective_priority = 0;
    } else {
        const unsigned max_priority = (1U << cfg.header_bits) - 1U;
        effective_priority = std::min(effective_priority, max_priority);
        writer.WriteBits(effective_priority, cfg.header_bits);
    }
    WriteQuantizedPayload(writer, value, cfg, effective_priority);
}

void WriteVec3(BitWriter& writer, const std::array<float, 3>& value, const QuantConfig& cfg) {
    const unsigned priority = (1U << cfg.header_bits) - 1U;
    writer.WriteBits(priority, cfg.header_bits);
    WriteQuantizedPayload(writer, value.at(0), cfg, priority);
    WriteQuantizedPayload(writer, value.at(1), cfg, priority);
    WriteQuantizedPayload(writer, value.at(2), cfg, priority);
}

auto ParseDimensionPair(std::string_view line) -> std::optional<std::array<float, 2>> {
    const std::size_t sep = line.find('x');
    if (sep == std::string_view::npos) {
        return std::nullopt;
    }
    try {
        const float first = std::stof(std::string(line.substr(0, sep)));
        const float second = std::stof(std::string(line.substr(sep + 1)));
        return std::array<float, 2>{first, second};
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

auto ReadLandSummary(const std::filesystem::path& map_dir) -> std::optional<LandSummary> {
    std::ifstream in(map_dir / "land");
    if (!in) {
        return std::nullopt;
    }

    std::string grid_line;
    std::string world_line;
    if (!std::getline(in, grid_line) || !std::getline(in, world_line)) {
        return std::nullopt;
    }
    const auto grid = ParseDimensionPair(grid_line);
    const auto world = ParseDimensionPair(world_line);
    if (!grid || !world) {
        return std::nullopt;
    }

    LandSummary summary;
    summary.world_width = world->at(0);
    summary.world_height = world->at(1);
    const auto grid_width = static_cast<int>(grid->at(0));
    const auto grid_height = static_cast<int>(grid->at(1));
    const int sample_count = std::max(0, grid_width * grid_height);
    for (int i = 0; i < sample_count; ++i) {
        std::string line;
        if (!std::getline(in, line)) {
            break;
        }
        std::istringstream row(line);
        float ignored = 0.0F;
        float height = 0.0F;
        if (row >> ignored >> height) {
            summary.max_height = std::max(summary.max_height, height);
        }
    }
    return summary;
}

auto UnitTypeForStateToken(const std::string& token, bool is_crate) -> std::int32_t {
    if (is_crate) {
        return kCargoBoxUnitType;
    }
    if (token == "e") {
        return kPowerCellUnitType;
    }
    if (token == "s") {
        return kFlakTurretUnitType;
    }
    if (token == "g") {
        return kGunTurretUnitType;
    }
    if (token == "r") {
        return kRepairPadUnitType;
    }
    if (token == "f") {
        return kRefuelPadUnitType;
    }
    if (token == "u") {
        return kUplinkUnitType;
    }
    if (token == "h") {
        return kDarklightUnitType;
    }
    return 0;
}

auto ParseStateEntityLine(const std::string& line, std::int32_t net_id)
    -> std::optional<MvpEntitySnapshot> {
    std::istringstream row(line);
    std::string token;
    if (!(row >> token) || token.empty() || token.front() == '#') {
        return std::nullopt;
    }

    bool is_crate = false;
    if (token == "c") {
        is_crate = true;
        if (!(row >> token)) {
            return std::nullopt;
        }
    }

    const std::int32_t unit_type = UnitTypeForStateToken(token, is_crate);
    if (unit_type == 0) {
        return std::nullopt;
    }

    std::int32_t team = 0;
    float pos_x = 0.0F;
    float pos_y = 0.0F;
    float pos_z = 0.0F;
    float rx = 0.0F;
    float ry = 0.0F;
    float rz = 0.0F;
    if (!(row >> team >> pos_x >> pos_y >> pos_z >> rx >> ry >> rz)) {
        return std::nullopt;
    }

    MvpEntitySnapshot entity;
    entity.net_id = net_id;
    entity.unit_type = unit_type;
    entity.team = team;
    entity.is_manned = false;
    entity.cargo_unit_type = kDefaultCargoUnitType;
    entity.pos = {pos_x, pos_y, pos_z};
    entity.rot = {rx, ry, rz};
    return entity;
}

auto MapDirectory(const WorldBootstrapConfig& bootstrap) -> std::filesystem::path {
    return std::filesystem::path(bootstrap.map_root) / bootstrap.map_name;
}

auto RuntimeWorldBootstrapConfig() -> WorldBootstrapConfig {
    WorldBootstrapConfig bootstrap;
    bootstrap.map_name = ProcessRuntime().Config().map;
    return bootstrap;
}

void WriteEntity(BitWriter& writer, const MvpEntitySnapshot& entity) {
    static const QuantConfig kPosConfig = MakeQuantConfig(
        QuantSpec{kVectorHeaderBits, kVectorTotalBits, kPositionMax, kPositionRange});
    static const QuantConfig kRotConfig = MakeQuantConfig(
        QuantSpec{kVectorHeaderBits, kVectorTotalBits, kRotationMax, kRotationRange});
    static const QuantConfig kStatConfig =
        MakeQuantConfig(QuantSpec{kStatsBits, kNoDynamicTotal, kUnitFloatMax, kUnitFloatRange});

    writer.WriteI32(entity.net_id);
    writer.WriteBool(entity.is_manned);
    writer.WriteBits(kFullSnapshotMask, kEntityMaskBits);
    writer.WriteBits(0, kBankSelectorBits);
    writer.WriteBits(static_cast<std::uint32_t>(entity.unit_type), kIdBits);
    writer.WriteBits(static_cast<std::uint32_t>(entity.team), kIdBits);
    writer.WriteBits(static_cast<std::uint32_t>(entity.team), kIdBits);
    if (entity.unit_type == kDecorationUnitType) {
        writer.WriteI32(0);
        writer.WriteI32(0);
    } else if (entity.unit_type == kCargoBoxUnitType) {
        writer.WriteBits(static_cast<std::uint32_t>(entity.cargo_unit_type), kIdBits);
    }
    writer.WriteBool(true);
    // Field order follows the mask bit order (POS bit1, ROT bit3, HEALTH bit5). Rotation
    // MUST be sent or map fixtures (repair pads/bases) render at a default orientation —
    // i.e. "sideways". The reference marks loaded fixtures ROT-dirty, so it sends this too.
    WriteVec3(writer, entity.pos, kPosConfig);
    WriteVec3(writer, entity.rot, kRotConfig);
    WriteQuantized(writer, entity.health, kStatConfig, 0);
}

void WriteHardpointBlock(BitWriter& writer) {
    constexpr std::array<std::array<double, kVec2ElementCount>, kHardpointsPerBlock> kCorners = {
        {{{-kHardpointHalfExtent, -kHardpointHalfExtent}},
         {{kHardpointHalfExtent, -kHardpointHalfExtent}},
         {{-kHardpointHalfExtent, kHardpointHalfExtent}},
         {{kHardpointHalfExtent, kHardpointHalfExtent}}}};
    writer.WriteI32(kHardpointsPerBlock);
    for (const auto& corner : kCorners) {
        writer.WriteFixed1616(corner.at(0));
        writer.WriteFixed1616(corner.at(1));
        writer.WriteFixed1616(kHardpointZ);
        writer.WriteFixed1616(0.0);
        writer.WriteFixed1616(0.0);
        writer.WriteFixed1616(kHardpointNormalZ);
        writer.WriteI32(0);
    }
    writer.WriteFixed1616(kHardpointReactionRange);
}

void WriteBehaviorHeader(BitWriter& writer) {
    writer.WriteByte(0);
    writer.WriteFixed1616(kBehaviorTimeout);
    writer.WriteFixed1616(kBehaviorHeaderTen);
    writer.WriteFixed1616(kBehaviorHeaderTen);
    writer.WriteFixed1616(kBehaviorHeaderTen);
    writer.WriteFixed1616(kBehaviorHeaderTen);
    writer.WriteI32(kBehaviorTeamSize);
    writer.WriteI32(kBehaviorGlimpseMs);
    writer.WriteI32(kBehaviorPushMs);
    writer.WriteFixed1616(kBehaviorGravityForce);
    writer.WriteI32(1);
    writer.WriteI32(1);
    writer.WriteFixed1616(kBehaviorUnitValue);
    for (int i = 0; i < kBehaviorHeaderUnknownCount; ++i) {
        writer.WriteFixed1616(kBehaviorUnitValue);
    }
    writer.WriteByte(1);
    writer.WriteByte(1);
}

void WriteBehaviorWeapons(BitWriter& writer) {
    for (int unit = 0; unit < kBehaviorWeaponUnitCount; ++unit) {
        for (int slot = 0; slot < kBehaviorWeaponSlotCount; ++slot) {
            (void)unit;
            (void)slot;
            for (int i = 0; i < kBehaviorWeaponBoolCount; ++i) {
                writer.WriteByte(0);
            }
            writer.WriteFixed1616(kWeaponTargetingCone);
            for (int i = 0; i < kBehaviorWeaponIntCount; ++i) {
                writer.WriteI32(0);
            }
            writer.WriteFixed1616(kWeaponCooldown);
            writer.WriteFixed1616(kWeaponRange);
            writer.WriteFixed1616(kWeaponVelocity);
            writer.WriteFixed1616(kWeaponTargetingCone);
        }
    }
}

void WriteBehaviorUnits(BitWriter& writer) {
    for (int unit = 0; unit < kBehaviorUnitCount; ++unit) {
        (void)unit;
        writer.WriteFixed1616(kUnitScale);
        writer.WriteFixed1616(kUnitRegen);
        writer.WriteI32(kUnitMaxHealth);
    }
}

void WriteBehaviorVehiclePhysics(BitWriter& writer) {
    for (int vehicle = 0; vehicle < kBehaviorVehiclePhysicsCount; ++vehicle) {
        (void)vehicle;
        writer.WriteFixed1616(kVehicleSpeed);
        writer.WriteFixed1616(kVehicleAccel);
        writer.WriteI32(kVehicleEngineTorque);
        writer.WriteI32(kVehicleSuspensionStiffness);
        writer.WriteFixed1616(kVehicleGroundFriction);
        writer.WriteFixed1616(kVehicleTurnRate);
        writer.WriteFixed1616(kVehicleSuspensionDampening);
        writer.WriteI32(0);
        writer.WriteI32(kVehicleMass);
    }
}

template <std::size_t Count>
void WriteFixedList(BitWriter& writer, const std::array<double, Count>& values) {
    for (const double value : values) {
        writer.WriteFixed1616(value);
    }
}

void WriteBehaviorActiveVehicles(BitWriter& writer) {
    constexpr std::array<double, kTankActiveValueCount> kTank = {
        kActiveTurnAdjust, kTankMoveAdjust,  kTankStrafeAdjust, kVehicleMaxVelocity,
        kLowFuelLevel,     kTankHoverHeight, kGravityPct};
    constexpr std::array<double, kScoutActiveValueCount> kScout = {
        kActiveTurnAdjust,  kTankMoveAdjust,         kScoutMoveBackward,
        kScoutStrafeAdjust, kScoutMaxVelocity,       kLowFuelLevel,
        kScoutMaxAltitude,  kScoutSpeedHeightPickup, kGravityPct};
    constexpr std::array<double, kBomberActiveValueCount> kBomber = {
        kBomberAxMag,    kBomberAyMag,   kBomberForwardMag, kBomberLowAirspeed,
        kBomberAngFac,   kBomberTurnLow, kBomberTurnHigh,   kBomberTurnZero,
        kBomberVeryHigh, kBomberCeiling, kLowFuelLevel};

    WriteFixedList(writer, kTank);
    WriteFixedList(writer, kScout);
    WriteFixedList(writer, kBomber);
}

auto SessionPlayerId(std::uint64_t session_id) -> std::int32_t {
    return session_id <= static_cast<std::uint64_t>(kMaxPlayerId)
               ? static_cast<std::int32_t>(session_id)
               : kMaxPlayerId;
}

// TCP-framed UPDATE_STATS (0x1C) for broadcasting a team change to OTHER clients so
// their rosters update (the requester gets the same record on UDP from its Connection).
// Reuses the raw UDP body builder so the wire layout has a single source of truth, then
// wraps it in the [u16 len][opcode][body] TCP frame.
auto BuildUpdateStatsFramed(std::int32_t player_id, std::int32_t team)
    -> std::vector<std::uint8_t> {
    const auto raw = BuildUdpUpdateStats(player_id, team);  // [0x1C][body]
    if (raw.empty()) {
        return {};
    }
    const std::vector<std::uint8_t> body(raw.begin() + 1, raw.end());
    return EncodeTcpFrame(raw.front(), body).value_or(std::vector<std::uint8_t>{});
}

}  // namespace

auto BuildBehavior() -> std::vector<std::uint8_t> {
    BitWriter writer;
    WriteBehaviorHeader(writer);
    WriteBehaviorWeapons(writer);
    WriteBehaviorUnits(writer);
    WriteBehaviorVehiclePhysics(writer);
    for (int block = 0; block < kHardpointBlockCount; ++block) {
        (void)block;
        WriteHardpointBlock(writer);
    }
    WriteBehaviorActiveVehicles(writer);
    return Frame(Opcode::Behavior, writer);
}

auto BuildTranslation() -> std::vector<std::uint8_t> {
    BitWriter writer;
    for (const TranslationSpec& spec : TranslationSpecs()) {
        writer.WriteI32(spec.header_bits);
        writer.WriteI32(0);
        writer.WriteI32(spec.total_bits);
        writer.WriteString(spec.max);
        writer.WriteString(spec.range);
    }
    return Frame(Opcode::Translation, writer);
}

auto BuildViewUpdateSnapshot(std::int32_t sequence, const std::vector<MvpEntitySnapshot>& entities,
                             float local_health, float local_energy) -> std::vector<std::uint8_t> {
    static const QuantConfig kStatConfig =
        MakeQuantConfig(QuantSpec{kStatsBits, kNoDynamicTotal, kUnitFloatMax, kUnitFloatRange});

    BitWriter writer;
    writer.WriteI32(sequence);
    writer.WriteI32(sequence);
    writer.WriteBool(true);
    writer.WriteBits(0, kLocalWeaponBits);
    WriteQuantized(writer, local_health, kStatConfig, 0);
    WriteQuantized(writer, local_energy, kStatConfig, 0);
    const auto count = static_cast<std::uint8_t>(std::min(entities.size(), kMaxSnapshotEntities));
    writer.WriteBits(count, kEntityCountBits);
    for (std::size_t i = 0; i < count; ++i) {
        WriteEntity(writer, entities.at(i));
    }
    return Frame(Opcode::ViewUpdate, writer);
}

auto BuildTankSpawn(const TankSpawnSpec& spec) -> std::vector<std::uint8_t> {
    BitWriter writer;
    writer.WriteI32(spec.sequence);
    writer.WriteBool(true);  // include vitals
    writer.WriteBits(0, kWeaponIdBits);
    writer.WriteBits(kSpawnVitalMultiplier, kStatsBits);
    writer.WriteBits(kSpawnVitalMultiplier, kStatsBits);
    writer.WriteI32(spec.unit_type);
    writer.WriteI32(spec.net_id);
    writer.WriteByte(static_cast<std::uint8_t>(spec.team));
    for (const float value : spec.pos) {
        writer.WriteFixed1616(value);
    }
    for (const float value : spec.rot) {
        writer.WriteFixed1616(value);
    }
    return Frame(Opcode::TankSpawn, writer);
}

auto BuildReincarnateResult(std::uint8_t code, std::string_view message)
    -> std::vector<std::uint8_t> {
    BitWriter writer;
    writer.WriteByte(code);
    writer.WriteString(message);
    return Frame(Opcode::Reincarnate, writer);
}

auto BuildBirthNotice(std::int32_t player_id) -> std::vector<std::uint8_t> {
    BitWriter writer;
    writer.WriteI32(player_id);
    writer.WriteI32(1);
    return Frame(Opcode::BirthNotice, writer);
}

MvpOnlineBridge::MvpOnlineBridge(IncomingCmdQueue& inbound, OutboundStateQueue& outbound)
    : MvpOnlineBridge(inbound, outbound, WorldBootstrapConfig{}) {}

MvpOnlineBridge::MvpOnlineBridge(IncomingCmdQueue& inbound, OutboundStateQueue& outbound,
                                 WorldBootstrapConfig bootstrap)
    : inbound_(&inbound), outbound_(&outbound), bootstrap_(std::move(bootstrap)) {
    LoadMapBootstrap();
}

void MvpOnlineBridge::SetWorldProvider(WorldProvider provider) {
    world_provider_ = std::move(provider);
}

void MvpOnlineBridge::Tick(std::uint32_t sequence) {
    bool visibility_changed = false;
    for (const ClientCommand& cmd : inbound_->DrainAll()) {
        HandleCommand(cmd, visibility_changed, sequence);
    }
    if (visibility_changed) {
        EmitSnapshots(sequence);
    }
}

void MvpOnlineBridge::HandleCommand(const ClientCommand& cmd, bool& visibility_changed,
                                    std::uint32_t sequence) {
    switch (cmd.kind) {
    case ClientCommandKind::ClientConnected: AddSession(cmd, visibility_changed); return;
    case ClientCommandKind::WantUpdates:
        MarkWantUpdates(cmd.session_id, visibility_changed);
        return;
    case ClientCommandKind::Disconnected: RemoveSession(cmd.session_id, visibility_changed); return;
    case ClientCommandKind::Reincarnate:
        HandleReincarnate(cmd, visibility_changed, sequence);
        return;
    case ClientCommandKind::LoginUser:
    case ClientCommandKind::LoginPassword:
    case ClientCommandKind::ActionInput: return;
    }
}

void MvpOnlineBridge::AddSession(const ClientCommand& cmd, bool& visibility_changed) {
    if (sessions_.find(cmd.session_id) != sessions_.end()) {
        return;
    }
    SessionState state;
    state.session_id = cmd.session_id;
    state.player_id = SessionPlayerId(cmd.session_id);
    // Join with NO team (0); the player selects one at team-select (team-switch
    // reincarnate -> HandleTeamSwitch), matching the reference server. Pre-assigning
    // disagrees with the engine's team-select and corrupts the roster display.
    state.team = 0;
    state.name = cmd.text.empty() ? ("player" + std::to_string(state.player_id)) : cmd.text;

    const SessionState joined = state;
    sessions_.emplace(cmd.session_id, std::move(state));
    EmitRosterCatchup(joined);
    visibility_changed = true;
    WFH_DEBUG("mvp", "session %llu joined MVP world player_id=%d team=%d",
              static_cast<unsigned long long>(cmd.session_id), static_cast<int>(joined.player_id),
              static_cast<int>(joined.team));
}

void MvpOnlineBridge::MarkWantUpdates(std::uint64_t session_id, bool& visibility_changed) {
    auto it = sessions_.find(session_id);
    if (it == sessions_.end()) {
        return;
    }
    if (!it->second.wants_updates) {
        it->second.wants_updates = true;
        visibility_changed = true;
        WFH_DEBUG("mvp", "session %llu wants MVP updates",
                  static_cast<unsigned long long>(session_id));
    }
}

void MvpOnlineBridge::RemoveSession(std::uint64_t session_id, bool& visibility_changed) {
    if (sessions_.erase(session_id) != 0) {
        visibility_changed = true;
        WFH_DEBUG("mvp", "session %llu removed from MVP world",
                  static_cast<unsigned long long>(session_id));
    }
}

void MvpOnlineBridge::HandleReincarnate(const ClientCommand& cmd, bool& visibility_changed,
                                        std::uint32_t sequence) {
    auto it = sessions_.find(cmd.session_id);
    if (it == sessions_.end()) {
        WFH_DEBUG("mvp", "ignored reincarnate for unknown session %llu",
                  static_cast<unsigned long long>(cmd.session_id));
        return;
    }

    SessionState& session = it->second;
    if (cmd.team != 0) {
        HandleTeamSwitch(session, cmd.team);
        return;
    }

    const MvpEntitySnapshot* pad = ResolveSpawnPad(session, cmd.unit_id, cmd.pad_id);
    if (pad == nullptr) {
        outbound_->Push(OutboundMessage{
            session.session_id, true,
            BuildReincarnateResult(kReincarnateInvalidEntry, "Invalid Entry Point.")});
        WFH_DEBUG("mvp", "session %llu spawn rejected selected=%d base=%d team=%d",
                  static_cast<unsigned long long>(session.session_id),
                  static_cast<int>(cmd.unit_id), static_cast<int>(cmd.pad_id),
                  static_cast<int>(session.team));
        return;
    }

    SpawnOnPad(session, *pad, sequence, visibility_changed);
}

void MvpOnlineBridge::HandleTeamSwitch(SessionState& session, std::int32_t team) {
    if (team == 1 || team == 2) {
        session.team = team;
        outbound_->Push(OutboundMessage{session.session_id, true,
                                        BuildReincarnateResult(kReincarnateTeamSwitchOk, "")});
        // Broadcast the team change to OTHER clients so their roster lists update (the
        // requester already received UPDATE_STATS on UDP from its Connection; mirrors the
        // reference server, which broadcasts UPDATE_STATS on a switch).
        std::size_t peers = 0;
        for (const auto& [id, peer] : sessions_) {
            (void)peer;
            if (id == session.session_id) {
                continue;
            }
            outbound_->Push(
                OutboundMessage{id, true, BuildUpdateStatsFramed(session.player_id, team)});
            ++peers;
        }
        WFH_DEBUG("mvp", "session %llu switched team=%d (UPDATE_STATS to %zu peers)",
                  static_cast<unsigned long long>(session.session_id),
                  static_cast<int>(session.team), peers);
        return;
    }

    outbound_->Push(
        OutboundMessage{session.session_id, true,
                        BuildReincarnateResult(kReincarnateInvalidTeam, "Invalid team.")});
}

void MvpOnlineBridge::SpawnOnPad(SessionState& session, const MvpEntitySnapshot& pad,
                                 std::uint32_t sequence, bool& visibility_changed) {
    session.entity = MvpEntitySnapshot{};
    session.entity.net_id = next_entity_id_++;
    session.entity.unit_type = kDefaultUnitType;
    session.entity.team = session.team;
    session.entity.is_manned = true;
    session.entity.pos = pad.pos;
    session.entity.rot = pad.rot;
    session.spawned = true;

    TankSpawnSpec spawn;
    spawn.sequence = static_cast<std::int32_t>(sequence);
    spawn.net_id = session.entity.net_id;
    spawn.unit_type = session.entity.unit_type;
    spawn.team = session.entity.team;
    spawn.pos = session.entity.pos;
    spawn.rot = session.entity.rot;
    outbound_->Push(OutboundMessage{session.session_id, true, BuildTankSpawn(spawn)});
    outbound_->Push(
        OutboundMessage{session.session_id, true, BuildReincarnateResult(kReincarnateOk, "")});
    for (const auto& [id, existing] : sessions_) {
        (void)existing;
        outbound_->Push(OutboundMessage{id, true, BuildBirthNotice(session.player_id)});
    }

    visibility_changed = true;
    WFH_DEBUG("mvp", "session %llu spawned entity=%d team=%d pad=%d",
              static_cast<unsigned long long>(session.session_id),
              static_cast<int>(session.entity.net_id), static_cast<int>(session.team),
              static_cast<int>(pad.net_id));
}

void MvpOnlineBridge::LoadMapBootstrap() {
    static_entities_.clear();
    next_entity_id_ = 1;
    LoadStateEntities();
    EnsureFallbackRepairPads();
}

void MvpOnlineBridge::LoadStateEntities() {
    const std::filesystem::path map_dir = MapDirectory(bootstrap_);
    const std::filesystem::path state_path = map_dir / "state";
    std::ifstream state_file(state_path);
    if (!state_file) {
        const std::string state_path_text = state_path.string();
        WFH_DEBUG("mvp", "no map state file for map=%s path=%s; using fallback pads",
                  bootstrap_.map_name.c_str(), state_path_text.c_str());
        return;
    }

    std::string line;
    while (std::getline(state_file, line)) {
        auto entity = ParseStateEntityLine(line, next_entity_id_);
        if (!entity) {
            continue;
        }
        static_entities_.push_back(*entity);
        ++next_entity_id_;
    }
    const std::string state_path_text = state_path.string();
    WFH_DEBUG("mvp", "loaded map state map=%s path=%s entities=%zu", bootstrap_.map_name.c_str(),
              state_path_text.c_str(), static_entities_.size());
}

auto MvpOnlineBridge::ExistingRepairPadTeams() const -> std::array<bool, 3> {
    std::array<bool, 3> has_team_pad{};
    for (const MvpEntitySnapshot& entity : static_entities_) {
        if (entity.unit_type == kRepairPadUnitType && entity.team >= 1 && entity.team <= 2) {
            has_team_pad.at(static_cast<std::size_t>(entity.team)) = true;
        }
    }
    return has_team_pad;
}

void MvpOnlineBridge::EnsureFallbackRepairPads() {
    const std::filesystem::path map_dir = MapDirectory(bootstrap_);
    LandSummary summary;
    if (const auto loaded = ReadLandSummary(map_dir)) {
        summary = *loaded;
    }

    const auto has_team_pad = ExistingRepairPadTeams();

    for (std::int32_t team = 1; team <= 2; ++team) {
        if (has_team_pad.at(static_cast<std::size_t>(team))) {
            continue;
        }
        MvpEntitySnapshot pad;
        pad.net_id = next_entity_id_++;
        pad.unit_type = kRepairPadUnitType;
        pad.team = team;
        pad.is_manned = false;
        const float x_factor = team == 1 ? kTeamOnePadXFactor : kTeamTwoPadXFactor;
        pad.pos = {summary.world_width * x_factor, summary.world_height * kRepairPadYFactor,
                   summary.max_height + kRepairPadHeightOffset};
        static_entities_.push_back(pad);
        WFH_DEBUG("mvp", "created fallback repair pad map=%s id=%d team=%d",
                  bootstrap_.map_name.c_str(), static_cast<int>(pad.net_id),
                  static_cast<int>(team));
    }
}

void MvpOnlineBridge::EmitRosterCatchup(const SessionState& joined) {
    for (const auto& [id, existing] : sessions_) {
        if (id == joined.session_id) {
            continue;
        }
        outbound_->Push(OutboundMessage{
            joined.session_id, true,
            BuildAddToRoster(existing.player_id, existing.team, existing.name, "")});
        outbound_->Push(OutboundMessage{
            id, true, BuildAddToRoster(joined.player_id, joined.team, joined.name, "")});
    }
}

auto MvpOnlineBridge::EntitySnapshots() const -> std::vector<MvpEntitySnapshot> {
    std::vector<MvpEntitySnapshot> entities;
    entities.reserve(static_entities_.size() + sessions_.size());
    // Map fixtures (pads/bases from the parsed `state`) are ALWAYS sent so the client
    // can open the entry map / pick a spawn pad — the reference server sends this state
    // every snapshot. The engine world-load populates terrain only, not these objects.
    entities.insert(entities.end(), static_entities_.begin(), static_entities_.end());
    if (world_provider_) {
        // M6.1: add the engine's authoritative dynamic entities (tanks/missiles) on top
        // of the fixtures, rather than replacing them.
        const std::vector<MvpEntitySnapshot> engine = world_provider_();
        entities.insert(entities.end(), engine.begin(), engine.end());
        return entities;
    }
    // MVP fallback (no engine world): session-projected tanks.
    for (const auto& [id, session] : sessions_) {
        (void)id;
        if (session.spawned) {
            entities.push_back(session.entity);
        }
    }
    return entities;
}

auto MvpOnlineBridge::ResolveSpawnPad(const SessionState& session, std::int32_t selected_entry_id,
                                      std::int32_t base_id) const -> const MvpEntitySnapshot* {
    const std::array<std::int32_t, 2> candidates{selected_entry_id, base_id};
    for (const std::int32_t candidate : candidates) {
        if (candidate == 0) {
            continue;
        }
        const auto it = std::find_if(static_entities_.begin(), static_entities_.end(),
                                     [&](const MvpEntitySnapshot& entity) -> bool {
                                         return entity.net_id == candidate &&
                                                entity.unit_type == kRepairPadUnitType &&
                                                entity.team == session.team;
                                     });
        if (it != static_entities_.end()) {
            return &(*it);
        }
    }

    const auto it = std::find_if(static_entities_.begin(), static_entities_.end(),
                                 [&](const MvpEntitySnapshot& entity) -> bool {
                                     return entity.unit_type == kRepairPadUnitType &&
                                            entity.team == session.team;
                                 });
    return it == static_entities_.end() ? nullptr : &(*it);
}

void MvpOnlineBridge::EmitSnapshots(std::uint32_t sequence) {
    const auto entities = EntitySnapshots();
    for (const auto& [id, session] : sessions_) {
        if (!session.wants_updates) {
            continue;
        }
        outbound_->Push(OutboundMessage{
            id, true,
            BuildViewUpdateSnapshot(static_cast<std::int32_t>(sequence), entities, 1.0F, 1.0F)});
        WFH_TRACE("mvp", "queued MVP snapshot session=%llu entities=%zu",
                  static_cast<unsigned long long>(id), entities.size());
    }
}

auto ProcessMvpBridge() -> MvpOnlineBridge& {
    // Process lifetime, mirroring ProcessRuntime(): avoids DLL teardown ordering work.
    // NOLINTNEXTLINE(cppcoreguidelines-owning-memory)
    static auto* const bridge = new MvpOnlineBridge(
        ProcessRuntime().Inbound(), ProcessRuntime().Outbound(), RuntimeWorldBootstrapConfig());
    return *bridge;
}

void ProcessMvpOnlineTick(std::uint32_t sequence) {
    ProcessMvpBridge().Tick(sequence);
}

}  // namespace wfh::server
// NOLINTEND(cppcoreguidelines-avoid-do-while,cppcoreguidelines-pro-type-vararg)
