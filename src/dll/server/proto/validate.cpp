#include "wfh/proto/validate.hpp"

#include "wfh/proto/opcodes.hpp"

#include <algorithm>
#include <array>
#include <cmath>

namespace wfh::proto {

namespace {

constexpr std::uint32_t kInvalidOidSentinel = 0xFFFFFFFFU;  // entity +0xB4 init value
constexpr std::uint8_t kPrintableAsciiMin = 0x20;           // space
constexpr std::uint8_t kPrintableAsciiMax = 0x7E;           // '~'

}  // namespace

auto IsKnownOpcode(std::uint8_t opcode) -> bool {
    // Data-driven whitelist — extend by adding the enumerator here and in opcodes.hpp.
    constexpr std::array<Opcode, 21> kKnown = {
        Opcode::HelloThere,    Opcode::UpdateArray, Opcode::ViewUpdate,     Opcode::Hello,
        Opcode::DeleteObject,  Opcode::WorldStats,  Opcode::Player,         Opcode::TankSpawn,
        Opcode::AddToRoster,   Opcode::BirthNotice, Opcode::Login,          Opcode::LoginStatus,
        Opcode::Motd,          Opcode::Behavior,    Opcode::Reincarnate,    Opcode::TeamInfo,
        Opcode::GameClock,     Opcode::Translation, Opcode::TranslationAck, Opcode::WantUpdates,
        Opcode::IdentifiedUdp,
    };
    return std::any_of(kKnown.begin(), kKnown.end(), [opcode](Opcode known) -> bool {
        return static_cast<std::uint8_t>(known) == opcode;
    });
}

auto ClampUnit(float value) -> float {
    if (std::isnan(value)) {
        return 0.0F;
    }
    if (value < -1.0F) {
        return -1.0F;
    }
    if (value > 1.0F) {
        return 1.0F;
    }
    return value;
}

auto IsValidClientUnitType(std::int32_t unit_type) -> bool {
    return unit_type >= 0 && unit_type <= kMaxClientUnitType;
}

auto IsValidTeam(std::int32_t team) -> bool {
    return team == 1 || team == 2;
}

auto IsValidOid(std::uint32_t oid) -> bool {
    return oid != 0 && oid != kInvalidOidSentinel;
}

auto IsAcceptableString(std::string_view text, std::size_t max_len) -> bool {
    if (text.size() > max_len) {
        return false;
    }
    // Printable ASCII only; reject control/non-ASCII bytes a hostile client might use.
    return std::all_of(text.begin(), text.end(), [](char raw) -> bool {
        const auto byte = static_cast<std::uint8_t>(raw);
        return byte >= kPrintableAsciiMin && byte <= kPrintableAsciiMax;
    });
}

}  // namespace wfh::proto
