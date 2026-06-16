// NOLINTBEGIN(portability-avoid-pragma-once)
// pragma once is the project-wide include-guard convention; intentional.
#pragma once
// NOLINTEND(portability-avoid-pragma-once)

#include <cstddef>
#include <cstdint>
#include <string_view>

namespace wfh::proto {

// Field validators applied to UNTRUSTED client data BEFORE it can reach the engine.
// All are pure and fail-closed: they answer "is this value engine-safe?" so a
// rejecting caller can drop the connection rather than feed the engine garbage.

// Largest accepted protocol string length (including the NUL), used as the default
// cap for BitReader::ReadString on inbound packets. Generous but bounded.
constexpr std::size_t kMaxStringLen = 256;

// Highest valid spawnable unit/vehicle type the client may request. TankSpawn in
// the engine validates spawn types 0..4; other object types are server-spawned and
// never accepted from a client.
constexpr std::int32_t kMaxClientUnitType = 4;

// Clamp an analog action channel value to the engine's [-1, 1] range. NaN maps to 0.
[[nodiscard]] auto ClampUnit(float value) -> float;

// A client-requested spawn unit type must be in [0, kMaxClientUnitType].
[[nodiscard]] auto IsValidClientUnitType(std::int32_t unit_type) -> bool;

// Teams are 1 (RED) or 2 (BLU); 0 / anything else is invalid for a player.
[[nodiscard]] auto IsValidTeam(std::int32_t team) -> bool;

// An object id must be a sane positive identifier (0 and the 0xffffffff sentinel are
// not valid live OIDs).
[[nodiscard]] auto IsValidOid(std::uint32_t oid) -> bool;

// A decoded string is acceptable if it is within the cap and contains only printable
// ASCII (rejects embedded control bytes a 2006 client never sends but an attacker
// might use to confuse downstream handling).
[[nodiscard]] auto IsAcceptableString(std::string_view text, std::size_t max_len = kMaxStringLen)
    -> bool;

}  // namespace wfh::proto
