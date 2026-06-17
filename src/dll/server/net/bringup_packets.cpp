#include "wfh/server/bringup_packets.hpp"

#include "wfh/proto/bitstream.hpp"
#include "wfh/proto/framing.hpp"
#include "wfh/proto/opcodes.hpp"

#include <array>
#include <cstdint>
#include <string_view>
#include <vector>

namespace wfh::server {

namespace {

using proto::BitWriter;
using proto::EncodeTcpFrame;
using proto::Opcode;

// Frame `body` under `opcode`; on the (impossible-for-bring-up) oversize case,
// EncodeTcpFrame returns nullopt and we yield empty bytes (the caller treats an
// empty build as a no-op / drop). Bring-up bodies are tiny, so this never trips.
auto Frame(Opcode opcode, BitWriter& writer) -> std::vector<std::uint8_t> {
    auto framed = EncodeTcpFrame(static_cast<std::uint8_t>(opcode), writer.Bytes());
    return framed.value_or(std::vector<std::uint8_t>{});
}

constexpr std::uint8_t kHelloVersion = 0x00;
constexpr std::uint8_t kHelloUdpConfig = 0x01;
constexpr std::uint8_t kHelloSessionKey = 0x02;
constexpr std::uint8_t kHelloVerified = 0x03;

// UDP reliable-stream handshake opcodes/values (server->client raw datagrams).
constexpr std::uint8_t kUdpAckOpcode = 0x02;            // ACK (subcmd-multiplexed)
constexpr std::uint8_t kUdpAckSubcmdHandshake = 0x00;   // subcmd 0 = handshake ack
constexpr std::uint8_t kUdpHandshakeOpcode = 0x03;      // D_HANDSHAKE stream defs
constexpr std::uint8_t kUdpStreamControlOpcode = 0x04;  // stream control (unpause)
constexpr std::uint8_t kUdpPongOpcode = 0x0C;           // ping reply
constexpr std::int32_t kUdpStreamCount = 4;             // Unreliable/Reliable/Stream2/GameData
constexpr std::int32_t kUdpStreamIdCount = 1;           // one id per stream
constexpr std::int32_t kUdpStreamPriority = 1;          // per-stream priority
constexpr std::uint16_t kUdpStreamUnpauseSeq = 1;       // initial stream sequence

// UPDATE_STATS (0x1C) team-switch record constants (from the reference capture). The
// non-team fields are fixed values the client expects; only player_id + team vary.
constexpr std::uint8_t kUdpUpdateStatsOpcode = 0x1C;
constexpr std::int32_t kUpdateStatsRecordKind = 6;
constexpr std::uint16_t kUpdateStatsFieldMask = 33;
constexpr std::uint16_t kUpdateStatsFieldA = 3;
constexpr std::uint16_t kUpdateStatsFieldB = 5;
constexpr std::uint16_t kUpdateStatsFieldC = 9;
constexpr double kUpdateStatsUnitFraction = 1.0;
constexpr std::int32_t kUpdateStatsTrailingFlags = 10;

}  // namespace

auto BuildHelloUdpConfig(std::uint16_t udp_port, std::string_view host)
    -> std::vector<std::uint8_t> {
    BitWriter writer;
    writer.WriteByte(kHelloUdpConfig);
    writer.WriteU16(udp_port);
    writer.WriteU16(1);  // host count (one advertised endpoint)
    writer.WriteString(host);
    return Frame(Opcode::Hello, writer);
}

auto BuildHelloVersion() -> std::vector<std::uint8_t> {
    BitWriter writer;
    writer.WriteByte(kHelloVersion);
    writer.WriteI32(kProtocolVersion);
    return Frame(Opcode::Hello, writer);
}

auto BuildHelloSessionKey(std::string_view key) -> std::vector<std::uint8_t> {
    BitWriter writer;
    writer.WriteByte(kHelloSessionKey);
    writer.WriteString(key);
    return Frame(Opcode::Hello, writer);
}

auto BuildHelloVerified() -> std::vector<std::uint8_t> {
    BitWriter writer;
    writer.WriteByte(kHelloVerified);  // sub 3, no payload
    return Frame(Opcode::Hello, writer);
}

auto BuildIdentifiedUdp() -> std::vector<std::uint8_t> {
    BitWriter writer;  // empty body
    return Frame(Opcode::IdentifiedUdp, writer);
}

// is_donor/code are distinct protocol fields; the convertible-pair check does not
// apply to this fixed wire layout.
// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
auto BuildLoginStatus(bool is_donor, std::uint8_t code) -> std::vector<std::uint8_t> {
    BitWriter writer;
    writer.WriteByte(is_donor ? 1 : 0);
    writer.WriteByte(code);
    return Frame(Opcode::LoginStatus, writer);
}

auto BuildBpsReply(std::int32_t requested_rate) -> std::vector<std::uint8_t> {
    BitWriter writer;
    writer.WriteI32(requested_rate);
    writer.WriteByte(1);  // approved
    return Frame(Opcode::Bps, writer);
}

auto BuildPlayer(std::int32_t player_id, bool is_guest) -> std::vector<std::uint8_t> {
    BitWriter writer;
    writer.WriteI32(player_id);
    writer.WriteByte(is_guest ? 1 : 0);
    return Frame(Opcode::Player, writer);
}

auto BuildGameClock(std::int32_t ticks) -> std::vector<std::uint8_t> {
    constexpr std::int32_t kPhaseLengthMs = 30000;
    BitWriter writer;
    writer.WriteI32(ticks);
    writer.WriteByte(0x01);  // clock active
    writer.WriteI32(1);      // phase flag
    writer.WriteI32(kPhaseLengthMs);
    return Frame(Opcode::GameClock, writer);
}

auto BuildMotd(std::string_view message) -> std::vector<std::uint8_t> {
    BitWriter writer;
    writer.WriteString(message);
    return Frame(Opcode::Motd, writer);
}

auto BuildTeamInfo() -> std::vector<std::uint8_t> {
    BitWriter writer;
    // Team 1 (RED): id + 5 strings.
    writer.WriteByte(1);
    writer.WriteString("Crimson_Federation");
    writer.WriteString("Crimson Federation");
    writer.WriteString("Crimson Base");
    writer.WriteString("The red team.");
    writer.WriteString("Crimson Federation Wins!");
    // Team 2 (BLU): id + 5 strings.
    writer.WriteByte(2);
    writer.WriteString("Azure_Alliance");
    writer.WriteString("Azure Alliance");
    writer.WriteString("Azure Base");
    writer.WriteString("The blue team.");
    writer.WriteString("Azure Alliance Wins!");
    return Frame(Opcode::TeamInfo, writer);
}

auto BuildWorldStats(std::string_view map_name) -> std::vector<std::uint8_t> {
    BitWriter writer;
    writer.WriteString(map_name);
    writer.WriteByte(1);         // unused flag
    writer.WriteByte(1);         // map id
    writer.WriteFixed1616(1.0);  // scale/value
    return Frame(Opcode::WorldStats, writer);
}

// account_id/team are distinct fields; convertible-pair check does not apply.
// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
auto BuildAddToRoster(std::int32_t account_id, std::int32_t team, std::string_view name,
                      std::string_view nametag) -> std::vector<std::uint8_t> {
    BitWriter writer;
    writer.WriteI32(account_id);
    writer.WriteI32(0);  // account metadata
    writer.WriteU16(static_cast<std::uint16_t>(team));
    writer.WriteU16(2);  // color/stat slot
    writer.WriteString(name);
    writer.WriteString(nametag);
    writer.WriteU16(0);          // kills
    writer.WriteU16(0);          // deaths
    writer.WriteFixed1616(0.0);  // score
    writer.WriteI32(0);          // flags
    return Frame(Opcode::AddToRoster, writer);
}

auto BuildUdpHandshakeAck(std::int32_t ticks) -> std::vector<std::uint8_t> {
    BitWriter writer;
    writer.WriteByte(kUdpAckOpcode);
    writer.WriteByte(kUdpAckSubcmdHandshake);
    writer.WriteI32(ticks);
    return writer.Bytes();
}

auto BuildUdpStreamDefs(std::int32_t ticks, std::int32_t player_id) -> std::vector<std::uint8_t> {
    static constexpr std::array<std::string_view, kUdpStreamCount> kStreamNames = {
        "Unreliable", "Reliable", "Stream 2", "Game Data"};
    BitWriter writer;
    writer.WriteByte(kUdpHandshakeOpcode);
    writer.WriteI32(ticks);
    writer.WriteI32(player_id);
    writer.WriteI32(kUdpStreamCount);
    for (std::int32_t i = 0; i < kUdpStreamCount; ++i) {
        writer.WriteString(kStreamNames.at(static_cast<std::size_t>(i)));
        writer.WriteI32(kUdpStreamIdCount);
        writer.WriteI32(i);  // stream id
    }
    writer.WriteI32(kUdpStreamCount);  // config count
    for (std::int32_t i = 0; i < kUdpStreamCount; ++i) {
        writer.WriteI32(i);  // stream id
        writer.WriteI32(kUdpStreamPriority);
    }
    return writer.Bytes();
}

auto BuildUdpStreamUnpause(std::uint8_t stream_id) -> std::vector<std::uint8_t> {
    BitWriter writer;
    writer.WriteByte(kUdpStreamControlOpcode);
    writer.WriteByte(stream_id);
    writer.WriteU16(kUdpStreamUnpauseSeq);
    return writer.Bytes();
}

auto BuildUdpPong(std::int32_t echoed_timestamp) -> std::vector<std::uint8_t> {
    BitWriter writer;
    writer.WriteByte(kUdpPongOpcode);
    writer.WriteI32(echoed_timestamp);
    return writer.Bytes();
}

// player_id/team are distinct wire fields; the convertible-pair swap check does not apply.
// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
auto BuildUdpUpdateStats(std::int32_t player_id, std::int32_t team) -> std::vector<std::uint8_t> {
    BitWriter writer;
    writer.WriteByte(kUdpUpdateStatsOpcode);
    writer.WriteI32(player_id);
    writer.WriteI32(kUpdateStatsRecordKind);
    writer.WriteU16(static_cast<std::uint16_t>(team));
    writer.WriteU16(kUpdateStatsFieldMask);
    writer.WriteU16(kUpdateStatsFieldA);
    writer.WriteU16(kUpdateStatsFieldB);
    writer.WriteU16(kUpdateStatsFieldC);
    writer.WriteFixed1616(kUpdateStatsUnitFraction);
    writer.WriteFixed1616(kUpdateStatsUnitFraction);
    writer.WriteI32(kUpdateStatsTrailingFlags);
    return writer.Bytes();
}

}  // namespace wfh::server
