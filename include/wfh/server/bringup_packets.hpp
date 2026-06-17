// NOLINTBEGIN(portability-avoid-pragma-once)
// pragma once is the project-wide include-guard convention; intentional.
#pragma once
// NOLINTEND(portability-avoid-pragma-once)

#include <cstdint>
#include <string_view>
#include <vector>

namespace wfh::server {

// Server->client bring-up packet bodies, ported from the proven reference flow
// (Wulf-Forge do_login_and_bootstrap) and cross-checked against wulfram2.exe.
// Each returns a COMPLETE TCP frame ([u16 len][opcode][body]) ready to send, except
// the UDP-only VERIFIED variant which the caller frames for UDP. All use the
// hardened wfh::proto::BitWriter (MSB-first) + EncodeTcpFrame.
//
// Bodies that are large/positional (BEHAVIOR 0x24, TRANSLATION 0x32) are emitted
// here too, but see bringup_packets.cpp for the TODO notes on field-table fidelity:
// reaching VERIFIED + roster is the M5.1b bar; full physics-tunable correctness is
// a follow-up (M6/M7) once the engine-oracle path is wired.

constexpr std::int32_t kProtocolVersion = 0x4E89;  // 20105; the one hard handshake gate

// HELLO (0x13) subtypes.
[[nodiscard]] auto BuildHelloUdpConfig(std::uint16_t udp_port, std::string_view host)
    -> std::vector<std::uint8_t>;                                     // sub 1
[[nodiscard]] auto BuildHelloVersion() -> std::vector<std::uint8_t>;  // sub 0
[[nodiscard]] auto BuildHelloSessionKey(std::string_view key)
    -> std::vector<std::uint8_t>;                                      // sub 2
[[nodiscard]] auto BuildHelloVerified() -> std::vector<std::uint8_t>;  // sub 3 (TCP frame)

// IDENTIFIED_UDP (0x4D): empty body. Sent once the UDP key echo links the endpoint.
[[nodiscard]] auto BuildIdentifiedUdp() -> std::vector<std::uint8_t>;

// LOGIN_STATUS (0x22): [byte is_donor][byte code]. code 1 = ask password, 8 = ok.
[[nodiscard]] auto BuildLoginStatus(bool is_donor, std::uint8_t code) -> std::vector<std::uint8_t>;

// BPS (0x4E): echo the requested rate and approve it.
[[nodiscard]] auto BuildBpsReply(std::int32_t requested_rate) -> std::vector<std::uint8_t>;

// PLAYER (0x17): [i32 player_id][byte is_guest].
[[nodiscard]] auto BuildPlayer(std::int32_t player_id, bool is_guest) -> std::vector<std::uint8_t>;

// GAME_CLOCK (0x2F), MOTD (0x23), TEAM_INFO (0x28), WORLD_STATS (0x16).
[[nodiscard]] auto BuildGameClock(std::int32_t ticks) -> std::vector<std::uint8_t>;
[[nodiscard]] auto BuildMotd(std::string_view message) -> std::vector<std::uint8_t>;
[[nodiscard]] auto BuildTeamInfo() -> std::vector<std::uint8_t>;
[[nodiscard]] auto BuildWorldStats(std::string_view map_name) -> std::vector<std::uint8_t>;

// ADD_TO_ROSTER (0x1A): account/team/name/nametag + stat slots.
[[nodiscard]] auto BuildAddToRoster(std::int32_t account_id, std::int32_t team,
                                    std::string_view name, std::string_view nametag)
    -> std::vector<std::uint8_t>;

// ---------------------------------------------------------------------------
// UDP reliable-stream handshake (server->client). Unlike the bring-up packets
// above, these are RAW UDP datagram bodies ([opcode][body], NO TCP length frame
// and NO seq prefix), matching the reference server's on_d_handshake. They set up
// the client's gameplay streams; without them the client never accepts world/team
// data (so team-select/entry/spawn stay inert). See memory/udp-stream-handshake-required.

// 0x02 handshake ACK: [0x02][byte subcmd=0][i32 ticks].
[[nodiscard]] auto BuildUdpHandshakeAck(std::int32_t ticks) -> std::vector<std::uint8_t>;

// 0x03 D_HANDSHAKE stream definitions: [0x03][i32 ticks][i32 player_id][i32 def_count=4] +
// 4x [string name][i32 id_count=1][i32 id] + [i32 cfg_count=4] + 4x [i32 stream_id][i32
// priority=1].
[[nodiscard]] auto BuildUdpStreamDefs(std::int32_t ticks, std::int32_t player_id)
    -> std::vector<std::uint8_t>;

// 0x04 stream control (UNPAUSE): [0x04][byte stream_id][u16 sequence=1].
[[nodiscard]] auto BuildUdpStreamUnpause(std::uint8_t stream_id) -> std::vector<std::uint8_t>;

// 0x0C ping reply (PONG): [0x0C][i32 echoed_timestamp].
[[nodiscard]] auto BuildUdpPong(std::int32_t echoed_timestamp) -> std::vector<std::uint8_t>;

// 0x1C UPDATE_STATS (raw UDP): a player's stat/team record. Sent to the requester right
// after a team switch so the client updates its roster list and activates the entry-map /
// respawn selector. Without it the client shows "you changed teams" but the list never
// updates and the selector stays disabled. Matches the reference capture:
// [0x1C][i32 player_id][i32 6][u16 team][u16 33][u16 3][u16 5][u16 9]
// [fix16.16 1.0][fix16.16 1.0][i32 10].
[[nodiscard]] auto BuildUdpUpdateStats(std::int32_t player_id, std::int32_t team)
    -> std::vector<std::uint8_t>;

}  // namespace wfh::server
