#include "wfh/server/connection.hpp"

#include "wfh/log.hpp"
#include "wfh/proto/bitstream.hpp"
#include "wfh/proto/opcodes.hpp"
#include "wfh/proto/validate.hpp"
#include "wfh/server/bringup_packets.hpp"
#include "wfh/server/world_packets.hpp"

#include <cstdint>
#include <limits>
#include <optional>
#include <string>
#include <vector>

// Every WFH_* logging call expands to the project's intentional do-while(0) guard
// macro that forwards a printf-style C variadic to Log::Write. Suppress the two
// macro-inherent findings file-wide so the call sites stay readable; all other
// checks remain on.
// NOLINTBEGIN(cppcoreguidelines-avoid-do-while,cppcoreguidelines-pro-type-vararg)
namespace wfh::server {

namespace {

using proto::BitReader;
using proto::Frame;
using proto::Opcode;

// HELLO subtypes seen inbound. sub 0 = version check (TCP), sub 1 = key echo (UDP).
constexpr std::uint8_t kHelloVersion = 0x00;
constexpr std::uint8_t kHelloKeyEcho = 0x01;
constexpr std::uint8_t kHelloPostLinkConfirm = 0x02;
constexpr std::uint8_t kUdpAckOpcode = 0x02;
constexpr std::uint8_t kUdpAckSubcmd = 0x01;
constexpr std::uint16_t kUdpAckLength = 9;

// UDP reliable-stream handshake the client requires to enable gameplay streams.
constexpr std::uint8_t kUdpDHandshakeOpcode = 0x03;  // client D_HANDSHAKE
constexpr std::uint8_t kUdpPingOpcode = 0x0B;        // client ping -> we reply 0x0C pong
constexpr std::uint8_t kReliableStreamId = 1;        // stream we unpause (events/chat)
constexpr std::uint8_t kGameDataStreamId = 3;        // stream we unpause (movement/state)

// LOGIN_STATUS (0x22) codes: 1 = ask for password, 8 = login OK.
constexpr std::uint8_t kLoginStatusAskPassword = 1;
constexpr std::uint8_t kLoginStatusOk = 8;

// A joining player has NO team until they pick one at the team-select screen (the
// reference server joins with team 0 and the client then sends a team-switch
// reincarnate). Pre-assigning a team here disagrees with the engine's team-select
// and shows the player on the wrong/both teams.
constexpr std::int32_t kJoinTeamUnassigned = 0;

// Append framed bytes onto an output buffer.
void Append(std::vector<std::uint8_t>& out, const std::vector<std::uint8_t>& frame) {
    out.insert(out.end(), frame.begin(), frame.end());
}

auto StateName(ConnState state) -> const char* {
    switch (state) {
    case ConnState::AwaitingKeyEcho: return "AwaitingKeyEcho";
    case ConnState::AwaitingUsername: return "AwaitingUsername";
    case ConnState::AwaitingPassword: return "AwaitingPassword";
    case ConnState::Verified: return "Verified";
    case ConnState::InGame: return "InGame";
    case ConnState::Closed: return "Closed";
    }
    return "Unknown";
}

void LogTcpRecv(std::uint64_t session_id, std::size_t len, ConnState state) {
    WFH_TRACE("conn", "session %llu TCP recv len=%zu state=%s",
              static_cast<unsigned long long>(session_id), len, StateName(state));
}

void LogTcpFeedRejected(std::uint64_t session_id, bool feed_ok, std::size_t buffered) {
    WFH_DEBUG("conn", "session %llu TCP feed rejected feed_ok=%d buffered=%zu",
              static_cast<unsigned long long>(session_id), feed_ok ? 1 : 0, buffered);
}

void LogTcpFrame(std::uint64_t session_id, const Frame& frame, ConnState state) {
    WFH_TRACE("conn", "session %llu TCP frame opcode=0x%02X body=%zu state=%s",
              static_cast<unsigned long long>(session_id), static_cast<unsigned>(frame.opcode),
              frame.body.size(), StateName(state));
}

void LogTcpFrameClosed(std::uint64_t session_id, std::uint8_t opcode) {
    WFH_DEBUG("conn", "session %llu closed after opcode=0x%02X",
              static_cast<unsigned long long>(session_id), static_cast<unsigned>(opcode));
}

void LogUnknownOpcode(std::uint64_t session_id, std::uint8_t opcode) {
    WFH_DEBUG("conn", "session %llu unknown opcode=0x%02X rejected",
              static_cast<unsigned long long>(session_id), static_cast<unsigned>(opcode));
}

void LogAwaitingKeyEchoRejected(std::uint64_t session_id, std::uint8_t opcode) {
    WFH_DEBUG("conn", "session %llu rejected opcode=0x%02X while awaiting UDP key echo",
              static_cast<unsigned long long>(session_id), static_cast<unsigned>(opcode));
}

void LogVerifiedNoOp(std::uint64_t session_id, std::uint8_t opcode) {
    WFH_TRACE("conn", "session %llu accepted verified opcode=0x%02X as no-op",
              static_cast<unsigned long long>(session_id), static_cast<unsigned>(opcode));
}

void LogBpsReply(std::uint64_t session_id, std::int32_t requested_rate) {
    WFH_TRACE("conn", "session %llu approved BPS request rate=%d",
              static_cast<unsigned long long>(session_id), static_cast<int>(requested_rate));
}

void LogGenericNoOp(std::uint64_t session_id, ConnState state) {
    WFH_TRACE("conn", "session %llu accepted GENERIC no-op state=%s",
              static_cast<unsigned long long>(session_id), StateName(state));
}

void LogPostLinkHelloNoOp(std::uint64_t session_id, std::uint8_t subcmd) {
    WFH_TRACE("conn", "session %llu accepted post-link HELLO subcmd=0x%02X as no-op",
              static_cast<unsigned long long>(session_id), static_cast<unsigned>(subcmd));
}

void LogEnteredInGame(std::uint64_t session_id) {
    WFH_DEBUG("conn", "session %llu entered InGame after WANT_UPDATES",
              static_cast<unsigned long long>(session_id));
}

void LogInGameNoOp(std::uint64_t session_id, std::uint8_t opcode) {
    WFH_TRACE("conn", "session %llu accepted in-game opcode=0x%02X as no-op",
              static_cast<unsigned long long>(session_id), static_cast<unsigned>(opcode));
}

void LogUdpIgnoredClosed(std::uint64_t session_id, std::uint8_t opcode) {
    WFH_TRACE("conn", "session %llu ignored UDP opcode=0x%02X while closed",
              static_cast<unsigned long long>(session_id), static_cast<unsigned>(opcode));
}

void LogUdpPacket(std::uint64_t session_id, std::uint8_t opcode, std::size_t len, ConnState state) {
    WFH_TRACE("conn", "session %llu UDP opcode=0x%02X len=%zu state=%s",
              static_cast<unsigned long long>(session_id), static_cast<unsigned>(opcode), len,
              StateName(state));
}

void LogUdpKeyMismatch(std::uint64_t session_id) {
    WFH_TRACE("conn", "session %llu UDP key echo mismatch/invalid",
              static_cast<unsigned long long>(session_id));
}

auto DefaultPlayerId(std::uint64_t session_id) -> std::int32_t {
    constexpr auto kMaxId = static_cast<std::uint64_t>(std::numeric_limits<std::int32_t>::max());
    return session_id <= kMaxId ? static_cast<std::int32_t>(session_id)
                                : std::numeric_limits<std::int32_t>::max();
}

// Answer the client's D_HANDSHAKE (0x03): ack + the 4 stream definitions + unpause the
// reliable + game-data streams. Without these the client's gameplay streams stay paused,
// so it never accepts world/team data or sends team-select/spawn. Matches the reference
// server's on_d_handshake. ticks are informational (0 is fine).
void EmitUdpStreamHandshake(std::int32_t player_id, std::uint64_t session_id, StepResult& out) {
    out.udp_datagrams.push_back(BuildUdpHandshakeAck(0));
    out.udp_datagrams.push_back(BuildUdpStreamDefs(0, player_id));
    out.udp_datagrams.push_back(BuildUdpStreamUnpause(kReliableStreamId));
    out.udp_datagrams.push_back(BuildUdpStreamUnpause(kGameDataStreamId));
    WFH_DEBUG("conn", "session %llu UDP stream handshake queued (ack+defs+unpause 1,3) pid=%d",
              static_cast<unsigned long long>(session_id), static_cast<int>(player_id));
}

// Reply to a client ping (0x0B) with a pong (0x0C) echoing the client's timestamp.
void EmitUdpPong(const std::uint8_t* body, std::size_t len, StepResult& out) {
    BitReader reader(body, len);
    out.udp_datagrams.push_back(BuildUdpPong(reader.ReadI32().value_or(0)));
}

struct UdpKeyEcho {
    bool saw_key_echo = false;
    bool valid = false;
    std::string key;
};

struct LoginPayload {
    std::string primary;
    std::optional<std::string> secondary;
};

struct ReincarnateRequest {
    std::uint16_t sequence = 0;
    bool is_team_switch = false;
    std::int32_t team_id = 0;
    std::int32_t selected_entry_id = 0;
    std::int32_t base_id = 0;
};

auto ReadUdpKeyEcho(const std::uint8_t* body, std::size_t len) -> UdpKeyEcho {
    BitReader reader(body, len);
    const auto sub = reader.ReadByte();
    if (!sub || *sub != kHelloKeyEcho) {
        return {};
    }

    UdpKeyEcho echo;
    echo.saw_key_echo = true;
    const auto key = reader.ReadString(proto::kMaxStringLen);
    if (!reader.Failed() && key) {
        echo.valid = true;
        echo.key = *key;
    }
    return echo;
}

auto ReadReincarnateRequest(const std::uint8_t* body, std::size_t len)
    -> std::optional<ReincarnateRequest> {
    BitReader reader(body, len);
    const auto sequence = reader.ReadU16();
    const auto length = reader.ReadU16();
    const auto mode = reader.ReadByte();
    const auto first_value = reader.ReadI32();
    const auto second_value = reader.ReadI32();
    if (reader.Failed() || !sequence || !length || !mode || !first_value || !second_value) {
        return std::nullopt;
    }

    ReincarnateRequest request;
    request.sequence = *sequence;
    if (*mode == 1) {
        request.is_team_switch = true;
        request.team_id = *first_value;
        return request;
    }

    const auto extra_x = reader.ReadI32();
    const auto extra_y = reader.ReadI32();
    if (reader.Failed() || !extra_x || !extra_y) {
        return std::nullopt;
    }
    request.selected_entry_id = *first_value;
    request.base_id = *second_value;
    return request;
}

}  // namespace

Connection::Connection(std::uint64_t session_id, ServerConfig cfg, std::string session_key,
                       IncomingCmdQueue& inbound)
    : session_id_(session_id), cfg_(std::move(cfg)), session_key_(std::move(session_key)),
      inbound_(&inbound) {
    WFH_DEBUG("conn", "session %llu created bind_port=%u map=%s",
              static_cast<unsigned long long>(session_id_), static_cast<unsigned>(cfg_.bind_port),
              cfg_.map.c_str());
}

auto Connection::OnAccept() -> std::vector<std::uint8_t> {
    std::vector<std::uint8_t> out;
    // Mirror the proven Python bootstrap exactly: UDP_CONFIG -> SESSION_KEY, then
    // wait for the UDP key echo. VERSION (HELLO sub 0) is a client->server packet;
    // echoing it back here stalls the real client before it sends the key echo
    // (the engine self-connection never linked its UDP until this was removed).
    Append(out, BuildHelloUdpConfig(cfg_.bind_port, cfg_.advertised_udp_host));
    Append(out, BuildHelloSessionKey(session_key_));
    WFH_DEBUG("conn", "session %llu accept burst queued bytes=%zu",
              static_cast<unsigned long long>(session_id_), out.size());
    return out;
}

auto Connection::LinkUdpAndIdentify() -> std::vector<std::uint8_t> {
    std::vector<std::uint8_t> out;
    if (udp_linked_) {
        WFH_TRACE("conn", "session %llu UDP identify ignored; already linked",
                  static_cast<unsigned long long>(session_id_));
        return out;  // idempotent
    }
    udp_linked_ = true;
    if (state_ == ConnState::AwaitingKeyEcho) {
        state_ = ConnState::AwaitingUsername;
    }
    Append(out, BuildIdentifiedUdp());
    WFH_DEBUG("conn", "session %llu UDP linked; state=%s tcp_bytes=%zu",
              static_cast<unsigned long long>(session_id_), StateName(state_), out.size());
    return out;
}

auto Connection::OnUdpPacket(std::uint8_t opcode, const std::uint8_t* body, std::size_t len)
    -> StepResult {
    StepResult result;
    if (state_ == ConnState::Closed) {
        LogUdpIgnoredClosed(session_id_, opcode);
        result.close = true;
        return result;
    }
    LogUdpPacket(session_id_, opcode, len, state_);
    // The reliable-UDP stream handshake can arrive before the key-echo links the
    // endpoint; answer it regardless of state so the client's gameplay streams come up.
    if (opcode == kUdpDHandshakeOpcode) {
        const std::int32_t pid = player_id_ >= 0 ? player_id_ : DefaultPlayerId(session_id_);
        EmitUdpStreamHandshake(pid, session_id_, result);
        return result;
    }
    if (opcode == kUdpPingOpcode) {
        EmitUdpPong(body, len, result);
        return result;
    }
    if (opcode == static_cast<std::uint8_t>(Opcode::Reincarnate)) {
        if (state_ != ConnState::InGame) {
            WFH_TRACE("conn", "session %llu ignored UDP reincarnate before InGame",
                      static_cast<unsigned long long>(session_id_));
            return result;
        }
        if (!HandleUdpReincarnateRequest(body, len, result)) {
            result.close = true;
        }
        return result;
    }
    // The only UDP packet relevant pre-game is the HELLO(sub 1) session-key echo,
    // which links this connection's UDP endpoint. Anything else is ignored until
    // the game-state handlers explicitly validate it.
    if (opcode != static_cast<std::uint8_t>(Opcode::Hello)) {
        return result;
    }
    const UdpKeyEcho echo = ReadUdpKeyEcho(body, len);
    if (!echo.saw_key_echo) {
        return result;
    }
    if (!echo.valid || echo.key != session_key_) {
        LogUdpKeyMismatch(session_id_);
        return result;  // mismatch: ignore (do not advance, do not close)
    }
    result.tcp_out = LinkUdpAndIdentify();
    // In-game UDP gameplay (ACTION/REINCARNATE) is handled in M5.2; for M5.1b we
    // only need the key echo to reach VERIFIED.
    return result;
}

auto Connection::OnTcpData(const std::uint8_t* data, std::size_t len) -> StepResult {
    StepResult result;
    if (state_ == ConnState::Closed) {
        WFH_TRACE("conn", "session %llu ignored TCP bytes while closed",
                  static_cast<unsigned long long>(session_id_));
        result.close = true;
        return result;
    }
    LogTcpRecv(session_id_, len, state_);
    const bool feed_ok = tcp_.Feed(data, len);
    const std::size_t buffered = tcp_.Buffered();
    if (!feed_ok || buffered > limits_.max_buffered_bytes) {
        state_ = ConnState::Closed;
        result.close = true;
        LogTcpFeedRejected(session_id_, feed_ok, buffered);
        return result;
    }

    for (std::size_t processed = 0; processed < limits_.max_frames_per_drain; ++processed) {
        auto frame = tcp_.Next();
        if (tcp_.Failed()) {
            state_ = ConnState::Closed;
            result.close = true;
            return result;
        }
        if (!frame) {
            break;  // no complete frame yet
        }
        LogTcpFrame(session_id_, *frame, state_);
        if (!HandleFrame(*frame, result.tcp_out)) {
            state_ = ConnState::Closed;
            result.close = true;
            LogTcpFrameClosed(session_id_, frame->opcode);
            return result;
        }
    }
    return result;
}

auto Connection::HandleAwaitingKeyEcho(Opcode opcode, BitReader& reader) -> bool {
    // Pre-UDP-link, the only meaningful TCP packet is HELLO(sub 0) version. A
    // mismatched version is the one hard gate -> drop. No other packet is valid yet.
    if (opcode != Opcode::Hello) {
        return false;
    }
    const auto sub = reader.ReadByte();
    if (!sub) {
        return false;
    }
    if (*sub != kHelloVersion) {
        return true;  // other HELLO subtypes here are benign/no-op
    }
    const auto version = reader.ReadI32();
    return !reader.Failed() && version && *version == kProtocolVersion;
}

auto HandlePostLinkHelloNoOp(BitReader& reader, std::uint8_t& accepted_subcmd) -> bool {
    const auto sub = reader.ReadByte();
    if (!sub) {
        return false;
    }
    accepted_subcmd = *sub;
    if (*sub == kHelloPostLinkConfirm) {
        return !reader.Failed();
    }
    if (*sub != kHelloVersion) {
        return false;
    }
    const auto version = reader.ReadI32();
    return !reader.Failed() && version && *version == kProtocolVersion;
}

auto ReadAcceptableString(BitReader& reader) -> std::optional<std::string> {
    const auto value = reader.ReadString(proto::kMaxStringLen);
    if (reader.Failed() || !value || !proto::IsAcceptableString(*value)) {
        return std::nullopt;
    }
    return *value;
}

auto ReadLoginPayload(BitReader reader) -> std::optional<LoginPayload> {
    BitReader direct = reader;
    if (const auto value = ReadAcceptableString(direct)) {
        return LoginPayload{*value, std::nullopt};
    }

    BitReader typed = reader;
    const auto type = typed.ReadByte();
    if (!type) {
        return std::nullopt;
    }

    auto primary = ReadAcceptableString(typed);
    if (!primary) {
        return std::nullopt;
    }

    auto secondary = ReadAcceptableString(typed);
    if (!secondary) {
        return LoginPayload{*primary, std::nullopt};
    }
    return LoginPayload{*primary, *secondary};
}

void Connection::CompleteLoginWithPassword(const std::string& pass,
                                           std::vector<std::uint8_t>& out) {
    inbound_->Push(
        ClientCommand{ClientCommandKind::LoginPassword, session_id_, 0, 0.0F, 0, 0, 0, pass});
    state_ = ConnState::Verified;
    EmitBringup(out);
    inbound_->Push(ClientCommand{ClientCommandKind::ClientConnected, session_id_, 0, 0.0F, 0, 0, 0,
                                 username_});
    WFH_DEBUG("conn", "session %llu password accepted; state=%s bringup_bytes=%zu",
              static_cast<unsigned long long>(session_id_), StateName(state_), out.size());
}

auto Connection::HandleLoginUsername(BitReader& reader, std::vector<std::uint8_t>& out) -> bool {
    const auto login = ReadLoginPayload(reader);
    if (!login) {
        WFH_DEBUG("conn", "session %llu rejected login username",
                  static_cast<unsigned long long>(session_id_));
        return false;
    }
    username_ = login->primary;
    inbound_->Push(
        ClientCommand{ClientCommandKind::LoginUser, session_id_, 0, 0.0F, 0, 0, 0, login->primary});
    if (login->secondary) {
        CompleteLoginWithPassword(*login->secondary, out);
        return true;
    }
    state_ = ConnState::AwaitingPassword;
    Append(out, BuildLoginStatus(true, kLoginStatusAskPassword));
    WFH_DEBUG("conn", "session %llu accepted username len=%zu; state=%s",
              static_cast<unsigned long long>(session_id_), username_.size(), StateName(state_));
    return true;
}

auto Connection::HandleLoginPassword(BitReader& reader, std::vector<std::uint8_t>& out) -> bool {
    const auto login = ReadLoginPayload(reader);
    if (!login) {
        WFH_DEBUG("conn", "session %llu rejected login password",
                  static_cast<unsigned long long>(session_id_));
        return false;
    }
    const std::string& pass = login->secondary ? *login->secondary : login->primary;
    // Login accepted (M5.1b: trust-the-echo; real auth is a follow-up).
    CompleteLoginWithPassword(pass, out);
    return true;
}

auto Connection::HandleBpsRequest(BitReader& reader, std::vector<std::uint8_t>& out) const -> bool {
    const auto requested_rate = reader.ReadI32();
    if (reader.Failed() || !requested_rate) {
        WFH_DEBUG("conn", "session %llu rejected malformed BPS request",
                  static_cast<unsigned long long>(session_id_));
        return false;
    }
    Append(out, BuildBpsReply(*requested_rate));
    LogBpsReply(session_id_, *requested_rate);
    return true;
}

auto Connection::HandleReincarnateRequest(const std::uint8_t* body, std::size_t len) -> bool {
    const auto request = ReadReincarnateRequest(body, len);
    if (!request) {
        WFH_DEBUG("conn", "session %llu rejected malformed reincarnate request",
                  static_cast<unsigned long long>(session_id_));
        return false;
    }

    if (request->is_team_switch) {
        return QueueTeamReincarnate(request->team_id);
    }
    return QueueSpawnReincarnate(request->selected_entry_id, request->base_id);
}

auto Connection::HandleUdpReincarnateRequest(const std::uint8_t* body, std::size_t len,
                                             StepResult& out) -> bool {
    const auto request = ReadReincarnateRequest(body, len);
    if (!request) {
        WFH_DEBUG("conn", "session %llu rejected malformed UDP reincarnate request",
                  static_cast<unsigned long long>(session_id_));
        return false;
    }

    const bool queued = request->is_team_switch
                            ? QueueTeamReincarnate(request->team_id)
                            : QueueSpawnReincarnate(request->selected_entry_id, request->base_id);
    if (!queued) {
        return false;
    }

    out.udp_out =
        BuildUdpAck(UdpAckSpec{static_cast<std::uint8_t>(Opcode::Reincarnate), request->sequence});
    WFH_TRACE("conn", "session %llu queued UDP ack opcode=0x%02X seq=%u bytes=%zu",
              static_cast<unsigned long long>(session_id_),
              static_cast<unsigned>(Opcode::Reincarnate), static_cast<unsigned>(request->sequence),
              out.udp_out.size());

    if (request->is_team_switch) {
        // Mirror the reference team-switch reply: push the UPDATE_STATS (0x1C) record on
        // UDP to the requester. This is what makes the client refresh its roster list and
        // ACTIVATE the entry-map / respawn selector (the code-17 REINCARNATE confirm the
        // client already gets shows "you changed teams", but the list/selector stay inert
        // until this record arrives). The world bridge still records the team for spawn
        // validation from the queued command above.
        const std::int32_t pid = player_id_ >= 0 ? player_id_ : DefaultPlayerId(session_id_);
        out.udp_datagrams.push_back(BuildUdpUpdateStats(pid, request->team_id));
        WFH_DEBUG("conn", "session %llu team-switch UPDATE_STATS queued team=%d pid=%d",
                  static_cast<unsigned long long>(session_id_), static_cast<int>(request->team_id),
                  static_cast<int>(pid));
    }
    return true;
}

auto Connection::QueueTeamReincarnate(std::int32_t team_id) -> bool {
    if (team_id != 1 && team_id != 2) {
        WFH_DEBUG("conn", "session %llu rejected reincarnate team=%d",
                  static_cast<unsigned long long>(session_id_), static_cast<int>(team_id));
        return false;
    }
    inbound_->Push(
        ClientCommand{ClientCommandKind::Reincarnate, session_id_, 0, 0.0F, team_id, 0, 0, {}});
    WFH_DEBUG("conn", "session %llu queued reincarnate team switch team=%d",
              static_cast<unsigned long long>(session_id_), static_cast<int>(team_id));
    return true;
}

auto Connection::QueueSpawnReincarnate(std::int32_t selected_entry_id, std::int32_t base_id)
    -> bool {
    if (selected_entry_id < 0 || base_id < 0) {
        WFH_DEBUG("conn", "session %llu rejected reincarnate selected=%d base=%d",
                  static_cast<unsigned long long>(session_id_), static_cast<int>(selected_entry_id),
                  static_cast<int>(base_id));
        return false;
    }

    inbound_->Push(ClientCommand{
        ClientCommandKind::Reincarnate, session_id_, 0, 0.0F, 0, selected_entry_id, base_id, {}});
    WFH_DEBUG("conn", "session %llu queued reincarnate spawn selected=%d base=%d",
              static_cast<unsigned long long>(session_id_), static_cast<int>(selected_entry_id),
              static_cast<int>(base_id));
    return true;
}

auto Connection::BuildUdpAck(UdpAckSpec spec) -> std::vector<std::uint8_t> {
    proto::BitWriter writer;
    writer.WriteByte(kUdpAckOpcode);
    writer.WriteU16(++udp_outgoing_sequence_);
    writer.WriteU16(kUdpAckLength);
    writer.WriteByte(kUdpAckSubcmd);
    writer.WriteByte(spec.acked_opcode);
    writer.WriteU16(spec.acked_sequence);
    return writer.Bytes();
}

auto Connection::HandleFrame(const Frame& frame, std::vector<std::uint8_t>& out) -> bool {
    // Reject any opcode that is not in the known set before doing anything with it.
    if (!proto::IsKnownOpcode(frame.opcode)) {
        LogUnknownOpcode(session_id_, frame.opcode);
        return false;
    }
    BitReader reader(frame.body.data(), frame.body.size());
    const auto opcode = static_cast<Opcode>(frame.opcode);
    if (opcode == Opcode::Generic) {
        LogGenericNoOp(session_id_, state_);
        return true;
    }

    switch (state_) {
    case ConnState::AwaitingKeyEcho: {
        const bool ok = HandleAwaitingKeyEcho(opcode, reader);
        if (!ok) {
            LogAwaitingKeyEchoRejected(session_id_, frame.opcode);
        }
        return ok;
    }

    case ConnState::AwaitingUsername:
        if (opcode == Opcode::Hello) {
            std::uint8_t accepted_subcmd = 0;
            const bool ok = HandlePostLinkHelloNoOp(reader, accepted_subcmd);
            if (ok) {
                LogPostLinkHelloNoOp(session_id_, accepted_subcmd);
            }
            return ok;
        }
        return opcode == Opcode::Login && HandleLoginUsername(reader, out);

    case ConnState::AwaitingPassword:
        return opcode == Opcode::Login && HandleLoginPassword(reader, out);

    case ConnState::Verified:
        // WANT_UPDATES moves to in-game; the translation ACK and other post-login
        // control packets are accepted as no-ops here (engine bridge acts later).
        if (opcode == Opcode::Bps) {
            return HandleBpsRequest(reader, out);
        }
        if (opcode == Opcode::WantUpdates) {
            state_ = ConnState::InGame;
            inbound_->Push(
                ClientCommand{ClientCommandKind::WantUpdates, session_id_, 0, 0.0F, 0, 0, 0, {}});
            LogEnteredInGame(session_id_);
        } else {
            LogVerifiedNoOp(session_id_, frame.opcode);
        }
        return true;

    case ConnState::InGame:
        // Full in-game TCP handling (reincarnate, chat, etc.) is M5.2/M6; for now
        // accept known opcodes without acting (the engine bridge does the work).
        if (opcode == Opcode::Bps) {
            return HandleBpsRequest(reader, out);
        }
        if (opcode == Opcode::Reincarnate) {
            return HandleReincarnateRequest(frame.body.data(), frame.body.size());
        }
        LogInGameNoOp(session_id_, frame.opcode);
        return true;

    case ConnState::Closed: return false;
    }
    return false;
}

void Connection::EmitBringup(std::vector<std::uint8_t>& out) {
    // VERIFIED is sent on UDP when linked; we always have a UDP link by this state,
    // but TCP is a valid fallback the client also accepts, so send it on TCP here
    // (the M5.1b socket layer does not yet have a per-session UDP send path).
    const std::int32_t pid = player_id_ >= 0 ? player_id_ : DefaultPlayerId(session_id_);
    Append(out, BuildHelloVerified());
    Append(out, BuildTeamInfo());
    Append(out, BuildLoginStatus(true, kLoginStatusOk));
    Append(out, BuildPlayer(pid, false));
    Append(out, BuildGameClock(0));
    Append(out, BuildMotd("Wulf Forge Headless"));
    Append(out, BuildBehavior());
    Append(out, BuildTranslation());
    Append(out, BuildAddToRoster(pid, kJoinTeamUnassigned, username_, ""));
    Append(out, BuildWorldStats(cfg_.map));
    WFH_DEBUG("conn", "session %llu emitted bringup pid=%d bytes=%zu",
              static_cast<unsigned long long>(session_id_), static_cast<int>(pid), out.size());
}

}  // namespace wfh::server
// NOLINTEND(cppcoreguidelines-avoid-do-while,cppcoreguidelines-pro-type-vararg)
