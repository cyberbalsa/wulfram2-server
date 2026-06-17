// NOLINTBEGIN(portability-avoid-pragma-once)
// pragma once is the project-wide include-guard convention; intentional.
#pragma once
// NOLINTEND(portability-avoid-pragma-once)

#include "wfh/proto/bitstream.hpp"
#include "wfh/proto/framing.hpp"
#include "wfh/proto/opcodes.hpp"
#include "wfh/server/queues.hpp"
#include "wfh/server/server_config.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace wfh::server {

// The per-connection handshake/session state machine. This is the pure protocol
// brain: it consumes inbound TCP frames + UDP datagrams and produces (a) outbound
// wire bytes to send and (b) validated ClientCommands for the engine queue. It owns
// NO socket and touches NO engine memory — it is fully host-testable by feeding it
// bytes. The socket layer (Acceptor) drives it.

// NOLINTNEXTLINE(performance-enum-size)
enum class ConnState : int {
    AwaitingKeyEcho,   // sent UDP_CONFIG + SESSION_KEY; waiting for the UDP key echo
    AwaitingUsername,  // UDP linked (IDENTIFIED_UDP sent); waiting for LOGIN username
    AwaitingPassword,  // got username, asked for password; waiting for LOGIN password
    Verified,          // logged in; bring-up packets sent; pre-updates
    InGame,            // client sent WANT_UPDATES; receiving world state
    Closed,            // dropped (protocol violation, flood, or peer close)
};

// What a connection wants the socket layer to do after a step.
struct StepResult {
    std::vector<std::uint8_t> tcp_out;  // bytes to send on TCP (already framed)
    std::vector<std::uint8_t> udp_out;  // single UDP datagram to the source endpoint
    // Multiple discrete UDP datagrams to the source endpoint, sent in order (each is
    // one datagram). Used by the reliable-stream handshake (0x02 ack + 0x03 defs +
    // 0x04 unpause x2) where the client expects separate packets.
    std::vector<std::vector<std::uint8_t>> udp_datagrams;
    bool close = false;  // drop the connection (violation/flood)
};

// Flood/sanity caps applied per connection. Conservative; a 2006 client stays well
// under these, an attacker hits them and gets dropped.
constexpr std::size_t kDefaultMaxBufferedBytes = std::size_t{64} * 1024;  // inbound backlog cap
constexpr std::size_t kDefaultMaxFramesPerDrain = 256;                    // frames per Feed call
struct ConnLimits {
    std::size_t max_buffered_bytes = kDefaultMaxBufferedBytes;
    std::size_t max_frames_per_drain = kDefaultMaxFramesPerDrain;
};

class Connection {
public:
    Connection(std::uint64_t session_id, ServerConfig cfg, std::string session_key,
               IncomingCmdQueue& inbound);

    // Called once on accept: returns the initial bytes to send (HELLO UDP_CONFIG +
    // VERSION + SESSION_KEY).
    [[nodiscard]] auto OnAccept() -> std::vector<std::uint8_t>;

    // Feed a raw TCP recv() chunk. Parses all complete frames, advances the state
    // machine, enqueues commands, and returns outbound bytes / a close request.
    // Fail-closed: any framing error, unknown/out-of-order opcode, oversize, flood,
    // or reader under-run sets close = true.
    [[nodiscard]] auto OnTcpData(const std::uint8_t* data, std::size_t len) -> StepResult;

    // Feed a UDP datagram body (already de-framed by the caller: opcode + body).
    // Used for the key echo (HELLO sub 1) and in-game inputs. Returns outbound TCP
    // bytes if the step warrants them (e.g. IDENTIFIED_UDP is sent on TCP here).
    [[nodiscard]] auto OnUdpPacket(std::uint8_t opcode, const std::uint8_t* body, std::size_t len)
        -> StepResult;

    [[nodiscard]] auto State() const -> ConnState { return state_; }
    [[nodiscard]] auto SessionId() const -> std::uint64_t { return session_id_; }
    [[nodiscard]] auto SessionKey() const -> const std::string& { return session_key_; }
    [[nodiscard]] auto PlayerId() const -> std::int32_t { return player_id_; }
    [[nodiscard]] auto UdpLinked() const -> bool { return udp_linked_; }

    // Called by the Acceptor when this connection's UDP endpoint is confirmed (the
    // key echo matched). Advances past AwaitingKeyEcho and returns IDENTIFIED_UDP +
    // (the client now proceeds to LOGIN). Idempotent.
    [[nodiscard]] auto LinkUdpAndIdentify() -> std::vector<std::uint8_t>;

    // Assign the engine-allocated player id once login completes (the engine side
    // owns id allocation; do not trust the client).
    void SetPlayerId(std::int32_t player_id) { player_id_ = player_id; }

private:
    struct UdpAckSpec {
        std::uint8_t acked_opcode = 0;
        std::uint16_t acked_sequence = 0;
    };

    // Handle one fully-received TCP frame. Returns false to close the connection.
    [[nodiscard]] auto HandleFrame(const proto::Frame& frame, std::vector<std::uint8_t>& out)
        -> bool;

    // Per-state frame handlers (kept separate so HandleFrame stays simple). Each
    // returns false to drop the connection.
    [[nodiscard]] static auto HandleAwaitingKeyEcho(proto::Opcode opcode, proto::BitReader& reader)
        -> bool;
    [[nodiscard]] auto HandleLoginUsername(proto::BitReader& reader, std::vector<std::uint8_t>& out)
        -> bool;
    [[nodiscard]] auto HandleLoginPassword(proto::BitReader& reader, std::vector<std::uint8_t>& out)
        -> bool;
    [[nodiscard]] auto HandleBpsRequest(proto::BitReader& reader,
                                        std::vector<std::uint8_t>& out) const -> bool;
    [[nodiscard]] auto HandleReincarnateRequest(const std::uint8_t* body, std::size_t len) -> bool;
    [[nodiscard]] auto HandleUdpReincarnateRequest(const std::uint8_t* body, std::size_t len,
                                                   StepResult& out) -> bool;
    // Decode an in-game ACTION_DUMP (0x09) / ACTION_UPDATE (0x0A) body and enqueue one validated
    // ActionInput command per drivable channel (channel in range, value clamped to [-1,1]). The
    // server maps session_id -> owned entity; the client-asserted entity id is never trusted.
    void HandleUdpActionInput(std::uint8_t opcode, const std::uint8_t* body, std::size_t len);
    [[nodiscard]] auto QueueTeamReincarnate(std::int32_t team_id) -> bool;
    [[nodiscard]] auto QueueSpawnReincarnate(std::int32_t selected_entry_id, std::int32_t base_id)
        -> bool;
    [[nodiscard]] auto BuildUdpAck(UdpAckSpec spec) -> std::vector<std::uint8_t>;

    void CompleteLoginWithPassword(const std::string& pass, std::vector<std::uint8_t>& out);

    // Build the post-login bring-up burst (VERIFIED..WORLD_STATS) into `out`.
    void EmitBringup(std::vector<std::uint8_t>& out);

    std::uint64_t session_id_;
    ServerConfig cfg_;
    std::string session_key_;
    // Non-owning; the Acceptor owns the queue and outlives every Connection. Stored
    // as a pointer (not a reference) so the class stays assignable and to satisfy
    // the no-ref-data-member guideline.
    IncomingCmdQueue* inbound_;

    proto::TcpFrameAccumulator tcp_;
    ConnState state_ = ConnState::AwaitingKeyEcho;
    ConnLimits limits_;
    bool udp_linked_ = false;
    std::int32_t player_id_ = -1;
    std::uint16_t udp_outgoing_sequence_ = 0;
    std::string username_;
};

}  // namespace wfh::server
