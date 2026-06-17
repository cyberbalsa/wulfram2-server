#include "wfh/server/acceptor.hpp"

#include "wfh/proto/framing.hpp"
#include "wfh/proto/opcodes.hpp"
#include "wfh/server/connection.hpp"

// WinSock2 must precede windows.h. The project wraps third-party headers in a
// warning push/pop where they trip /W4; the SDK socket headers are clean enough
// under /W4 but we keep the include order strict.
#ifdef _MSC_VER
#pragma warning(push, 0)
#endif
#include <winsock2.h>

#include <ws2tcpip.h>
#ifdef _MSC_VER
#pragma warning(pop)
#endif

#include "wfh/log.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <map>
#include <memory>
#include <optional>
#include <random>
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

constexpr int kListenBacklog = 8;
constexpr std::size_t kRecvChunk = 4096;
constexpr long kSelectTimeoutUs = 50000;  // 50 ms wakeups so Stop() is responsive
constexpr unsigned kSessionMixShift = 16;
constexpr std::uint64_t kSessionLowMask = 0xffffU;
constexpr int kSessionKeyNibbles = 12;
constexpr int kBitsPerNibble = 4;
constexpr int kTopNibbleShift = (kSessionKeyNibbles - 1) * kBitsPerNibble;
constexpr std::uint64_t kNibbleMask = 0x0FU;
constexpr std::string_view kHexDigits = "0123456789abcdef";
constexpr std::size_t kUdpLengthPrefixSize = 2;
constexpr std::size_t kUdpOpcodeSize = 1;
constexpr unsigned kByteShift = 8;

// DIAGNOSTIC (temporary): render a byte span as space-separated lowercase hex so we
// can compare the engine's raw wire bytes against the known-good Python reference.
auto HexDump(const std::uint8_t* data, std::size_t len) -> std::string {
    std::string out;
    constexpr std::size_t kMaxDumpBytes = 64;
    const std::size_t shown = len < kMaxDumpBytes ? len : kMaxDumpBytes;
    out.reserve(shown * 3);
    for (std::size_t i = 0; i < shown; ++i) {
        // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        const std::uint8_t byte = data[i];
        out.push_back(kHexDigits.at(byte >> kBitsPerNibble));
        out.push_back(kHexDigits.at(byte & kNibbleMask));
        out.push_back(' ');
    }
    return out;
}

// Generate a short random session key the client must echo over UDP to link its
// endpoint. Not a security token (the protocol is trust-the-echo), just a nonce.
auto MakeSessionKey(std::uint64_t session_id) -> std::string {
    static std::mt19937 rng(std::random_device{}());
    const std::uint64_t mixed =
        (static_cast<std::uint64_t>(rng()) << kSessionMixShift) ^ (session_id & kSessionLowMask);
    std::string key = "Key";
    for (int shift = kTopNibbleShift; shift >= 0; shift -= kBitsPerNibble) {
        const auto index =
            static_cast<std::size_t>((mixed >> static_cast<unsigned>(shift)) & kNibbleMask);
        key.push_back(kHexDigits.at(index));
    }
    return key;
}

}  // namespace

// One accepted TCP client: its socket, its UDP peer address (once linked), and its
// protocol state machine.
struct TcpClient {
    SOCKET sock = INVALID_SOCKET;
    std::unique_ptr<Connection> conn;
    sockaddr_in udp_addr{};
    bool udp_addr_known = false;
};

struct Acceptor::Impl {
    SOCKET listen_sock = INVALID_SOCKET;
    SOCKET udp_sock = INVALID_SOCKET;
    std::map<std::uint64_t, TcpClient> clients;  // session_id -> client
    std::uint64_t next_session_id = 1;
    bool wsa_started = false;
};

struct FallbackPort {
    std::uint16_t value = 0;
};

struct RequestedPort {
    std::uint16_t value = 0;
};

namespace {

void SendBytes(SOCKET sock, const std::vector<std::uint8_t>& bytes);
void SendUdpBytes(SOCKET sock, const sockaddr_in& peer_addr,
                  const std::vector<std::uint8_t>& bytes);
auto ReadBoundPort(SOCKET sock, FallbackPort fallback) -> std::uint16_t;

// Send a step's UDP output to `peer`: the single udp_out (if any) then each discrete
// udp_datagram (the reliable-stream handshake emits several separate datagrams).
void SendStepUdp(SOCKET sock, const sockaddr_in& peer, const StepResult& step) {
    if (!step.udp_out.empty()) {
        SendUdpBytes(sock, peer, step.udp_out);
    }
    for (const std::vector<std::uint8_t>& datagram : step.udp_datagrams) {
        if (!datagram.empty()) {
            SendUdpBytes(sock, peer, datagram);
        }
    }
}

// Some client UDP packets arrive as raw [opcode][body], and some include a
// two-byte total-length envelope before that payload. This mirrors the old
// Python server's working UdpEnvelope path; strict [seq][opcode][body] remains
// supported via proto::DecodeUdpFrame and is tried first by HandleUdpDatagram.
auto DecodeRawUdpPayload(const std::uint8_t* data, std::size_t len)
    -> std::optional<proto::UdpFrame> {
    if (len < kUdpOpcodeSize) {
        return std::nullopt;
    }

    std::size_t payload_offset = 0;
    std::size_t payload_len = len;
    if (len > kUdpLengthPrefixSize) {
        // NOLINTBEGIN(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        const auto declared = static_cast<std::uint16_t>(
            (static_cast<std::uint16_t>(data[0]) << kByteShift) | data[1]);
        // NOLINTEND(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        if (declared == len) {
            payload_offset = kUdpLengthPrefixSize;
            payload_len -= kUdpLengthPrefixSize;
        }
    }

    if (payload_len < kUdpOpcodeSize) {
        return std::nullopt;
    }

    proto::UdpFrame frame;
    // NOLINTBEGIN(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    const std::uint8_t* payload = data + payload_offset;
    frame.opcode = payload[0];
    frame.body.assign(payload + kUdpOpcodeSize, payload + payload_len);
    // NOLINTEND(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    return frame;
}

auto TryLinkUdpFrame(Acceptor::Impl& impl, const proto::UdpFrame& frame, const sockaddr_in& from)
    -> bool {
    for (auto& [id, client] : impl.clients) {
        if (client.conn->UdpLinked()) {
            continue;
        }
        const auto step =
            client.conn->OnUdpPacket(frame.opcode, frame.body.data(), frame.body.size());
        if (client.conn->UdpLinked()) {
            client.udp_addr = from;
            client.udp_addr_known = true;
            SendBytes(client.sock, step.tcp_out);
            SendStepUdp(impl.udp_sock, from, step);
            WFH_DEBUG("net", "linked UDP endpoint for session %llu opcode=0x%02X bytes=%zu",
                      static_cast<unsigned long long>(id), static_cast<unsigned>(frame.opcode),
                      frame.body.size());
            return true;  // linked exactly one session
        }
        if (!step.udp_datagrams.empty() || !step.udp_out.empty()) {
            // Pre-link UDP response (e.g. the D_HANDSHAKE stream setup arrives before
            // the key echo links the endpoint). Answer to the source endpoint.
            SendStepUdp(impl.udp_sock, from, step);
            WFH_DEBUG("net", "session %llu pre-link UDP response opcode=0x%02X datagrams=%zu",
                      static_cast<unsigned long long>(id), static_cast<unsigned>(frame.opcode),
                      step.udp_datagrams.size());
            return true;
        }
    }
    return false;
}

auto SameUdpEndpoint(const sockaddr_in& left, const sockaddr_in& right) -> bool {
    return left.sin_family == right.sin_family && left.sin_port == right.sin_port &&
           left.sin_addr.s_addr == right.sin_addr.s_addr;
}

auto TryRouteLinkedUdpFrame(Acceptor::Impl& impl, const proto::UdpFrame& frame,
                            const sockaddr_in& from) -> bool {
    if (!proto::IsKnownOpcode(frame.opcode)) {
        return false;
    }
    auto match =
        std::find_if(impl.clients.begin(), impl.clients.end(), [&](const auto& item) -> bool {
            const TcpClient& client = item.second;
            return client.udp_addr_known && SameUdpEndpoint(client.udp_addr, from);
        });
    if (match == impl.clients.end()) {
        return false;
    }
    auto& [id, client] = *match;
    const auto step = client.conn->OnUdpPacket(frame.opcode, frame.body.data(), frame.body.size());
    SendBytes(client.sock, step.tcp_out);
    SendStepUdp(impl.udp_sock, from, step);
    WFH_TRACE("net", "routed linked UDP session=%llu opcode=0x%02X bytes=%zu close=%d",
              static_cast<unsigned long long>(id), static_cast<unsigned>(frame.opcode),
              frame.body.size(), step.close ? 1 : 0);
    return true;
}

// Route ONE UDP packet (key echo) to the matching not-yet-linked / linked connection.
void HandleOneUdpPacket(Acceptor::Impl& impl, const std::uint8_t* data, std::size_t len,
                        const sockaddr_in& from) {
    if (const auto seq_frame = proto::DecodeUdpFrame(data, len);
        seq_frame && TryLinkUdpFrame(impl, *seq_frame, from)) {
        return;
    }

    if (const auto raw_frame = DecodeRawUdpPayload(data, len)) {
        if (TryLinkUdpFrame(impl, *raw_frame, from)) {
            return;
        }
        if (TryRouteLinkedUdpFrame(impl, *raw_frame, from)) {
            return;
        }
    }

    if (const auto seq_frame = proto::DecodeUdpFrame(data, len)) {
        if (TryRouteLinkedUdpFrame(impl, *seq_frame, from)) {
            return;
        }
    }
    WFH_TRACE("net", "UDP packet ignored; no matching pending session");
}

// HELLO subtype bytes and handshake-packet header sizes (named so the splitter below
// is free of magic numbers).
constexpr std::uint8_t kHelloSubVersion = 0x00;   // [13][00][i32 version]
constexpr std::uint8_t kHelloSubConfig = 0x01;    // [13][01][u16 strlen][string]
constexpr std::uint8_t kHelloSubConfirm = 0x02;   // [13][02]
constexpr std::uint8_t kHelloSubVerified = 0x03;  // [13][03]
constexpr std::uint8_t kHelloSubNone = 0xFF;      // sentinel: too short to hold a subtype
constexpr std::size_t kHelloThereHeader = 3;      // opcode + u16 strlen
constexpr std::size_t kHelloConfigHeader = 4;     // opcode + subtype + u16 strlen
constexpr std::size_t kHelloVersionLen = 6;       // opcode + subtype + i32
constexpr std::size_t kHelloShortLen = 2;         // opcode + subtype only

// Length of a handshake packet whose payload ends with a u16-BE-length string: the fixed
// header bytes plus that embedded string length (the u16 sits in the 2 bytes ending the
// header). Clamped to the datagram length.
auto StringPacketLength(const std::uint8_t* data, std::size_t len, std::size_t header)
    -> std::size_t {
    if (len < header) {
        return len;
    }
    // NOLINTBEGIN(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    const std::size_t embedded =
        (static_cast<std::size_t>(data[header - 2]) << kByteShift) | data[header - 1];
    // NOLINTEND(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    const std::size_t pkt = header + embedded;
    return pkt <= len ? pkt : len;
}

// Length of the FIRST handshake packet in a (possibly batched) UDP datagram. The engine
// can flush several HELLO/ROOT packets into one datagram (e.g. "Hello There" +
// key-echo), so we split on the known handshake shapes; anything else consumes the rest
// of the datagram (single packet / seq-framed game traffic).
auto FirstUdpPacketLength(const std::uint8_t* data, std::size_t len) -> std::size_t {
    if (len < 1) {
        return len;
    }
    // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    const std::uint8_t opcode = data[0];
    if (opcode == static_cast<std::uint8_t>(proto::Opcode::HelloThere)) {
        return StringPacketLength(data, len, kHelloThereHeader);
    }
    if (opcode != static_cast<std::uint8_t>(proto::Opcode::Hello)) {
        return len;  // unknown / seq-framed game packet: consume the whole datagram
    }
    // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    const std::uint8_t sub = len >= kHelloShortLen ? data[1] : kHelloSubNone;
    if (sub == kHelloSubConfig) {
        return StringPacketLength(data, len, kHelloConfigHeader);
    }
    if (sub == kHelloSubVersion) {
        return len < kHelloVersionLen ? len : kHelloVersionLen;
    }
    if (sub == kHelloSubConfirm || sub == kHelloSubVerified) {
        return len < kHelloShortLen ? len : kHelloShortLen;
    }
    return len;
}

// Route a UDP datagram, splitting any batched handshake packets first.
void HandleUdpDatagram(Acceptor::Impl& impl, const std::uint8_t* data, std::size_t len,
                       const sockaddr_in& from) {
    WFH_TRACE("net", "UDP datagram received bytes=%zu clients=%zu", len, impl.clients.size());
    std::size_t cursor = 0;
    while (cursor < len) {
        // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        std::size_t pkt = FirstUdpPacketLength(data + cursor, len - cursor);
        if (pkt == 0 || pkt > len - cursor) {
            pkt = len - cursor;
        }
        // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        HandleOneUdpPacket(impl, data + cursor, pkt, from);
        cursor += pkt;
    }
}

// Send a byte buffer on a connected TCP socket (centralizes the SDK char* cast).
void SendBytes(SOCKET sock, const std::vector<std::uint8_t>& bytes) {
    if (bytes.empty()) {
        return;
    }
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    send(sock, reinterpret_cast<const char*>(bytes.data()), static_cast<int>(bytes.size()), 0);
}

void SendUdpBytes(SOCKET sock, const sockaddr_in& peer_addr,
                  const std::vector<std::uint8_t>& bytes) {
    if (bytes.empty()) {
        return;
    }
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    sendto(sock, reinterpret_cast<const char*>(bytes.data()), static_cast<int>(bytes.size()), 0,
           // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
           reinterpret_cast<const sockaddr*>(&peer_addr), sizeof(peer_addr));
    WFH_TRACE("net", "sent UDP step response bytes=%zu", bytes.size());
}

// Accept one pending TCP connection, register it, and send its HELLO burst.
void AcceptNewConnection(Acceptor::Impl& impl, const ServerConfig& cfg, IncomingCmdQueue& inbound) {
    sockaddr_in peer{};
    int peer_len = sizeof(peer);
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    const SOCKET sock = accept(impl.listen_sock, reinterpret_cast<sockaddr*>(&peer), &peer_len);
    if (sock == INVALID_SOCKET) {
        return;
    }
    u_long nonblock = 1;
    ioctlsocket(sock, static_cast<long>(FIONBIO), &nonblock);
    const std::uint64_t sid = impl.next_session_id++;
    TcpClient client;
    client.sock = sock;
    client.conn = std::make_unique<Connection>(sid, cfg, MakeSessionKey(sid), inbound);
    const auto hello = client.conn->OnAccept();
    SendBytes(sock, hello);
    impl.clients.emplace(sid, std::move(client));
    WFH_INFO("net", "accepted TCP session %llu", static_cast<unsigned long long>(sid));
    WFH_DEBUG("net", "sent TCP accept burst for session %llu bytes=%zu",
              static_cast<unsigned long long>(sid), hello.size());
}

// Read one UDP datagram (if any) and route it to the matching connection.
void PumpUdp(Acceptor::Impl& impl) {
    std::array<std::uint8_t, kRecvChunk> buf{};
    sockaddr_in from{};
    int from_len = sizeof(from);
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    const int count = recvfrom(impl.udp_sock, reinterpret_cast<char*>(buf.data()),
                               static_cast<int>(buf.size()), 0,
                               // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
                               reinterpret_cast<sockaddr*>(&from), &from_len);
    if (count > 0) {
        // Verbose wire diagnostic: hex of the raw datagram + source port. (Reads only
        // the receive buffer — safe in host tests, unlike engine-memory probes which
        // belong in the injected DLL tick.)
        const std::string hex = HexDump(buf.data(), static_cast<std::size_t>(count));
        WFH_DEBUG("net", "recvfrom UDP bytes=%d srcport=%u hex=[ %s]", count,
                  static_cast<unsigned>(ntohs(from.sin_port)), hex.c_str());
        HandleUdpDatagram(impl, buf.data(), static_cast<std::size_t>(count), from);
    } else if (count == SOCKET_ERROR) {
        WFH_DEBUG("net", "recvfrom UDP failed (%d)", WSAGetLastError());
    }
}

// Service one readable TCP client; returns true if it should be reaped (dead/dropped).
auto PumpTcpClient(std::uint64_t session_id, TcpClient& client) -> bool {
    std::array<std::uint8_t, kRecvChunk> buf{};
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    auto* raw_buf = reinterpret_cast<char*>(buf.data());
    const int count = recv(client.sock, raw_buf, static_cast<int>(buf.size()), 0);
    if (count <= 0) {
        WFH_DEBUG("net", "TCP session %llu recv closed/error count=%d wsa=%d",
                  static_cast<unsigned long long>(session_id), count, WSAGetLastError());
        return true;  // peer closed or error
    }
    {
        const std::string hex = HexDump(buf.data(), static_cast<std::size_t>(count));
        WFH_DEBUG("net", "TCP session %llu recv bytes=%d hex=[ %s]",
                  static_cast<unsigned long long>(session_id), count, hex.c_str());
    }
    const auto step = client.conn->OnTcpData(buf.data(), static_cast<std::size_t>(count));
    SendBytes(client.sock, step.tcp_out);
    if (!step.tcp_out.empty()) {
        WFH_TRACE("net", "TCP session %llu sent response bytes=%zu",
                  static_cast<unsigned long long>(session_id), step.tcp_out.size());
    }
    return step.close;
}

void SendReliableOutbound(TcpClient& client, const OutboundMessage& msg) {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    send(client.sock, reinterpret_cast<const char*>(msg.bytes.data()),
         static_cast<int>(msg.bytes.size()), 0);
    WFH_TRACE("net", "sent reliable outbound session=%llu bytes=%zu",
              static_cast<unsigned long long>(msg.session_id), msg.bytes.size());
}

void SendUnreliableOutbound(SOCKET udp_sock, TcpClient& client, const OutboundMessage& msg) {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    sendto(udp_sock, reinterpret_cast<const char*>(msg.bytes.data()),
           static_cast<int>(msg.bytes.size()), 0,
           // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
           reinterpret_cast<const sockaddr*>(&client.udp_addr), sizeof(client.udp_addr));
    WFH_TRACE("net", "sent unreliable outbound session=%llu bytes=%zu",
              static_cast<unsigned long long>(msg.session_id), msg.bytes.size());
}

void FlushOneOutbound(Acceptor::Impl& impl, const OutboundMessage& msg) {
    auto it = impl.clients.find(msg.session_id);
    if (it == impl.clients.end()) {
        WFH_DEBUG("net", "dropped outbound for unknown session %llu bytes=%zu",
                  static_cast<unsigned long long>(msg.session_id), msg.bytes.size());
        return;
    }
    if (msg.reliable) {
        SendReliableOutbound(it->second, msg);
        return;
    }
    if (it->second.udp_addr_known) {
        SendUnreliableOutbound(impl.udp_sock, it->second, msg);
        return;
    }
    WFH_TRACE("net", "deferred/dropped unreliable outbound before UDP link session=%llu",
              static_cast<unsigned long long>(msg.session_id));
}

// Drain engine/relay outbound messages and send them per session (TCP or UDP).
void FlushOutboundMessages(Acceptor::Impl& impl, OutboundStateQueue& outbound) {
    auto messages = outbound.DrainAll();
    if (!messages.empty()) {
        WFH_TRACE("net", "flushing outbound messages count=%zu", messages.size());
    }
    for (const auto& msg : messages) {
        FlushOneOutbound(impl, msg);
    }
}

void ReapClients(Acceptor::Impl& impl, IncomingCmdQueue& inbound,
                 const std::vector<std::uint64_t>& dead) {
    for (const std::uint64_t id : dead) {
        auto it = impl.clients.find(id);
        if (it == impl.clients.end()) {
            continue;
        }
        if (it->second.sock != INVALID_SOCKET) {
            closesocket(it->second.sock);
            it->second.sock = INVALID_SOCKET;
        }
        inbound.Push(ClientCommand{ClientCommandKind::Disconnected, id});
        WFH_INFO("net", "reaped TCP session %llu", static_cast<unsigned long long>(id));
        impl.clients.erase(it);
    }
}

auto StartWinsock(Acceptor::Impl& impl) -> bool {
    constexpr BYTE kWinsockMajor = 2;
    constexpr BYTE kWinsockMinor = 2;
    WFH_TRACE("net", "starting WinSock %u.%u", static_cast<unsigned>(kWinsockMajor),
              static_cast<unsigned>(kWinsockMinor));
    WSADATA wsa{};
    if (WSAStartup(MAKEWORD(kWinsockMajor, kWinsockMinor), &wsa) != 0) {
        WFH_FATAL("net", "WSAStartup failed (%d)", WSAGetLastError());
        return false;
    }
    impl.wsa_started = true;
    WFH_DEBUG("net", "WinSock started");
    return true;
}

auto OpenSockets(Acceptor::Impl& impl) -> bool {
    impl.listen_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    impl.udp_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (impl.listen_sock != INVALID_SOCKET && impl.udp_sock != INVALID_SOCKET) {
        WFH_DEBUG("net", "opened TCP/UDP sockets");
        return true;
    }
    WFH_FATAL("net", "socket() failed (%d)", WSAGetLastError());
    return false;
}

void EnableReuseAddress(SOCKET sock) {
    const BOOL yes = TRUE;
    // reinterpret_cast to the SDK's char* optval is the documented setsockopt idiom.
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&yes), sizeof(yes));
}

auto BindTcpUdp(Acceptor::Impl& impl, RequestedPort requested) -> std::optional<std::uint16_t> {
    WFH_DEBUG("net", "binding TCP/UDP requested_port=%u", static_cast<unsigned>(requested.value));
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(requested.value);

    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    const int tcp_bound = bind(impl.listen_sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
    if (tcp_bound == SOCKET_ERROR) {
        WFH_FATAL("net", "bind(:%u) failed (%d)", static_cast<unsigned>(requested.value),
                  WSAGetLastError());
        return std::nullopt;
    }

    const std::uint16_t actual = ReadBoundPort(impl.listen_sock, FallbackPort{requested.value});
    addr.sin_port = htons(actual);
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    if (bind(impl.udp_sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR) {
        WFH_FATAL("net", "bind UDP(:%u) failed (%d)", static_cast<unsigned>(actual),
                  WSAGetLastError());
        return std::nullopt;
    }
    WFH_DEBUG("net", "bound TCP/UDP actual_port=%u", static_cast<unsigned>(actual));
    return actual;
}

auto ListenTcp(SOCKET sock) -> bool {
    if (listen(sock, kListenBacklog) != SOCKET_ERROR) {
        WFH_DEBUG("net", "TCP listen active backlog=%d", kListenBacklog);
        return true;
    }
    WFH_FATAL("net", "listen() failed (%d)", WSAGetLastError());
    return false;
}

auto ReadBoundPort(SOCKET sock, FallbackPort fallback) -> std::uint16_t {
    sockaddr_in bound{};
    int bound_len = sizeof(bound);
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    if (getsockname(sock, reinterpret_cast<sockaddr*>(&bound), &bound_len) == 0) {
        return ntohs(bound.sin_port);
    }
    return fallback.value;
}

void SetNonBlocking(SOCKET sock) {
    u_long nonblock = 1;
    ioctlsocket(sock, static_cast<long>(FIONBIO), &nonblock);
    WFH_TRACE("net", "socket set nonblocking");
}

void AddReadableSocket(fd_set& set, SOCKET sock) {
    if (sock == INVALID_SOCKET || static_cast<std::size_t>(set.fd_count) >= FD_SETSIZE) {
        return;
    }
    // fd_set is a WinSock C struct; fd_count bounds the writable slot.
    // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-constant-array-index)
    set.fd_array[set.fd_count] = sock;
    ++set.fd_count;
}

auto BuildReadSet(const Acceptor::Impl& impl) -> fd_set {
    fd_set readfds{};
    readfds.fd_count = 0;
    AddReadableSocket(readfds, impl.listen_sock);
    AddReadableSocket(readfds, impl.udp_sock);
    for (const auto& [id, client] : impl.clients) {
        AddReadableSocket(readfds, client.sock);
    }
    return readfds;
}

auto SocketIsReadable(SOCKET sock, fd_set& readfds) -> bool {
    return FD_ISSET(sock, &readfds) != 0;
}

auto PollReadable(fd_set& readfds) -> int {
    timeval tv{};
    tv.tv_sec = 0;
    tv.tv_usec = kSelectTimeoutUs;
    return select(0, &readfds, nullptr, nullptr, &tv);
}

void PumpReadableSockets(Acceptor::Impl& impl, const ServerConfig& cfg, IncomingCmdQueue& inbound,
                         fd_set& readfds, std::vector<std::uint64_t>& dead) {
    if (SocketIsReadable(impl.listen_sock, readfds)) {
        AcceptNewConnection(impl, cfg, inbound);
    }
    if (SocketIsReadable(impl.udp_sock, readfds)) {
        PumpUdp(impl);
    }
    for (auto& [id, client] : impl.clients) {
        if (SocketIsReadable(client.sock, readfds) && PumpTcpClient(id, client)) {
            dead.push_back(id);
        }
    }
}

}  // namespace

// is_donor-style ctor: store refs; the heavy lifting is in Start()/Run().
Acceptor::Acceptor(ServerConfig cfg, IncomingCmdQueue& inbound, OutboundStateQueue& outbound)
    : cfg_(std::move(cfg)), inbound_(inbound), outbound_(outbound),
      impl_(std::make_unique<Impl>()) {}

Acceptor::~Acceptor() {
    Stop();
}

auto Acceptor::Start() -> bool {
    WFH_DEBUG("net", "acceptor start requested bind_port=%u tick_hz=%u",
              static_cast<unsigned>(cfg_.bind_port), static_cast<unsigned>(cfg_.tick_hz));
    if (!StartWinsock(*impl_)) {
        return false;
    }

    if (!OpenSockets(*impl_)) {
        Stop();
        return false;
    }
    EnableReuseAddress(impl_->listen_sock);

    const auto bound = BindTcpUdp(*impl_, RequestedPort{cfg_.bind_port});
    if (!bound) {
        Stop();
        return false;
    }
    if (!ListenTcp(impl_->listen_sock)) {
        Stop();
        return false;
    }

    bound_port_ = *bound;
    SetNonBlocking(impl_->listen_sock);
    SetNonBlocking(impl_->udp_sock);

    running_.store(true);
    stop_.store(false);
    thread_ = std::thread(&Acceptor::Run, this);
    WFH_INFO("net", "server listening on TCP+UDP :%u", static_cast<unsigned>(bound_port_));
    return true;
}

void Acceptor::Stop() {
    WFH_DEBUG("net", "acceptor stop requested");
    stop_.store(true);
    if (thread_.joinable()) {
        thread_.join();
    }
    running_.store(false);
    if (impl_->listen_sock != INVALID_SOCKET) {
        closesocket(impl_->listen_sock);
        impl_->listen_sock = INVALID_SOCKET;
    }
    if (impl_->udp_sock != INVALID_SOCKET) {
        closesocket(impl_->udp_sock);
        impl_->udp_sock = INVALID_SOCKET;
    }
    for (auto& [id, client] : impl_->clients) {
        if (client.sock != INVALID_SOCKET) {
            closesocket(client.sock);
        }
    }
    impl_->clients.clear();
    if (impl_->wsa_started) {
        WSACleanup();
        impl_->wsa_started = false;
    }
    WFH_DEBUG("net", "acceptor stopped");
}

void Acceptor::Run() {
    WFH_DEBUG("net", "acceptor thread started");
    while (!stop_.load()) {
        fd_set readfds = BuildReadSet(*impl_);
        const int ready = PollReadable(readfds);
        if (ready == SOCKET_ERROR) {
            WFH_WARN("net", "select() error (%d)", WSAGetLastError());
            continue;
        }
        if (ready > 0) {
            WFH_TRACE("net", "select ready=%d clients=%zu", ready, impl_->clients.size());
        }

        std::vector<std::uint64_t> dead;
        PumpReadableSockets(*impl_, cfg_, inbound_, readfds, dead);
        FlushOutboundMessages(*impl_, outbound_);
        ReapClients(*impl_, inbound_, dead);
    }
    WFH_DEBUG("net", "acceptor thread exiting");
}

}  // namespace wfh::server
// NOLINTEND(cppcoreguidelines-avoid-do-while,cppcoreguidelines-pro-type-vararg)
