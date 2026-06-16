// NOLINTBEGIN(portability-avoid-pragma-once)
// pragma once is the project-wide include-guard convention; intentional.
#pragma once
// NOLINTEND(portability-avoid-pragma-once)

#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

namespace wfh::proto {

// One decoded logical packet: the opcode byte plus the body that followed it
// (body EXCLUDES the opcode and the TCP length header).
struct Frame {
    std::uint8_t opcode = 0;
    std::vector<std::uint8_t> body;
};

// TCP framing: [u16_be total_len][opcode][body], where total_len COUNTS the 2
// length bytes (i.e. total_len = 2 + 1 + body.size()). Big-endian length.
//
// The largest legal Wulfram TCP frame is bounded by the u16 length field (0xFFFF),
// so this is the hard cap the accumulator enforces against a hostile length prefix.
constexpr std::size_t kMaxTcpFrameLen = 0xFFFF;

// Build a complete TCP frame (length header + opcode + body). Bodies large enough
// to overflow the u16 length are rejected (returns nullopt) rather than truncated.
[[nodiscard]] auto EncodeTcpFrame(std::uint8_t opcode, const std::vector<std::uint8_t>& body)
    -> std::optional<std::vector<std::uint8_t>>;

// Reassembles TCP frames from arbitrary recv() chunks (which may split or coalesce
// frames). Fail-closed against hostile input: a declared total_len below the 3-byte
// minimum (2 length + 1 opcode) or above kMaxTcpFrameLen latches a permanent error
// instead of buffering/allocating unboundedly. Once Failed(), the connection should
// be dropped.
class TcpFrameAccumulator {
public:
    // Feed a received chunk. Returns false (and latches Failed()) if the chunk
    // pushes the stream into an invalid/oversized framing state.
    auto Feed(const std::uint8_t* data, std::size_t len) -> bool;

    // Pop the next fully-received frame, or nullopt if none is complete yet.
    [[nodiscard]] auto Next() -> std::optional<Frame>;

    [[nodiscard]] auto Failed() const -> bool { return failed_; }
    [[nodiscard]] auto Buffered() const -> std::size_t { return buffer_.size(); }

private:
    std::vector<std::uint8_t> buffer_;
    bool failed_ = false;
};

// UDP framing: [u16_be sequence][opcode][body]. UDP is datagram-oriented (one
// datagram = one packet), so there is no reassembly — just encode/decode.
[[nodiscard]] auto EncodeUdpFrame(std::uint16_t sequence, std::uint8_t opcode,
                                  const std::vector<std::uint8_t>& body)
    -> std::vector<std::uint8_t>;

struct UdpFrame {
    std::uint16_t sequence = 0;
    std::uint8_t opcode = 0;
    std::vector<std::uint8_t> body;
};

// Decode a single UDP datagram. nullopt if it is too short to hold seq+opcode.
[[nodiscard]] auto DecodeUdpFrame(const std::uint8_t* data, std::size_t len)
    -> std::optional<UdpFrame>;

}  // namespace wfh::proto
