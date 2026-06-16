#include "wfh/proto/framing.hpp"

namespace wfh::proto {

namespace {

constexpr std::size_t kTcpHeaderLen = 2;     // u16 length prefix
constexpr std::size_t kTcpMinFrameLen = 3;   // 2 length + 1 opcode (empty body)
constexpr std::size_t kUdpHeaderLen = 3;     // u16 sequence + 1 opcode
constexpr std::size_t kUdpOpcodeOffset = 2;  // opcode byte follows the 2-byte sequence
constexpr unsigned kByteShift = 8;
constexpr std::uint16_t kByteMask = 0xFF;

// data must point at >= 2 readable bytes (callers guarantee this). Raw-span access.
// NOLINTBEGIN(cppcoreguidelines-pro-bounds-pointer-arithmetic)
auto ReadBigEndianU16(const std::uint8_t* data) -> std::uint16_t {
    const auto high = static_cast<std::uint16_t>(static_cast<std::uint16_t>(data[0]) << kByteShift);
    const auto low = static_cast<std::uint16_t>(data[1]);
    return static_cast<std::uint16_t>(high | low);
}
// NOLINTEND(cppcoreguidelines-pro-bounds-pointer-arithmetic)

void PushBigEndianU16(std::vector<std::uint8_t>& out, std::uint16_t value) {
    out.push_back(static_cast<std::uint8_t>((value >> kByteShift) & kByteMask));
    out.push_back(static_cast<std::uint8_t>(value & kByteMask));
}

}  // namespace

auto EncodeTcpFrame(std::uint8_t opcode, const std::vector<std::uint8_t>& body)
    -> std::optional<std::vector<std::uint8_t>> {
    const std::size_t total_len = kTcpHeaderLen + 1 + body.size();
    if (total_len > kMaxTcpFrameLen) {
        return std::nullopt;  // would overflow the u16 length field
    }
    std::vector<std::uint8_t> out;
    out.reserve(total_len);
    PushBigEndianU16(out, static_cast<std::uint16_t>(total_len));
    out.push_back(opcode);
    out.insert(out.end(), body.begin(), body.end());
    return out;
}

auto TcpFrameAccumulator::Feed(const std::uint8_t* data, std::size_t len) -> bool {
    if (failed_) {
        return false;
    }
    buffer_.insert(buffer_.end(), data,
                   data + len);  // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    // Validate the declared length of the frame at the front as soon as the 2-byte
    // header is present, so a hostile/garbage prefix is rejected before we wait on
    // (and buffer toward) a bogus size.
    if (buffer_.size() >= kTcpHeaderLen) {
        // total_len is u16, so it is inherently <= kMaxTcpFrameLen; only the lower
        // bound can be violated by a hostile prefix.
        const std::uint16_t total_len = ReadBigEndianU16(buffer_.data());
        if (total_len < kTcpMinFrameLen) {
            failed_ = true;
            return false;
        }
    }
    return true;
}

auto TcpFrameAccumulator::Next() -> std::optional<Frame> {
    if (failed_ || buffer_.size() < kTcpHeaderLen) {
        return std::nullopt;
    }
    const std::uint16_t total_len = ReadBigEndianU16(buffer_.data());
    // Re-validate defensively (Feed already checked, but Next must never trust it).
    // total_len is u16 so the upper bound (kMaxTcpFrameLen) holds by construction.
    if (total_len < kTcpMinFrameLen) {
        failed_ = true;
        return std::nullopt;
    }
    if (buffer_.size() < total_len) {
        return std::nullopt;  // frame not fully received yet
    }
    Frame frame;
    frame.opcode = buffer_.at(kTcpHeaderLen);
    const auto body_begin = buffer_.begin() + static_cast<std::ptrdiff_t>(kTcpHeaderLen + 1);
    const auto body_end = buffer_.begin() + static_cast<std::ptrdiff_t>(total_len);
    frame.body.assign(body_begin, body_end);
    buffer_.erase(buffer_.begin(), body_end);
    return frame;
}

// sequence and opcode are distinct protocol fields; the convertible-type swap check
// does not apply to this fixed wire layout.
// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
auto EncodeUdpFrame(std::uint16_t sequence, std::uint8_t opcode,
                    const std::vector<std::uint8_t>& body) -> std::vector<std::uint8_t> {
    std::vector<std::uint8_t> out;
    out.reserve(kUdpHeaderLen + body.size());
    PushBigEndianU16(out, sequence);
    out.push_back(opcode);
    out.insert(out.end(), body.begin(), body.end());
    return out;
}

auto DecodeUdpFrame(const std::uint8_t* data, std::size_t len) -> std::optional<UdpFrame> {
    if (len < kUdpHeaderLen) {
        return std::nullopt;
    }
    UdpFrame frame;
    frame.sequence = ReadBigEndianU16(data);
    // Raw-span API (ptr + len); indices are guarded by the len check above.
    // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    frame.opcode = data[kUdpOpcodeOffset];
    // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    frame.body.assign(data + kUdpHeaderLen, data + len);
    return frame;
}

}  // namespace wfh::proto
