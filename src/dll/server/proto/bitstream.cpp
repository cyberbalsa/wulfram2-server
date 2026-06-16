#include "wfh/proto/bitstream.hpp"

#include <algorithm>
#include <cmath>
#include <cstring>

namespace wfh::proto {

namespace {

constexpr unsigned kBitsPerByte = 8;
constexpr unsigned kMaxBits = 32;
constexpr unsigned kU16Bits = 16;
constexpr unsigned kHighBitIndex = 7;         // MSB position within a byte
constexpr std::uint8_t kAsciiHighBit = 0x80;  // bytes >= this are non-ASCII
constexpr double kFixed1616Scale = 65536.0;

}  // namespace

// --- BitWriter --------------------------------------------------------------

// The (value, num_bits) pair is the natural bit-writer API; the swappable-parameter
// check does not improve a primitive of this shape.
// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
void BitWriter::WriteBits(std::uint32_t value, unsigned num_bits) {
    num_bits = std::min(num_bits, kMaxBits);
    // Emit most-significant bit first so the byte stream matches the engine /
    // reference codec exactly.
    for (unsigned i = num_bits; i-- > 0;) {
        const std::uint32_t bit = (value >> i) & 1U;
        current_ = static_cast<std::uint8_t>(current_ | (bit << (kHighBitIndex - bit_index_)));
        ++bit_index_;
        if (bit_index_ == kBitsPerByte) {
            buffer_.push_back(current_);
            current_ = 0;
            bit_index_ = 0;
        }
    }
}

void BitWriter::WriteBool(bool value) {
    WriteBits(value ? 1U : 0U, 1);
}

void BitWriter::WriteByte(std::uint8_t value) {
    WriteBits(value, kBitsPerByte);
}

void BitWriter::WriteU16(std::uint16_t value) {
    WriteBits(value, kU16Bits);
}

void BitWriter::WriteI32(std::int32_t value) {
    WriteBits(static_cast<std::uint32_t>(value), kMaxBits);
}

void BitWriter::WriteFloat(float value) {
    std::uint32_t bits = 0;
    std::memcpy(&bits, &value, sizeof(bits));
    // (bits, kMaxBits) are the value and width; not a swapped pair.
    // NOLINTNEXTLINE(readability-suspicious-call-argument)
    WriteBits(bits, kMaxBits);
}

void BitWriter::WriteFixed1616(double value) {
    // round-half-away-from-zero, matching the reference int(round(v*65536)).
    const double scaled = std::round(value * kFixed1616Scale);
    WriteI32(static_cast<std::int32_t>(static_cast<std::int64_t>(scaled)));
}

void BitWriter::WriteString(std::string_view text) {
    // Wulfram string: [u16 length-including-NUL][ascii bytes][NUL]. ASCII only;
    // non-ASCII is replaced with '?' to mirror the reference encoder.
    const std::size_t len_with_nul = text.size() + 1;
    WriteU16(static_cast<std::uint16_t>(len_with_nul));
    for (const char raw : text) {
        const auto byte = static_cast<std::uint8_t>(raw);
        WriteByte(byte < kAsciiHighBit ? byte : static_cast<std::uint8_t>('?'));
    }
    WriteByte(0);
}

void BitWriter::WriteBytes(const std::uint8_t* data, std::size_t len) {
    for (std::size_t i = 0; i < len; ++i) {
        WriteByte(data[i]);  // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    }
}

void BitWriter::Align() {
    if (bit_index_ > 0) {
        buffer_.push_back(current_);
        current_ = 0;
        bit_index_ = 0;
    }
}

auto BitWriter::Bytes() -> std::vector<std::uint8_t> {
    Align();
    return buffer_;
}

auto BitWriter::BitLength() const -> std::size_t {
    return (buffer_.size() * kBitsPerByte) + bit_index_;
}

// --- BitReader --------------------------------------------------------------

BitReader::BitReader(const std::uint8_t* data, std::size_t len)
    : data_(data), total_bits_(len * kBitsPerByte) {}

BitReader::BitReader(const std::vector<std::uint8_t>& data)
    : data_(data.data()), total_bits_(data.size() * kBitsPerByte) {}

auto BitReader::ReadBits(unsigned num_bits) -> std::optional<std::uint32_t> {
    if (failed_ || num_bits > kMaxBits) {
        Fail();
        return std::nullopt;
    }
    if (RemainingBits() < num_bits) {
        Fail();
        return std::nullopt;
    }
    std::uint32_t value = 0;
    for (unsigned i = 0; i < num_bits; ++i) {
        const std::size_t byte_pos = bit_pos_ / kBitsPerByte;
        const auto bit_in_byte = static_cast<unsigned>(bit_pos_ % kBitsPerByte);
        const unsigned shift = kHighBitIndex - bit_in_byte;
        // data_ is a raw span; index is bounds-guarded by the RemainingBits check above.
        // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        const std::uint32_t bit = (static_cast<std::uint32_t>(data_[byte_pos]) >> shift) & 1U;
        value = (value << 1U) | bit;
        ++bit_pos_;
    }
    return value;
}

auto BitReader::ReadBool() -> std::optional<bool> {
    const auto bit = ReadBits(1);
    if (!bit) {
        return std::nullopt;
    }
    return *bit != 0;
}

auto BitReader::ReadByte() -> std::optional<std::uint8_t> {
    const auto value = ReadBits(kBitsPerByte);
    if (!value) {
        return std::nullopt;
    }
    return static_cast<std::uint8_t>(*value);
}

auto BitReader::ReadU16() -> std::optional<std::uint16_t> {
    const auto value = ReadBits(16);
    if (!value) {
        return std::nullopt;
    }
    return static_cast<std::uint16_t>(*value);
}

auto BitReader::ReadI32() -> std::optional<std::int32_t> {
    const auto value = ReadBits(kMaxBits);
    if (!value) {
        return std::nullopt;
    }
    return static_cast<std::int32_t>(*value);
}

auto BitReader::ReadFloat() -> std::optional<float> {
    const auto bits = ReadBits(kMaxBits);
    if (!bits) {
        return std::nullopt;
    }
    float value = 0.0F;
    const std::uint32_t raw = *bits;
    std::memcpy(&value, &raw, sizeof(value));
    return value;
}

auto BitReader::ReadFixed1616() -> std::optional<double> {
    const auto raw = ReadI32();
    if (!raw) {
        return std::nullopt;
    }
    return static_cast<double>(*raw) / kFixed1616Scale;
}

auto BitReader::ReadString(std::size_t max_len) -> std::optional<std::string> {
    const auto declared = ReadU16();
    if (!declared) {
        return std::nullopt;
    }
    const std::size_t len_with_nul = *declared;
    // Reject pathological lengths: empty (the protocol always includes the NUL, so
    // the minimum is 1), or longer than the caller's cap. The subsequent reads also
    // bound-check, but catching it here avoids a large fail-closed loop.
    if (len_with_nul == 0 || len_with_nul > max_len) {
        Fail();
        return std::nullopt;
    }
    std::string out;
    out.reserve(len_with_nul - 1);
    for (std::size_t i = 0; i < len_with_nul; ++i) {
        const auto byte = ReadByte();
        if (!byte) {
            return std::nullopt;  // ran past buffer -> latched failure
        }
        const bool is_last = (i + 1 == len_with_nul);
        if (is_last) {
            // The final byte MUST be the NUL terminator the length counted.
            if (*byte != 0) {
                Fail();
                return std::nullopt;
            }
        } else {
            out.push_back(static_cast<char>(*byte));
        }
    }
    return out;
}

auto BitReader::ReadBytes(std::size_t len) -> std::optional<std::vector<std::uint8_t>> {
    if (failed_ || RemainingBits() < len * kBitsPerByte) {
        Fail();
        return std::nullopt;
    }
    std::vector<std::uint8_t> out;
    out.reserve(len);
    for (std::size_t i = 0; i < len; ++i) {
        const auto byte = ReadByte();
        if (!byte) {
            return std::nullopt;
        }
        out.push_back(*byte);
    }
    return out;
}

auto BitReader::RemainingBits() const -> std::size_t {
    return bit_pos_ >= total_bits_ ? 0 : total_bits_ - bit_pos_;
}

auto BitReader::RemainingBytes() const -> std::size_t {
    return RemainingBits() / kBitsPerByte;
}

}  // namespace wfh::proto
