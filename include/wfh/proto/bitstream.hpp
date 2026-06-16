// NOLINTBEGIN(portability-avoid-pragma-once)
// pragma once is the project-wide include-guard convention; intentional.
#pragma once
// NOLINTEND(portability-avoid-pragma-once)

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace wfh::proto {

// MSB-first bit serialization for the Wulfram II wire protocol. Bit order matches
// the engine and the reference Python codec (Wulf-Forge/network/streams.py): bits
// of a value are emitted most-significant-first, and bytes fill from bit 7 down.
//
// BitWriter is infallible (it owns and grows its own buffer). BitReader is the
// security boundary: it reads UNTRUSTED bytes and is strictly bounds-checked and
// FAIL-CLOSED. No read ever touches memory past the buffer, and once any read
// fails the reader latches a sticky failure so every subsequent read also fails.
// This is the deliberate fix for the reference reader, which silently returned 0
// past end-of-stream.

class BitWriter {
public:
    BitWriter() = default;

    // Append the low `num_bits` (0..32) of `value`, most-significant-first. A
    // num_bits of 0 is a no-op; values above 32 are clamped to 32 (defensive — the
    // protocol never needs more, and over-wide writes must not read junk bits).
    void WriteBits(std::uint32_t value, unsigned num_bits);

    void WriteBool(bool value);
    void WriteByte(std::uint8_t value);
    void WriteU16(std::uint16_t value);       // 16 bits, big-endian order
    void WriteI32(std::int32_t value);        // 32 bits, two's complement
    void WriteFloat(float value);             // IEEE-754, big-endian bit order
    void WriteFixed1616(double value);        // round(value * 65536) as i32
    void WriteString(std::string_view text);  // [u16 len-incl-NUL][ascii][NUL]
    void WriteBytes(const std::uint8_t* data, std::size_t len);

    // Pad the current partial byte with zero bits up to the next byte boundary.
    void Align();

    // Flush any partial byte (zero-padded) and return the accumulated payload.
    [[nodiscard]] auto Bytes() -> std::vector<std::uint8_t>;

    // Current size in whole bits written (for tests / sizing).
    [[nodiscard]] auto BitLength() const -> std::size_t;

private:
    std::vector<std::uint8_t> buffer_;
    std::uint8_t current_ = 0;
    unsigned bit_index_ = 0;  // 0..7, MSB-first cursor within current_
};

// Reads MSB-first from a fixed, externally-owned byte span. Every accessor is
// bounds-checked; on under-run the reader latches failure (Failed() == true) and
// all reads return std::nullopt thereafter. Construction does not copy the bytes,
// so the span must outlive the reader.
class BitReader {
public:
    BitReader(const std::uint8_t* data, std::size_t len);
    explicit BitReader(const std::vector<std::uint8_t>& data);

    // Read `num_bits` (0..32) MSB-first. nullopt (and latched failure) if the
    // buffer does not hold that many bits, or if num_bits > 32.
    [[nodiscard]] auto ReadBits(unsigned num_bits) -> std::optional<std::uint32_t>;

    [[nodiscard]] auto ReadBool() -> std::optional<bool>;
    [[nodiscard]] auto ReadByte() -> std::optional<std::uint8_t>;
    [[nodiscard]] auto ReadU16() -> std::optional<std::uint16_t>;
    [[nodiscard]] auto ReadI32() -> std::optional<std::int32_t>;  // sign-extended
    [[nodiscard]] auto ReadFloat() -> std::optional<float>;
    [[nodiscard]] auto ReadFixed1616() -> std::optional<double>;

    // Read a [u16 len-incl-NUL][ascii][NUL] string. Rejects (nullopt + latched
    // failure): declared length 0, length > max_len, length running past the
    // buffer, or a missing trailing NUL. The returned string excludes the NUL.
    [[nodiscard]] auto ReadString(std::size_t max_len) -> std::optional<std::string>;

    // Copy `len` raw bytes (only valid when byte-aligned; misaligned reads still
    // work bit-by-bit). nullopt + latched failure if fewer than `len` remain.
    [[nodiscard]] auto ReadBytes(std::size_t len) -> std::optional<std::vector<std::uint8_t>>;

    [[nodiscard]] auto Failed() const -> bool { return failed_; }
    [[nodiscard]] auto RemainingBits() const -> std::size_t;
    [[nodiscard]] auto RemainingBytes() const -> std::size_t;

private:
    void Fail() { failed_ = true; }

    const std::uint8_t* data_;
    std::size_t total_bits_;
    std::size_t bit_pos_ = 0;  // absolute bit cursor from the start of data_
    bool failed_ = false;
};

}  // namespace wfh::proto
