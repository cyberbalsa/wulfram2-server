#include "wfh/proto/bitstream.hpp"
#include "wfh/proto/framing.hpp"
#include "wfh/proto/opcodes.hpp"
#include "wfh/proto/validate.hpp"

#include <gtest/gtest.h>

#include <array>
#include <cmath>
#include <cstdint>
#include <limits>
#include <string>
#include <vector>

using wfh::proto::BitReader;
using wfh::proto::BitWriter;

namespace {

// --- BitWriter / BitReader round-trips --------------------------------------

TEST(ProtoBits, AllWidthRoundTrip) {
    // Every bit width 1..32 round-trips a representative value (low `w` bits).
    for (unsigned w = 1; w <= 32; ++w) {
        const std::uint32_t mask = (w == 32) ? 0xFFFFFFFFU : ((1U << w) - 1U);
        const std::uint32_t value = 0xA5C3F00FU & mask;
        BitWriter writer;
        writer.WriteBits(value, w);
        const auto bytes = writer.Bytes();
        BitReader reader(bytes);
        const auto got = reader.ReadBits(w);
        ASSERT_TRUE(got.has_value()) << "width " << w;
        EXPECT_EQ(*got, value) << "width " << w;
    }
}

TEST(ProtoBits, MsbFirstByteOrder) {
    // Writing 0b101 in 3 bits then 0b11111 in 5 bits fills exactly one byte:
    // 1010 1111 1 -> first byte = 1011111? ; precisely: bits 1,0,1,1,1,1,1,1 = 0xBF.
    BitWriter writer;
    writer.WriteBits(0b101U, 3);
    writer.WriteBits(0b11111U, 5);
    const auto bytes = writer.Bytes();
    ASSERT_EQ(bytes.size(), 1U);
    EXPECT_EQ(bytes[0], 0xBFU);  // 1011 1111

    // A single 0xC3 byte read back MSB-first as 8 individual bits is 1,1,0,0,0,0,1,1.
    const std::vector<std::uint8_t> one{0xC3U};
    BitReader reader(one);
    const std::array<unsigned, 8> expected = {1, 1, 0, 0, 0, 0, 1, 1};
    for (unsigned i = 0; i < 8; ++i) {
        const auto bit = reader.ReadBits(1);
        ASSERT_TRUE(bit.has_value());
        EXPECT_EQ(*bit, expected.at(i)) << "bit " << i;
    }
}

TEST(ProtoBits, TypedRoundTrips) {
    BitWriter writer;
    writer.WriteByte(0xABU);
    writer.WriteU16(0x1234U);
    writer.WriteI32(-42);
    writer.WriteBool(true);
    writer.WriteBool(false);
    writer.WriteFloat(3.5F);
    writer.WriteFixed1616(-123.5);
    const auto bytes = writer.Bytes();

    BitReader reader(bytes);
    EXPECT_EQ(reader.ReadByte().value_or(0), 0xABU);
    EXPECT_EQ(reader.ReadU16().value_or(0), 0x1234U);
    EXPECT_EQ(reader.ReadI32().value_or(0), -42);
    EXPECT_EQ(reader.ReadBool().value_or(false), true);
    EXPECT_EQ(reader.ReadBool().value_or(true), false);
    EXPECT_FLOAT_EQ(reader.ReadFloat().value_or(0.0F), 3.5F);
    EXPECT_DOUBLE_EQ(reader.ReadFixed1616().value_or(0.0), -123.5);
    EXPECT_FALSE(reader.Failed());
}

TEST(ProtoBits, Fixed1616KnownEncoding) {
    // 1.0 -> 0x00010000 ; -1.0 -> 0xFFFF0000 (two's complement). Verify the bytes.
    BitWriter writer;
    writer.WriteFixed1616(1.0);
    writer.WriteFixed1616(-1.0);
    const auto bytes = writer.Bytes();
    const std::vector<std::uint8_t> expected = {0x00, 0x01, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00};
    EXPECT_EQ(bytes, expected);
}

TEST(ProtoBits, StringRoundTrip) {
    BitWriter writer;
    writer.WriteString("Wulfram");
    const auto bytes = writer.Bytes();
    // [u16 len-incl-NUL = 8]['W'...'m'][0x00]
    ASSERT_EQ(bytes.size(), 2U + 8U);
    EXPECT_EQ(bytes[0], 0x00U);
    EXPECT_EQ(bytes[1], 0x08U);
    EXPECT_EQ(bytes.back(), 0x00U);

    BitReader reader(bytes);
    const auto got = reader.ReadString(wfh::proto::kMaxStringLen);
    ASSERT_TRUE(got.has_value());
    EXPECT_EQ(*got, "Wulfram");
    EXPECT_FALSE(reader.Failed());
}

TEST(ProtoBits, EmptyStringRoundTrip) {
    BitWriter writer;
    writer.WriteString("");
    const auto bytes = writer.Bytes();
    BitReader reader(bytes);
    const auto got = reader.ReadString(wfh::proto::kMaxStringLen);
    ASSERT_TRUE(got.has_value());
    EXPECT_TRUE(got->empty());
}

// --- BitReader adversarial / fail-closed ------------------------------------

TEST(ProtoBitsAdversarial, ReadPastEndFailsClosed) {
    const std::vector<std::uint8_t> one{0xFFU};  // 8 bits only
    BitReader reader(one);
    EXPECT_TRUE(reader.ReadByte().has_value());   // consumes all 8
    EXPECT_FALSE(reader.ReadBool().has_value());  // 1 bit past end -> fail
    EXPECT_TRUE(reader.Failed());
    // Sticky: even a 0-bit-ish further read stays failed.
    EXPECT_FALSE(reader.ReadByte().has_value());
}

TEST(ProtoBitsAdversarial, OverWideReadRejected) {
    const std::vector<std::uint8_t> data{0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU};
    BitReader reader(data);
    EXPECT_FALSE(reader.ReadBits(33).has_value());  // > 32 bits
    EXPECT_TRUE(reader.Failed());
}

TEST(ProtoBitsAdversarial, PartialBitReadAtEnd) {
    const std::vector<std::uint8_t> data{0xAAU};  // 8 bits
    BitReader reader(data);
    EXPECT_TRUE(reader.ReadBits(5).has_value());   // 3 left
    EXPECT_FALSE(reader.ReadBits(4).has_value());  // wants 4, only 3 -> fail
    EXPECT_TRUE(reader.Failed());
}

TEST(ProtoBitsAdversarial, StringLengthOverBufferRejected) {
    // Declared length 100 but only a few bytes follow.
    BitWriter writer;
    writer.WriteU16(100);
    writer.WriteByte('h');
    writer.WriteByte('i');
    const auto bytes = writer.Bytes();
    BitReader reader(bytes);
    EXPECT_FALSE(reader.ReadString(wfh::proto::kMaxStringLen).has_value());
    EXPECT_TRUE(reader.Failed());
}

TEST(ProtoBitsAdversarial, StringLengthZeroRejected) {
    BitWriter writer;
    writer.WriteU16(0);  // illegal: protocol always counts the NUL (min 1)
    const auto bytes = writer.Bytes();
    BitReader reader(bytes);
    EXPECT_FALSE(reader.ReadString(wfh::proto::kMaxStringLen).has_value());
    EXPECT_TRUE(reader.Failed());
}

TEST(ProtoBitsAdversarial, StringLengthOverMaxRejected) {
    BitWriter writer;
    writer.WriteU16(50);
    const auto bytes = writer.Bytes();
    BitReader reader(bytes);
    EXPECT_FALSE(reader.ReadString(8).has_value());  // cap is 8, declared 50
    EXPECT_TRUE(reader.Failed());
}

TEST(ProtoBitsAdversarial, StringMissingNulRejected) {
    // length 3, but the third byte is not NUL.
    BitWriter writer;
    writer.WriteU16(3);
    writer.WriteByte('a');
    writer.WriteByte('b');
    writer.WriteByte('c');  // should have been 0x00
    const auto bytes = writer.Bytes();
    BitReader reader(bytes);
    EXPECT_FALSE(reader.ReadString(wfh::proto::kMaxStringLen).has_value());
    EXPECT_TRUE(reader.Failed());
}

TEST(ProtoBitsAdversarial, EmptyBufferFailsClosed) {
    BitReader reader(nullptr, 0);
    EXPECT_FALSE(reader.ReadByte().has_value());
    EXPECT_TRUE(reader.Failed());
    EXPECT_EQ(reader.RemainingBits(), 0U);
}

// --- TCP framing ------------------------------------------------------------

TEST(ProtoFraming, TcpEncodeShape) {
    const std::vector<std::uint8_t> body{0x01U, 0x02U, 0x03U};
    const auto frame = wfh::proto::EncodeTcpFrame(0x13U, body);
    ASSERT_TRUE(frame.has_value());
    // total_len = 2 + 1 + 3 = 6, big-endian.
    ASSERT_EQ(frame->size(), 6U);
    EXPECT_EQ((*frame)[0], 0x00U);
    EXPECT_EQ((*frame)[1], 0x06U);
    EXPECT_EQ((*frame)[2], 0x13U);  // opcode
    EXPECT_EQ((*frame)[3], 0x01U);
}

TEST(ProtoFraming, TcpEncodeOverlongRejected) {
    const std::vector<std::uint8_t> body(wfh::proto::kMaxTcpFrameLen, 0xCCU);
    EXPECT_FALSE(wfh::proto::EncodeTcpFrame(0x13U, body).has_value());
}

TEST(ProtoFraming, TcpAccumulatorSingleFrame) {
    const auto frame = wfh::proto::EncodeTcpFrame(0x18U, {0xDEU, 0xADU}).value();
    wfh::proto::TcpFrameAccumulator acc;
    ASSERT_TRUE(acc.Feed(frame.data(), frame.size()));
    const auto got = acc.Next();
    ASSERT_TRUE(got.has_value());
    EXPECT_EQ(got->opcode, 0x18U);
    EXPECT_EQ(got->body, (std::vector<std::uint8_t>{0xDEU, 0xADU}));
    EXPECT_FALSE(acc.Next().has_value());  // nothing left
}

TEST(ProtoFraming, TcpAccumulatorSplitChunks) {
    const auto frame = wfh::proto::EncodeTcpFrame(0x24U, {0x11U, 0x22U, 0x33U, 0x44U}).value();
    wfh::proto::TcpFrameAccumulator acc;
    // Feed byte-by-byte: no frame until the last byte arrives.
    for (std::size_t i = 0; i + 1 < frame.size(); ++i) {
        ASSERT_TRUE(acc.Feed(&frame[i], 1));
        EXPECT_FALSE(acc.Next().has_value()) << "premature frame at byte " << i;
    }
    ASSERT_TRUE(acc.Feed(&frame.back(), 1));
    const auto got = acc.Next();
    ASSERT_TRUE(got.has_value());
    EXPECT_EQ(got->opcode, 0x24U);
}

TEST(ProtoFraming, TcpAccumulatorCoalescedFrames) {
    const auto f1 = wfh::proto::EncodeTcpFrame(0x16U, {0x01U}).value();
    const auto f2 = wfh::proto::EncodeTcpFrame(0x17U, {0x02U, 0x03U}).value();
    std::vector<std::uint8_t> both = f1;
    both.insert(both.end(), f2.begin(), f2.end());
    wfh::proto::TcpFrameAccumulator acc;
    ASSERT_TRUE(acc.Feed(both.data(), both.size()));
    const auto g1 = acc.Next();
    const auto g2 = acc.Next();
    ASSERT_TRUE(g1.has_value());
    ASSERT_TRUE(g2.has_value());
    EXPECT_EQ(g1->opcode, 0x16U);
    EXPECT_EQ(g2->opcode, 0x17U);
    EXPECT_FALSE(acc.Next().has_value());
}

TEST(ProtoFramingAdversarial, TcpUndersizeLengthRejected) {
    // Declared total_len = 2 (below the 3-byte minimum) -> latched failure.
    wfh::proto::TcpFrameAccumulator acc;
    const std::vector<std::uint8_t> bad{0x00U, 0x02U};
    EXPECT_FALSE(acc.Feed(bad.data(), bad.size()));
    EXPECT_TRUE(acc.Failed());
    EXPECT_FALSE(acc.Next().has_value());
}

TEST(ProtoFramingAdversarial, TcpTruncatedFrameNeverCompletes) {
    // A well-formed header claiming 10 bytes, but only 4 delivered: no frame, no crash.
    const std::vector<std::uint8_t> partial{0x00U, 0x0AU, 0x18U, 0x01U};
    wfh::proto::TcpFrameAccumulator acc;
    ASSERT_TRUE(acc.Feed(partial.data(), partial.size()));
    EXPECT_FALSE(acc.Next().has_value());
    EXPECT_FALSE(acc.Failed());  // still waiting, not an error
}

// --- UDP framing ------------------------------------------------------------

TEST(ProtoFraming, UdpRoundTrip) {
    const auto frame = wfh::proto::EncodeUdpFrame(0x1234U, 0x25U, {0xAAU, 0xBBU});
    ASSERT_EQ(frame.size(), 5U);
    const auto got = wfh::proto::DecodeUdpFrame(frame.data(), frame.size());
    ASSERT_TRUE(got.has_value());
    EXPECT_EQ(got->sequence, 0x1234U);
    EXPECT_EQ(got->opcode, 0x25U);
    EXPECT_EQ(got->body, (std::vector<std::uint8_t>{0xAAU, 0xBBU}));
}

TEST(ProtoFramingAdversarial, UdpTooShortRejected) {
    const std::vector<std::uint8_t> tiny{0x00U, 0x01U};  // 2 bytes, need >= 3
    EXPECT_FALSE(wfh::proto::DecodeUdpFrame(tiny.data(), tiny.size()).has_value());
}

// --- Validators -------------------------------------------------------------

TEST(ProtoValidate, KnownOpcodes) {
    EXPECT_TRUE(wfh::proto::IsKnownOpcode(0x13U));  // Hello
    EXPECT_TRUE(wfh::proto::IsKnownOpcode(0x18U));  // TankSpawn
    EXPECT_TRUE(wfh::proto::IsKnownOpcode(0x0EU));  // UpdateArray
    EXPECT_TRUE(wfh::proto::IsKnownOpcode(0x4DU));  // IdentifiedUdp
    // Every opcode the client can emit is whitelisted so none is silently dropped at
    // the UDP/TCP gate — including the low-numbered control/handshake set.
    EXPECT_TRUE(wfh::proto::IsKnownOpcode(0x00U));  // DebugString
    EXPECT_TRUE(wfh::proto::IsKnownOpcode(0x03U));  // DHandshake (reliable-stream setup)
    EXPECT_TRUE(wfh::proto::IsKnownOpcode(0x0BU));  // ClientPing
    EXPECT_TRUE(wfh::proto::IsKnownOpcode(0x0AU));  // ActionUpdate
    EXPECT_TRUE(wfh::proto::IsKnownOpcode(0x33U));  // TranslationAck
    // Values outside the protocol set are still rejected.
    EXPECT_FALSE(wfh::proto::IsKnownOpcode(0xFFU));
    EXPECT_FALSE(wfh::proto::IsKnownOpcode(0x99U));
    EXPECT_FALSE(wfh::proto::IsKnownOpcode(0x01U));
}

TEST(ProtoValidate, ClampUnit) {
    EXPECT_FLOAT_EQ(wfh::proto::ClampUnit(0.5F), 0.5F);
    EXPECT_FLOAT_EQ(wfh::proto::ClampUnit(5.0F), 1.0F);
    EXPECT_FLOAT_EQ(wfh::proto::ClampUnit(-5.0F), -1.0F);
    EXPECT_FLOAT_EQ(wfh::proto::ClampUnit(std::numeric_limits<float>::quiet_NaN()), 0.0F);
}

TEST(ProtoValidate, UnitTypeTeamOid) {
    EXPECT_TRUE(wfh::proto::IsValidClientUnitType(0));
    EXPECT_TRUE(wfh::proto::IsValidClientUnitType(4));
    EXPECT_FALSE(wfh::proto::IsValidClientUnitType(5));
    EXPECT_FALSE(wfh::proto::IsValidClientUnitType(-1));

    EXPECT_TRUE(wfh::proto::IsValidTeam(1));
    EXPECT_TRUE(wfh::proto::IsValidTeam(2));
    EXPECT_FALSE(wfh::proto::IsValidTeam(0));
    EXPECT_FALSE(wfh::proto::IsValidTeam(3));

    EXPECT_TRUE(wfh::proto::IsValidOid(1U));
    EXPECT_FALSE(wfh::proto::IsValidOid(0U));
    EXPECT_FALSE(wfh::proto::IsValidOid(0xFFFFFFFFU));
}

TEST(ProtoValidate, AcceptableString) {
    EXPECT_TRUE(wfh::proto::IsAcceptableString("PlayerOne"));
    EXPECT_FALSE(wfh::proto::IsAcceptableString(std::string("bad\x01ctrl", 8)));
    EXPECT_FALSE(wfh::proto::IsAcceptableString(std::string(300, 'a')));  // over default cap
}

}  // namespace
