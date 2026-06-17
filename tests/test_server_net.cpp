// Tests for the M5.1b threaded socket server: config parsing, bring-up packet
// framing, the per-connection handshake state machine (in-order accept + adversarial
// reject), the queue boundary, and a loopback acceptor smoke. Engine-less.

#include "wfh/proto/bitstream.hpp"
#include "wfh/proto/framing.hpp"
#include "wfh/proto/opcodes.hpp"
#include "wfh/server/acceptor.hpp"
#include "wfh/server/action_input.hpp"
#include "wfh/server/bringup_packets.hpp"
#include "wfh/server/connection.hpp"
#include "wfh/server/dev_console.hpp"
#include "wfh/server/queues.hpp"
#include "wfh/server/runtime.hpp"
#include "wfh/server/server_config.hpp"
#include "wfh/server/world_packets.hpp"

#include <gtest/gtest.h>

#ifdef _MSC_VER
#pragma warning(push, 0)
#endif
#include <winsock2.h>

#include <ws2tcpip.h>
#ifdef _MSC_VER
#pragma warning(pop)
#endif

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <optional>
#include <string>
#include <thread>
#include <vector>

namespace {

using wfh::proto::BitReader;
using wfh::proto::Frame;
using wfh::proto::Opcode;
using wfh::proto::TcpFrameAccumulator;
using namespace wfh::server;

// Build a TCP frame for `opcode` with a body written by `fn` (BitWriter).
template <typename Fn> auto MakeFrame(Opcode opcode, Fn fn) -> std::vector<std::uint8_t> {
    wfh::proto::BitWriter w;
    fn(w);
    return wfh::proto::EncodeTcpFrame(static_cast<std::uint8_t>(opcode), w.Bytes()).value();
}

// Pull the first decoded frame out of a buffer of framed bytes.
auto FirstFrame(const std::vector<std::uint8_t>& bytes) -> Frame {
    TcpFrameAccumulator acc;
    acc.Feed(bytes.data(), bytes.size());
    auto f = acc.Next();
    return f.value_or(Frame{});
}

auto SessionKeyFromHelloBurst(const std::vector<std::uint8_t>& bytes) -> std::string {
    TcpFrameAccumulator acc;
    EXPECT_TRUE(acc.Feed(bytes.data(), bytes.size()));
    while (auto frame = acc.Next()) {
        if (frame->opcode != static_cast<std::uint8_t>(Opcode::Hello)) {
            continue;
        }
        BitReader r(frame->body.data(), frame->body.size());
        const auto sub = r.ReadByte();
        if (sub && *sub == 0x02) {
            auto key = r.ReadString(256);
            return key.value_or("");
        }
    }
    return "";
}

auto MakeRawUdpHelloKeyEcho(const std::string& key) -> std::vector<std::uint8_t> {
    wfh::proto::BitWriter body;
    body.WriteByte(0x01);
    body.WriteString(key);
    std::vector<std::uint8_t> datagram{static_cast<std::uint8_t>(Opcode::Hello)};
    const auto bytes = body.Bytes();
    datagram.insert(datagram.end(), bytes.begin(), bytes.end());
    return datagram;
}

auto MakePythonStyleLoginFrame(const std::string& username, const std::string& password)
    -> std::vector<std::uint8_t> {
    wfh::proto::BitWriter body_writer;
    body_writer.WriteByte(0x00);  // login type/subcmd byte; Python skips this before username
    body_writer.WriteString(username);
    body_writer.WriteString(password);

    auto body = body_writer.Bytes();
    body.resize(212, 0);  // observed real-client auto-login LOGIN body size
    return wfh::proto::EncodeTcpFrame(static_cast<std::uint8_t>(Opcode::Login), body).value();
}

auto DrainFrames(const std::vector<std::uint8_t>& bytes) -> std::vector<Frame> {
    TcpFrameAccumulator acc;
    EXPECT_TRUE(acc.Feed(bytes.data(), bytes.size()));
    std::vector<Frame> frames;
    while (auto frame = acc.Next()) {
        frames.push_back(*frame);
    }
    return frames;
}

auto CountEntitiesInViewUpdate(const Frame& frame) -> std::uint8_t {
    EXPECT_EQ(frame.opcode, static_cast<std::uint8_t>(Opcode::ViewUpdate));
    BitReader r(frame.body.data(), frame.body.size());
    (void)r.ReadI32();  // timestamp
    (void)r.ReadI32();  // sequence
    const auto has_stats = r.ReadBool();
    if (has_stats && *has_stats) {
        (void)r.ReadBits(5);   // weapon id / padding
        (void)r.ReadBits(10);  // health
        (void)r.ReadBits(10);  // energy
    }
    const auto count = r.ReadBits(8);
    return static_cast<std::uint8_t>(count.value_or(0));
}

auto Fnv1a32(const std::vector<std::uint8_t>& bytes) -> std::uint32_t {
    constexpr std::uint32_t kFnvOffset = 2166136261U;
    constexpr std::uint32_t kFnvPrime = 16777619U;
    std::uint32_t hash = kFnvOffset;
    for (const std::uint8_t byte : bytes) {
        hash ^= byte;
        hash *= kFnvPrime;
    }
    return hash;
}

struct DecodedEntity {
    std::int32_t net_id = 0;
    bool is_manned = false;
    std::uint32_t mask = 0;
    std::uint32_t unit_type = 0;
    std::uint32_t team = 0;
};

void SkipQuantizedVec3(BitReader& reader) {
    constexpr unsigned kVectorHeaderBits = 4;
    constexpr unsigned kVectorPayloadBits = 16;
    (void)reader.ReadBits(kVectorHeaderBits);
    (void)reader.ReadBits(kVectorPayloadBits);
    (void)reader.ReadBits(kVectorPayloadBits);
    (void)reader.ReadBits(kVectorPayloadBits);
}

auto DecodeEntitiesInViewUpdate(const Frame& frame) -> std::vector<DecodedEntity> {
    EXPECT_EQ(frame.opcode, static_cast<std::uint8_t>(Opcode::ViewUpdate));
    BitReader r(frame.body.data(), frame.body.size());
    (void)r.ReadI32();  // timestamp
    (void)r.ReadI32();  // sequence
    const auto has_stats = r.ReadBool();
    if (has_stats && *has_stats) {
        (void)r.ReadBits(5);   // weapon id / padding
        (void)r.ReadBits(10);  // health
        (void)r.ReadBits(10);  // energy
    }

    std::vector<DecodedEntity> entities;
    const auto count = r.ReadBits(8);
    for (std::uint32_t i = 0; i < count.value_or(0); ++i) {
        DecodedEntity entity;
        entity.net_id = r.ReadI32().value_or(0);
        entity.is_manned = r.ReadBool().value_or(false);
        entity.mask = r.ReadBits(10).value_or(0);
        (void)r.ReadBits(16);  // translation bank selector
        if ((entity.mask & (1U << 0U)) != 0U) {
            entity.unit_type = r.ReadBits(8).value_or(0);
            entity.team = r.ReadBits(8).value_or(0);
            (void)r.ReadBits(8);  // state/subteam
            if (entity.unit_type == 37U) {
                (void)r.ReadI32();
                (void)r.ReadI32();
            } else if (entity.unit_type == 19U) {
                (void)r.ReadBits(8);  // cargo contents
            }
            (void)r.ReadBool();  // force snap
        }
        if ((entity.mask & (1U << 1U)) != 0U) {
            SkipQuantizedVec3(r);
        }
        if ((entity.mask & (1U << 2U)) != 0U) {
            SkipQuantizedVec3(r);
        }
        if ((entity.mask & (1U << 3U)) != 0U) {
            SkipQuantizedVec3(r);
        }
        if ((entity.mask & (1U << 4U)) != 0U) {
            SkipQuantizedVec3(r);
        }
        if ((entity.mask & (1U << 5U)) != 0U) {
            (void)r.ReadBits(10);
        }
        if ((entity.mask & (1U << 7U)) != 0U) {
            (void)r.ReadBits(10);
        }
        if ((entity.mask & (1U << 8U)) != 0U) {
            (void)r.ReadI32();
        }
        entities.push_back(entity);
    }
    EXPECT_FALSE(r.Failed());
    return entities;
}

auto CountEntitiesMatching(const std::vector<DecodedEntity>& entities, std::uint32_t unit_type,
                           std::uint32_t team, bool is_manned) -> int {
    return static_cast<int>(
        std::count_if(entities.begin(), entities.end(), [=](const DecodedEntity& entity) {
            return entity.unit_type == unit_type && entity.team == team &&
                   entity.is_manned == is_manned;
        }));
}

auto FirstViewUpdateForSession(const std::vector<OutboundMessage>& messages,
                               std::uint64_t session_id) -> std::optional<Frame> {
    for (const OutboundMessage& msg : messages) {
        if (msg.session_id != session_id) {
            continue;
        }
        const Frame frame = FirstFrame(msg.bytes);
        if (frame.opcode == static_cast<std::uint8_t>(Opcode::ViewUpdate)) {
            return frame;
        }
    }
    return std::nullopt;
}

auto TempMapRoot() -> std::filesystem::path {
    const auto stamp = std::chrono::steady_clock::now().time_since_epoch().count();
    auto path = std::filesystem::temp_directory_path() / ("wfh_map_test_" + std::to_string(stamp));
    std::filesystem::create_directories(path);
    return path;
}

class ScopedCurrentPath {
public:
    explicit ScopedCurrentPath(const std::filesystem::path& path)
        : original_(std::filesystem::current_path()) {
        std::filesystem::current_path(path);
    }

    ~ScopedCurrentPath() {
        std::error_code ignored;
        std::filesystem::current_path(original_, ignored);
    }

    ScopedCurrentPath(const ScopedCurrentPath&) = delete;
    auto operator=(const ScopedCurrentPath&) -> ScopedCurrentPath& = delete;

private:
    std::filesystem::path original_;
};

void WriteTextFile(const std::filesystem::path& path, const std::string& contents) {
    std::ofstream out(path, std::ios::binary);
    out << contents;
}

auto MakeSpawnRequestBody(std::uint16_t sequence, std::int32_t selected_entry_id,
                          std::int32_t base_id) -> std::vector<std::uint8_t> {
    wfh::proto::BitWriter writer;
    writer.WriteU16(sequence);
    writer.WriteU16(17);
    writer.WriteByte(0);
    writer.WriteI32(selected_entry_id);
    writer.WriteI32(base_id);
    writer.WriteI32(2000);
    writer.WriteI32(700);
    return writer.Bytes();
}

void ExpectUdpAck(const std::uint8_t* bytes, std::size_t len, std::uint16_t acked_sequence,
                  std::uint8_t acked_opcode) {
    ASSERT_EQ(len, 9u);
    EXPECT_EQ(bytes[0], 0x02);
    BitReader reader(bytes + 1, len - 1);
    EXPECT_EQ(reader.ReadU16().value(), 1);
    EXPECT_EQ(reader.ReadU16().value(), 9);
    EXPECT_EQ(reader.ReadByte().value(), 1);
    EXPECT_EQ(reader.ReadByte().value(), acked_opcode);
    EXPECT_EQ(reader.ReadU16().value(), acked_sequence);
    EXPECT_FALSE(reader.Failed());
}

auto MakeTeamRequestBody(std::uint16_t sequence, std::int32_t team_id)
    -> std::vector<std::uint8_t> {
    wfh::proto::BitWriter writer;
    writer.WriteU16(sequence);
    writer.WriteU16(9);
    writer.WriteByte(1);
    writer.WriteI32(team_id);
    writer.WriteI32(0);
    return writer.Bytes();
}

// --- ServerConfig ----------------------------------------------------------

TEST(ServerConfig, ParsesServerSection) {
    const auto cfg = ParseServerConfig(
        "[log]\nlevel = \"debug\"\n[server]\nbind_port = 1234\ntick_hz = 30\nmap = \"foo\"\n");
    EXPECT_EQ(cfg.bind_port, 1234);
    EXPECT_EQ(cfg.tick_hz, 30u);
    EXPECT_EQ(cfg.map, "foo");
}

TEST(ServerConfig, DefaultsWhenMissingOrOutOfRange) {
    const auto cfg = ParseServerConfig("[server]\nbind_port = 99999\n");  // out of range
    EXPECT_EQ(cfg.bind_port, 2627);                                       // keeps default
    EXPECT_EQ(cfg.map, "bpass");
}

TEST(ServerConfig, IgnoresKeysOutsideServerSection) {
    const auto cfg = ParseServerConfig("[other]\nbind_port = 1\n[server]\nmap = bar\n");
    EXPECT_EQ(cfg.bind_port, 2627);
    EXPECT_EQ(cfg.map, "bar");
}

TEST(ServerConfig, WorldHostDefaultsOff) {
    const auto cfg = ParseServerConfig("[server]\nmap = bar\n");
    EXPECT_FALSE(cfg.world_host);
}

TEST(ServerConfig, ParsesWorldHostTrue) {
    const auto cfg = ParseServerConfig("[server]\nworld_host = true\n");
    EXPECT_TRUE(cfg.world_host);
}

TEST(ServerConfig, ParsesWorldHostNumericAndFalse) {
    EXPECT_TRUE(ParseServerConfig("[server]\nworld_host = 1\n").world_host);
    EXPECT_FALSE(ParseServerConfig("[server]\nworld_host = false\n").world_host);
    EXPECT_FALSE(ParseServerConfig("[server]\nworld_host = 0\n").world_host);
}

// --- Bring-up packets ------------------------------------------------------

TEST(BringupPackets, HelloVersionCarriesProtocolVersion) {
    const auto bytes = BuildHelloVersion();
    const Frame f = FirstFrame(bytes);
    EXPECT_EQ(f.opcode, static_cast<std::uint8_t>(Opcode::Hello));
    BitReader r(f.body.data(), f.body.size());
    EXPECT_EQ(r.ReadByte().value(), 0x00);             // subtype VERSION
    EXPECT_EQ(r.ReadI32().value(), kProtocolVersion);  // 0x4E89
}

TEST(BringupPackets, UdpConfigRoundTrips) {
    const auto bytes = BuildHelloUdpConfig(2627, "127.0.0.1");
    const Frame f = FirstFrame(bytes);
    BitReader r(f.body.data(), f.body.size());
    EXPECT_EQ(r.ReadByte().value(), 0x01);  // subtype UDP_CONFIG
    EXPECT_EQ(r.ReadU16().value(), 2627);   // port
    EXPECT_EQ(r.ReadU16().value(), 1);      // host count
    EXPECT_EQ(r.ReadString(256).value(), "127.0.0.1");
}

TEST(BringupPackets, RosterRoundTrips) {
    const auto bytes = BuildAddToRoster(7, 1, "player", "tag");
    const Frame f = FirstFrame(bytes);
    EXPECT_EQ(f.opcode, static_cast<std::uint8_t>(Opcode::AddToRoster));
    BitReader r(f.body.data(), f.body.size());
    EXPECT_EQ(r.ReadI32().value(), 7);  // account id
    EXPECT_EQ(r.ReadI32().value(), 0);  // metadata
    EXPECT_EQ(r.ReadU16().value(), 1);  // team
}

TEST(BringupPackets, TranslationContainsTwentyEightEntries) {
    const auto bytes = BuildTranslation();
    const Frame f = FirstFrame(bytes);
    EXPECT_EQ(f.opcode, static_cast<std::uint8_t>(Opcode::Translation));

    BitReader r(f.body.data(), f.body.size());
    EXPECT_EQ(r.ReadI32().value(), 16);  // slot 0 header bits
    EXPECT_EQ(r.ReadI32().value(), 0);   // slot 0 padding
    EXPECT_EQ(r.ReadI32().value(), 0);   // slot 0 fixed-width total
    EXPECT_EQ(r.ReadString(64).value(), "1000.0");
    EXPECT_EQ(r.ReadString(64).value(), "2000.0");

    EXPECT_EQ(r.ReadI32().value(), 5);  // slot 1 weapon id width
}

TEST(BringupPackets, ViewUpdateSnapshotCarriesTwoTankDefinitions) {
    std::vector<MvpEntitySnapshot> entities;
    entities.push_back(MvpEntitySnapshot{1, 0, 1, true, {100.0F, 100.0F, 100.0F}});
    entities.push_back(MvpEntitySnapshot{2, 0, 2, true, {140.0F, 100.0F, 100.0F}});

    const auto bytes = BuildViewUpdateSnapshot(123, entities, 1.0F, 1.0F);
    const Frame f = FirstFrame(bytes);
    EXPECT_EQ(CountEntitiesInViewUpdate(f), 2);

    BitReader r(f.body.data(), f.body.size());
    EXPECT_EQ(r.ReadI32().value(), 123);  // timestamp
    EXPECT_EQ(r.ReadI32().value(), 123);  // sequence
    EXPECT_TRUE(r.ReadBool().value());
    (void)r.ReadBits(5);
    (void)r.ReadBits(10);
    (void)r.ReadBits(10);
    EXPECT_EQ(r.ReadBits(8).value(), 2);

    EXPECT_EQ(r.ReadI32().value(), 1);  // first entity id
    EXPECT_TRUE(r.ReadBool().value());
    EXPECT_EQ(r.ReadBits(10).value(), 0x02Bu);  // DEF | POS | ROT | HEALTH
    EXPECT_EQ(r.ReadBits(16).value(), 0u);      // bank selector
    EXPECT_EQ(r.ReadBits(8).value(), 0u);       // unit type
    EXPECT_EQ(r.ReadBits(8).value(), 1u);       // team
}

TEST(BringupPackets, ViewUpdateSnapshotIncludesRotationSoFixturesAreNotSideways) {
    // Map fixtures (repair pads/bases) carry an orientation; the snapshot MUST declare
    // and send ROT (mask bit 3) per entity or the client renders them at a default
    // orientation ("sideways"). Decoding through the per-mask reader also proves the
    // rotation vec3 is laid out where the client expects it (POS, then ROT, then HEALTH).
    std::vector<MvpEntitySnapshot> entities;
    MvpEntitySnapshot pad{};
    pad.net_id = 9;
    pad.unit_type = 0;
    pad.team = 1;
    pad.is_manned = false;
    pad.pos = {5150.0F, 5241.0F, 7.7F};
    pad.rot = {0.16F, 0.13F, 4.65F};  // non-trivial heading (radians), like a real pad
    entities.push_back(pad);

    const auto bytes = BuildViewUpdateSnapshot(123, entities, 1.0F, 1.0F);
    const Frame f = FirstFrame(bytes);
    const auto decoded = DecodeEntitiesInViewUpdate(f);

    ASSERT_EQ(decoded.size(), 1u);
    constexpr std::uint32_t kRotBit = 1U << 3U;
    constexpr std::uint32_t kExpectedMask = 0x02Bu;  // DEF | POS | ROT | HEALTH
    EXPECT_NE(decoded.at(0).mask & kRotBit, 0u);
    EXPECT_EQ(decoded.at(0).mask, kExpectedMask);
    EXPECT_EQ(decoded.at(0).net_id, 9);
}

TEST(BringupPackets, BehaviorMatchesPythonPacketsTomlDefaults) {
    const auto bytes = BuildBehavior();
    EXPECT_EQ(bytes.size(), 3566u);
    EXPECT_EQ(Fnv1a32(bytes), 0x11c91899u);
}

// DISABLED dev aid (NOT run in CI): dumps the BEHAVIOR/TRANSLATION *bodies* (the bytes
// the engine dispatcher wraps in a MemBuff and passes to Net_HandleBehavior /
// Net_HandleTranslationTable — i.e. frame minus the 2-byte length + 1 opcode) to
// behavior_body.bin / translation_body.bin in the CWD, so the live dev-console probe
// (tools/feed_onjoin_probe.py) can feed them through the engine's own on-join handlers.
// Run explicitly:
//   build/wfh_tests.exe --gtest_filter=*DumpOnJoinBodies* --gtest_also_run_disabled_tests
TEST(BringupPackets, DISABLED_DumpOnJoinBodies) {
    const auto write_body = [](const char* path, const std::vector<std::uint8_t>& bytes) {
        const Frame frame = FirstFrame(bytes);
        std::ofstream out(path, std::ios::binary);
        out.write(reinterpret_cast<const char*>(frame.body.data()),
                  static_cast<std::streamsize>(frame.body.size()));
        std::cout << path << " opcode=0x" << std::hex << static_cast<int>(frame.opcode) << std::dec
                  << " body_len=" << frame.body.size() << "\n";
    };
    write_body("behavior_body.bin", BuildBehavior());
    write_body("translation_body.bin", BuildTranslation());
    SUCCEED();
}

TEST(WorldPackets, SpawnResultPacketsMatchPythonReferenceShapes) {
    const Frame reincarnate = FirstFrame(BuildReincarnateResult(0, ""));
    EXPECT_EQ(reincarnate.opcode, static_cast<std::uint8_t>(Opcode::Reincarnate));
    BitReader reincarnate_reader(reincarnate.body.data(), reincarnate.body.size());
    EXPECT_EQ(reincarnate_reader.ReadByte().value(), 0);
    EXPECT_EQ(reincarnate_reader.ReadString(64).value(), "");

    const Frame birth = FirstFrame(BuildBirthNotice(7));
    EXPECT_EQ(birth.opcode, static_cast<std::uint8_t>(Opcode::BirthNotice));
    BitReader birth_reader(birth.body.data(), birth.body.size());
    EXPECT_EQ(birth_reader.ReadI32().value(), 7);
    EXPECT_EQ(birth_reader.ReadI32().value(), 1);

    TankSpawnSpec spec;
    spec.sequence = 77;
    spec.net_id = 99;
    spec.unit_type = 0;
    spec.team = 1;
    spec.pos = {400.0F, 500.0F, 90.0F};
    spec.rot = {0.0F, 0.0F, 0.0F};

    const Frame tank = FirstFrame(BuildTankSpawn(spec));
    EXPECT_EQ(tank.opcode, static_cast<std::uint8_t>(Opcode::TankSpawn));
    BitReader tank_reader(tank.body.data(), tank.body.size());
    EXPECT_EQ(tank_reader.ReadI32().value(), 77);
    EXPECT_TRUE(tank_reader.ReadBool().value());
    EXPECT_EQ(tank_reader.ReadBits(5).value(), 0u);
    EXPECT_EQ(tank_reader.ReadBits(10).value(), 1u);
    EXPECT_EQ(tank_reader.ReadBits(10).value(), 1u);
    EXPECT_EQ(tank_reader.ReadI32().value(), 0);
    EXPECT_EQ(tank_reader.ReadI32().value(), 99);
    EXPECT_EQ(tank_reader.ReadByte().value(), 1);
    EXPECT_NEAR(tank_reader.ReadFixed1616().value(), 400.0, 0.001);
    EXPECT_NEAR(tank_reader.ReadFixed1616().value(), 500.0, 0.001);
    EXPECT_NEAR(tank_reader.ReadFixed1616().value(), 90.0, 0.001);
}

// --- Connection state machine ----------------------------------------------

// The accept burst must mirror the proven Python handshake: UDP_CONFIG (sub 1)
// then SESSION_KEY (sub 2), with NO server-sent VERSION (sub 0). VERSION is a
// client->server packet; sending it back stalls the real client before it echoes
// the session key over UDP, so the engine self-connection never links.
TEST(Connection, AcceptBurstIsUdpConfigThenSessionKeyNoVersion) {
    ServerConfig cfg;
    IncomingCmdQueue inbound;
    Connection conn(1, cfg, "Key1234", inbound);

    const auto hello = conn.OnAccept();

    std::vector<std::uint8_t> hello_subcmds;
    TcpFrameAccumulator acc;
    ASSERT_TRUE(acc.Feed(hello.data(), hello.size()));
    while (auto frame = acc.Next()) {
        if (frame->opcode != static_cast<std::uint8_t>(Opcode::Hello)) {
            continue;
        }
        BitReader r(frame->body.data(), frame->body.size());
        const auto sub = r.ReadByte();
        ASSERT_TRUE(sub.has_value());
        hello_subcmds.push_back(*sub);
    }

    EXPECT_EQ(hello_subcmds, (std::vector<std::uint8_t>{0x01, 0x02}));
}

// Drive a connection through the full proven order and assert it reaches Verified.
TEST(Connection, HappyPathReachesVerified) {
    ServerConfig cfg;
    IncomingCmdQueue inbound;
    Connection conn(1, cfg, "Key1234", inbound);

    const auto hello = conn.OnAccept();
    EXPECT_FALSE(hello.empty());
    EXPECT_EQ(conn.State(), ConnState::AwaitingKeyEcho);

    // Client sends HELLO(version) on TCP — accepted, still awaiting key echo.
    const auto vframe = MakeFrame(Opcode::Hello, [](wfh::proto::BitWriter& w) {
        w.WriteByte(0x00);
        w.WriteI32(kProtocolVersion);
    });
    auto step = conn.OnTcpData(vframe.data(), vframe.size());
    EXPECT_FALSE(step.close);
    EXPECT_EQ(conn.State(), ConnState::AwaitingKeyEcho);

    // UDP key echo links the endpoint -> AwaitingUsername + IDENTIFIED_UDP out.
    wfh::proto::BitWriter echo;
    echo.WriteByte(0x01);  // HELLO subtype key-echo
    echo.WriteString("Key1234");
    const auto echo_body = echo.Bytes();
    auto ustep = conn.OnUdpPacket(static_cast<std::uint8_t>(Opcode::Hello), echo_body.data(),
                                  echo_body.size());
    EXPECT_FALSE(ustep.tcp_out.empty());
    EXPECT_EQ(conn.State(), ConnState::AwaitingUsername);

    // LOGIN username -> AwaitingPassword.
    const auto uframe =
        MakeFrame(Opcode::Login, [](wfh::proto::BitWriter& w) { w.WriteString("alice"); });
    const auto namestep = conn.OnTcpData(uframe.data(), uframe.size());
    EXPECT_FALSE(namestep.close);
    EXPECT_EQ(conn.State(), ConnState::AwaitingPassword);

    // LOGIN password -> Verified + bring-up burst emitted.
    const auto pframe =
        MakeFrame(Opcode::Login, [](wfh::proto::BitWriter& w) { w.WriteString("secret"); });
    auto pstep = conn.OnTcpData(pframe.data(), pframe.size());
    EXPECT_EQ(conn.State(), ConnState::Verified);
    EXPECT_FALSE(pstep.tcp_out.empty());
    const std::vector<Frame> bringup = DrainFrames(pstep.tcp_out);
    const auto has_behavior = std::any_of(bringup.begin(), bringup.end(), [](const Frame& frame) {
        return frame.opcode == static_cast<std::uint8_t>(Opcode::Behavior);
    });
    const auto has_translation =
        std::any_of(bringup.begin(), bringup.end(), [](const Frame& frame) {
            return frame.opcode == static_cast<std::uint8_t>(Opcode::Translation);
        });
    EXPECT_TRUE(has_behavior);
    EXPECT_TRUE(has_translation);

    // WANT_UPDATES -> InGame.
    const auto wframe = MakeFrame(Opcode::WantUpdates, [](wfh::proto::BitWriter&) {});
    const auto wstep = conn.OnTcpData(wframe.data(), wframe.size());
    EXPECT_FALSE(wstep.close);
    EXPECT_EQ(conn.State(), ConnState::InGame);

    // The inbound queue saw user/password/connected/wantupdates commands.
    const auto cmds = inbound.DrainAll();
    EXPECT_GE(cmds.size(), 4u);
}

TEST(Connection, UdpKeyEchoBeforeTcpVersionStillAcceptsVersionNoOp) {
    ServerConfig cfg;
    IncomingCmdQueue inbound;
    Connection conn(1, cfg, "Key1234", inbound);
    (void)conn.OnAccept();

    wfh::proto::BitWriter echo;
    echo.WriteByte(0x01);
    echo.WriteString("Key1234");
    const auto echo_body = echo.Bytes();
    auto ustep = conn.OnUdpPacket(static_cast<std::uint8_t>(Opcode::Hello), echo_body.data(),
                                  echo_body.size());
    EXPECT_FALSE(ustep.tcp_out.empty());
    EXPECT_EQ(conn.State(), ConnState::AwaitingUsername);

    const auto delayed_version = MakeFrame(Opcode::Hello, [](wfh::proto::BitWriter& w) {
        w.WriteByte(0x00);
        w.WriteI32(kProtocolVersion);
    });
    const auto step = conn.OnTcpData(delayed_version.data(), delayed_version.size());

    EXPECT_FALSE(step.close);
    EXPECT_EQ(conn.State(), ConnState::AwaitingUsername);
}

TEST(Connection, UdpKeyEchoBeforePostLinkHelloSubcmdTwoKeepsAwaitingUsername) {
    ServerConfig cfg;
    IncomingCmdQueue inbound;
    Connection conn(1, cfg, "Key1234", inbound);
    (void)conn.OnAccept();

    wfh::proto::BitWriter echo;
    echo.WriteByte(0x01);
    echo.WriteString("Key1234");
    const auto echo_body = echo.Bytes();
    auto ustep = conn.OnUdpPacket(static_cast<std::uint8_t>(Opcode::Hello), echo_body.data(),
                                  echo_body.size());
    EXPECT_FALSE(ustep.tcp_out.empty());
    EXPECT_EQ(conn.State(), ConnState::AwaitingUsername);

    const auto post_link_hello =
        MakeFrame(Opcode::Hello, [](wfh::proto::BitWriter& w) { w.WriteByte(0x02); });
    const auto step = conn.OnTcpData(post_link_hello.data(), post_link_hello.size());

    EXPECT_FALSE(step.close);
    EXPECT_EQ(conn.State(), ConnState::AwaitingUsername);
}

TEST(Connection, PythonStyleLoginFrameWithPasswordCompletesVerifiedWithoutPrompt) {
    ServerConfig cfg;
    IncomingCmdQueue inbound;
    Connection conn(1, cfg, "Key1234", inbound);
    (void)conn.OnAccept();

    wfh::proto::BitWriter echo;
    echo.WriteByte(0x01);
    echo.WriteString("Key1234");
    const auto echo_body = echo.Bytes();
    auto ustep = conn.OnUdpPacket(static_cast<std::uint8_t>(Opcode::Hello), echo_body.data(),
                                  echo_body.size());
    EXPECT_FALSE(ustep.tcp_out.empty());
    EXPECT_EQ(conn.State(), ConnState::AwaitingUsername);

    const auto login = MakePythonStyleLoginFrame("codex_a", "pass_local");
    const auto step = conn.OnTcpData(login.data(), login.size());

    EXPECT_FALSE(step.close);
    EXPECT_EQ(conn.State(), ConnState::Verified);
    EXPECT_FALSE(step.tcp_out.empty());
}

TEST(Connection, BpsRequestAfterLoginGetsApprovedReply) {
    ServerConfig cfg;
    IncomingCmdQueue inbound;
    Connection conn(1, cfg, "Key1234", inbound);
    (void)conn.OnAccept();

    wfh::proto::BitWriter echo;
    echo.WriteByte(0x01);
    echo.WriteString("Key1234");
    const auto echo_body = echo.Bytes();
    auto ustep = conn.OnUdpPacket(static_cast<std::uint8_t>(Opcode::Hello), echo_body.data(),
                                  echo_body.size());
    EXPECT_FALSE(ustep.tcp_out.empty());

    const auto login = MakePythonStyleLoginFrame("codex_a", "pass_local");
    auto login_step = conn.OnTcpData(login.data(), login.size());
    EXPECT_FALSE(login_step.close);
    ASSERT_EQ(conn.State(), ConnState::Verified);

    wfh::proto::BitWriter bps_body;
    bps_body.WriteI32(60);
    const auto bps = wfh::proto::EncodeTcpFrame(0x4E, bps_body.Bytes()).value();
    const auto bps_step = conn.OnTcpData(bps.data(), bps.size());

    EXPECT_FALSE(bps_step.close);
    EXPECT_EQ(conn.State(), ConnState::Verified);
    const Frame reply = FirstFrame(bps_step.tcp_out);
    EXPECT_EQ(reply.opcode, 0x4E);
    BitReader r(reply.body.data(), reply.body.size());
    EXPECT_EQ(r.ReadI32().value(), 60);
    EXPECT_EQ(r.ReadByte().value(), 1);
}

TEST(Connection, InGameUdpReincarnateSpawnRequestEnqueuesCommand) {
    ServerConfig cfg;
    IncomingCmdQueue inbound;
    Connection conn(1, cfg, "Key1234", inbound);
    (void)conn.OnAccept();

    wfh::proto::BitWriter echo;
    echo.WriteByte(0x01);
    echo.WriteString("Key1234");
    const auto echo_body = echo.Bytes();
    auto ustep = conn.OnUdpPacket(static_cast<std::uint8_t>(Opcode::Hello), echo_body.data(),
                                  echo_body.size());
    EXPECT_FALSE(ustep.tcp_out.empty());

    const auto login = MakePythonStyleLoginFrame("codex_a", "pass_local");
    auto login_step = conn.OnTcpData(login.data(), login.size());
    EXPECT_FALSE(login_step.close);
    ASSERT_EQ(conn.State(), ConnState::Verified);

    const auto want_updates = MakeFrame(Opcode::WantUpdates, [](wfh::proto::BitWriter&) {});
    const auto want_step = conn.OnTcpData(want_updates.data(), want_updates.size());
    EXPECT_FALSE(want_step.close);
    ASSERT_EQ(conn.State(), ConnState::InGame);
    (void)inbound.DrainAll();

    const auto spawn_body = MakeSpawnRequestBody(0x1234, 5, 99);
    const auto spawn_step = conn.OnUdpPacket(static_cast<std::uint8_t>(Opcode::Reincarnate),
                                             spawn_body.data(), spawn_body.size());

    EXPECT_FALSE(spawn_step.close);
    ExpectUdpAck(spawn_step.udp_out.data(), spawn_step.udp_out.size(), 0x1234,
                 static_cast<std::uint8_t>(Opcode::Reincarnate));
    const auto cmds = inbound.DrainAll();
    ASSERT_EQ(cmds.size(), 1u);
    EXPECT_EQ(cmds.at(0).kind, ClientCommandKind::Reincarnate);
    EXPECT_EQ(cmds.at(0).session_id, 1u);
    EXPECT_EQ(cmds.at(0).unit_id, 5);
    EXPECT_EQ(cmds.at(0).pad_id, 99);
}

// Reach InGame on `conn` (accept -> UDP key echo -> login -> WANT_UPDATES) and drain any
// commands enqueued along the way, leaving the queue empty for the caller's assertions.
void DriveConnectionToInGame(Connection& conn, IncomingCmdQueue& inbound) {
    (void)conn.OnAccept();
    wfh::proto::BitWriter echo;
    echo.WriteByte(0x01);
    echo.WriteString("Key1234");
    const auto echo_body = echo.Bytes();
    (void)conn.OnUdpPacket(static_cast<std::uint8_t>(Opcode::Hello), echo_body.data(),
                           echo_body.size());
    const auto login = MakePythonStyleLoginFrame("codex_a", "pass_local");
    (void)conn.OnTcpData(login.data(), login.size());
    const auto want_updates = MakeFrame(Opcode::WantUpdates, [](wfh::proto::BitWriter&) {});
    (void)conn.OnTcpData(want_updates.data(), want_updates.size());
    (void)inbound.DrainAll();
}

TEST(Connection, InGameUdpActionUpdateEnqueuesActionInputCommands) {
    ServerConfig cfg;
    IncomingCmdQueue inbound;
    Connection conn(1, cfg, "Key1234", inbound);
    DriveConnectionToInGame(conn, inbound);
    ASSERT_EQ(conn.State(), ConnState::InGame);

    // Real 0x0A capture body (post-opcode): count=2, ch1 (~0.120) + ch6 (~0).
    const std::vector<std::uint8_t> body{0x02, 0x00, 0x00, 0x4a, 0xe7, 0x00, 0x00, 0x00, 0x00,
                                         0x00, 0x01, 0x70, 0xa2, 0x00, 0x06, 0x80, 0x1f};
    const auto step =
        conn.OnUdpPacket(static_cast<std::uint8_t>(Opcode::ActionUpdate), body.data(), body.size());
    EXPECT_FALSE(step.close);

    const auto cmds = inbound.DrainAll();
    ASSERT_EQ(cmds.size(), 2u);
    EXPECT_EQ(cmds.at(0).kind, ClientCommandKind::ActionInput);
    EXPECT_EQ(cmds.at(0).session_id, 1u);
    EXPECT_EQ(cmds.at(0).channel, 1);
    EXPECT_NEAR(cmds.at(0).value, 0.120F, 0.005F);
    EXPECT_EQ(cmds.at(1).channel, 6);
    EXPECT_NEAR(cmds.at(1).value, 0.0F, 0.01F);
}

TEST(Connection, UdpActionBeforeInGameIsIgnored) {
    ServerConfig cfg;
    IncomingCmdQueue inbound;
    Connection conn(1, cfg, "Key1234", inbound);
    (void)conn.OnAccept();  // state = AwaitingKeyEcho, not InGame

    const std::vector<std::uint8_t> body{0x01, 0x00, 0x00, 0x50, 0x83, 0x00, 0x00,
                                         0x00, 0x00, 0x00, 0x06, 0x85, 0x87};
    const auto step =
        conn.OnUdpPacket(static_cast<std::uint8_t>(Opcode::ActionUpdate), body.data(), body.size());
    EXPECT_FALSE(step.close);
    EXPECT_TRUE(inbound.DrainAll().empty());
}

TEST(BringupPackets, UdpUpdateStatsMatchesPythonTeamSwitchBytes) {
    // Byte-for-byte match of the reference server's UPDATE_STATS (0x1C) emitted on a
    // team switch (captured: player_id=4 team=2). This is the packet that makes the
    // client update its roster list + activate the entry-map / respawn selector.
    const auto bytes = BuildUdpUpdateStats(4, 2);
    const std::vector<std::uint8_t> expected = {
        0x1C,                    // opcode
        0x00, 0x00, 0x00, 0x04,  // player_id = 4
        0x00, 0x00, 0x00, 0x06,  // record kind = 6
        0x00, 0x02,              // team = 2
        0x00, 0x21,              // field mask = 33
        0x00, 0x03,              // field a = 3
        0x00, 0x05,              // field b = 5
        0x00, 0x09,              // field c = 9
        0x00, 0x01, 0x00, 0x00,  // fixed16.16 1.0
        0x00, 0x01, 0x00, 0x00,  // fixed16.16 1.0
        0x00, 0x00, 0x00, 0x0A,  // trailing flags = 10
    };
    EXPECT_EQ(bytes, expected);
}

TEST(Connection, InGameUdpTeamSwitchEmitsAckAndUpdateStats) {
    ServerConfig cfg;
    IncomingCmdQueue inbound;
    Connection conn(1, cfg, "Key1234", inbound);
    (void)conn.OnAccept();

    wfh::proto::BitWriter echo;
    echo.WriteByte(0x01);
    echo.WriteString("Key1234");
    const auto echo_body = echo.Bytes();
    (void)conn.OnUdpPacket(static_cast<std::uint8_t>(Opcode::Hello), echo_body.data(),
                           echo_body.size());

    const auto login = MakePythonStyleLoginFrame("codex_a", "pass_local");
    (void)conn.OnTcpData(login.data(), login.size());
    ASSERT_EQ(conn.State(), ConnState::Verified);
    const auto want_updates = MakeFrame(Opcode::WantUpdates, [](wfh::proto::BitWriter&) {});
    (void)conn.OnTcpData(want_updates.data(), want_updates.size());
    ASSERT_EQ(conn.State(), ConnState::InGame);
    (void)inbound.DrainAll();

    const auto team_body = MakeTeamRequestBody(0x0007, 2);
    const auto step = conn.OnUdpPacket(static_cast<std::uint8_t>(Opcode::Reincarnate),
                                       team_body.data(), team_body.size());

    EXPECT_FALSE(step.close);
    // The ack still goes out as the single udp_out datagram.
    ExpectUdpAck(step.udp_out.data(), step.udp_out.size(), 0x0007,
                 static_cast<std::uint8_t>(Opcode::Reincarnate));
    // The team-switch reply adds the UPDATE_STATS (0x1C) record on UDP.
    ASSERT_EQ(step.udp_datagrams.size(), 1u);
    const auto& stats = step.udp_datagrams.at(0);
    wfh::proto::BitReader r(stats.data(), stats.size());
    EXPECT_EQ(r.ReadByte().value(), 0x1Cu);  // UPDATE_STATS opcode
    EXPECT_EQ(r.ReadI32().value(), 1);       // player_id (session 1)
    EXPECT_EQ(r.ReadI32().value(), 6);       // record kind
    EXPECT_EQ(r.ReadU16().value(), 2u);      // team = 2
    EXPECT_FALSE(r.Failed());

    // The team switch is still queued for the world bridge.
    const auto cmds = inbound.DrainAll();
    ASSERT_EQ(cmds.size(), 1u);
    EXPECT_EQ(cmds.at(0).kind, ClientCommandKind::Reincarnate);
    EXPECT_EQ(cmds.at(0).team, 2);
}

TEST(Connection, EarlyGenericPacketBeforeKeyEchoIsNoOp) {
    ServerConfig cfg;
    IncomingCmdQueue inbound;
    Connection conn(1, cfg, "Key1234", inbound);
    (void)conn.OnAccept();

    const auto generic = MakeFrame(
        Opcode::Generic, [](wfh::proto::BitWriter& w) { w.WriteString("want_voice_data"); });
    const auto step = conn.OnTcpData(generic.data(), generic.size());

    EXPECT_FALSE(step.close);
    EXPECT_EQ(conn.State(), ConnState::AwaitingKeyEcho);
}

TEST(MvpOnlineBridge, LoadsMapStateAndSynthesizesRepairPadsBeforeSpawn) {
    const auto root = TempMapRoot();
    const auto map_dir = root / "unit_map";
    std::filesystem::create_directories(map_dir);
    WriteTextFile(map_dir / "land", "2x2\n"
                                    "1000x800\n"
                                    "0 10\n"
                                    "0 20\n"
                                    "0 30\n"
                                    "0 40\n");
    WriteTextFile(map_dir / "state", "g 1 100 200 300 0 0 0 0\n");

    WorldBootstrapConfig bootstrap;
    bootstrap.map_name = "unit_map";
    bootstrap.map_root = root.string();
    IncomingCmdQueue inbound;
    OutboundStateQueue outbound;
    MvpOnlineBridge bridge(inbound, outbound, bootstrap);

    ClientCommand connected;
    connected.kind = ClientCommandKind::ClientConnected;
    connected.session_id = 1;
    connected.text = "alice";
    inbound.Push(connected);
    inbound.Push(ClientCommand{ClientCommandKind::WantUpdates, 1});

    bridge.Tick(123);
    const auto messages = outbound.DrainAll();

    const auto snapshot = FirstViewUpdateForSession(messages, 1);
    ASSERT_TRUE(snapshot.has_value());
    const auto entities = DecodeEntitiesInViewUpdate(*snapshot);

    EXPECT_EQ(CountEntitiesMatching(entities, 30, 1, false), 1);
    EXPECT_EQ(CountEntitiesMatching(entities, 27, 1, false), 1);
    EXPECT_EQ(CountEntitiesMatching(entities, 27, 2, false), 1);
    EXPECT_EQ(CountEntitiesMatching(entities, 0, 1, true), 0);

    std::filesystem::remove_all(root);
}

TEST(MvpOnlineBridge, DefaultBootstrapLoadsBpassFromGameWorkingDirectory) {
    const auto root = TempMapRoot();
    const auto map_dir = root / "data" / "maps" / "bpass";
    std::filesystem::create_directories(map_dir);
    WriteTextFile(map_dir / "land", "2x2\n"
                                    "1000x800\n"
                                    "0 10\n"
                                    "0 20\n"
                                    "0 30\n"
                                    "0 40\n");
    WriteTextFile(map_dir / "state", "g 1 100 200 300 0 0 0 0\n");

    std::optional<Frame> snapshot;
    {
        const ScopedCurrentPath scoped_cwd(root);
        IncomingCmdQueue inbound;
        OutboundStateQueue outbound;
        MvpOnlineBridge bridge(inbound, outbound);

        ClientCommand connected;
        connected.kind = ClientCommandKind::ClientConnected;
        connected.session_id = 1;
        connected.text = "alice";
        inbound.Push(connected);
        inbound.Push(ClientCommand{ClientCommandKind::WantUpdates, 1});

        bridge.Tick(123);
        snapshot = FirstViewUpdateForSession(outbound.DrainAll(), 1);
    }

    ASSERT_TRUE(snapshot.has_value());
    const auto entities = DecodeEntitiesInViewUpdate(*snapshot);
    EXPECT_EQ(CountEntitiesMatching(entities, 30, 1, false), 1);
    EXPECT_EQ(CountEntitiesMatching(entities, 27, 1, false), 1);
    EXPECT_EQ(CountEntitiesMatching(entities, 27, 2, false), 1);

    std::filesystem::remove_all(root);
}

TEST(MvpOnlineBridge, ReincarnateSpawnUsesRepairPadAndBroadcastsSpawnState) {
    const auto root = TempMapRoot();
    const auto map_dir = root / "unit_map";
    std::filesystem::create_directories(map_dir);
    WriteTextFile(map_dir / "land", "2x2\n"
                                    "1000x800\n"
                                    "0 10\n"
                                    "0 20\n"
                                    "0 30\n"
                                    "0 40\n");

    WorldBootstrapConfig bootstrap;
    bootstrap.map_name = "unit_map";
    bootstrap.map_root = root.string();
    IncomingCmdQueue inbound;
    OutboundStateQueue outbound;
    MvpOnlineBridge bridge(inbound, outbound, bootstrap);

    ClientCommand connected;
    connected.kind = ClientCommandKind::ClientConnected;
    connected.session_id = 1;
    connected.text = "alice";
    inbound.Push(connected);
    inbound.Push(ClientCommand{ClientCommandKind::WantUpdates, 1});

    // Pick a team first (team-switch reincarnate); spawn is rejected without one.
    inbound.Push(ClientCommand{ClientCommandKind::Reincarnate, 1, 0, 0.0F, 1, 0, 0, {}});

    ClientCommand spawn;
    spawn.kind = ClientCommandKind::Reincarnate;
    spawn.session_id = 1;
    spawn.unit_id = 1;
    inbound.Push(spawn);

    bridge.Tick(123);
    const auto messages = outbound.DrainAll();

    bool saw_tank = false;
    bool saw_reincarnate = false;
    bool saw_birth = false;
    bool saw_udp_self = false;
    for (const OutboundMessage& msg : messages) {
        if (!msg.reliable) {
            // In-game updates are raw UDP datagrams ([opcode byte][body]); a spawned session
            // receives its own state via a 0x0F VIEW_UPDATE.
            if (!msg.bytes.empty() &&
                msg.bytes.front() == static_cast<std::uint8_t>(Opcode::ViewUpdate) &&
                msg.session_id == 1) {
                saw_udp_self = true;
            }
            continue;
        }
        const Frame frame = FirstFrame(msg.bytes);
        saw_tank = saw_tank || frame.opcode == static_cast<std::uint8_t>(Opcode::TankSpawn);
        saw_reincarnate =
            saw_reincarnate || frame.opcode == static_cast<std::uint8_t>(Opcode::Reincarnate);
        saw_birth = saw_birth || frame.opcode == static_cast<std::uint8_t>(Opcode::BirthNotice);
    }
    EXPECT_TRUE(saw_tank);
    EXPECT_TRUE(saw_reincarnate);
    EXPECT_TRUE(saw_birth);
    EXPECT_TRUE(saw_udp_self);

    std::filesystem::remove_all(root);
}

TEST(MvpOnlineBridge, ActionInputRoutesToSpawnedSessionEngineOid) {
    const auto root = TempMapRoot();
    const auto map_dir = root / "unit_map";
    std::filesystem::create_directories(map_dir);
    WriteTextFile(map_dir / "land", "2x2\n1000x800\n0 10\n0 20\n0 30\n0 40\n");

    WorldBootstrapConfig bootstrap;
    bootstrap.map_name = "unit_map";
    bootstrap.map_root = root.string();
    IncomingCmdQueue inbound;
    OutboundStateQueue outbound;
    MvpOnlineBridge bridge(inbound, outbound, bootstrap);

    // A spawn handler makes the session's tank a known engine oid; the input must route to it.
    constexpr std::int32_t kEngineOid = 9100;
    bridge.SetSpawnHandler([](std::int32_t, const std::array<float, 3>&,
                              const std::array<float, 3>&) { return kEngineOid; });
    std::int32_t routed_oid = 0;
    std::int32_t routed_channel = -1;
    float routed_value = 0.0F;
    int route_calls = 0;
    bridge.SetInputHandler([&](std::int32_t oid, std::int32_t channel, float value) {
        routed_oid = oid;
        routed_channel = channel;
        routed_value = value;
        ++route_calls;
    });

    inbound.Push(ClientCommand{ClientCommandKind::ClientConnected, 1, 0, 0.0F, 0, 0, 0, "alice"});
    inbound.Push(ClientCommand{ClientCommandKind::WantUpdates, 1});
    inbound.Push(ClientCommand{ClientCommandKind::Reincarnate, 1, 0, 0.0F, 1, 0, 0, {}});  // team 1
    inbound.Push(ClientCommand{ClientCommandKind::Reincarnate, 1, 0, 0.0F, 0, 1, 0, {}});  // spawn
    // forward channel at half throttle, AFTER spawn.
    inbound.Push(ClientCommand{ClientCommandKind::ActionInput, 1, 1, 0.5F, 0, 0, 0, {}});
    bridge.Tick(123);

    EXPECT_EQ(route_calls, 1);
    EXPECT_EQ(routed_oid, kEngineOid);
    EXPECT_EQ(routed_channel, 1);
    EXPECT_FLOAT_EQ(routed_value, 0.5F);

    std::filesystem::remove_all(root);
}

TEST(MvpOnlineBridge, ActionInputBeforeSpawnIsNotRouted) {
    IncomingCmdQueue inbound;
    OutboundStateQueue outbound;
    MvpOnlineBridge bridge(inbound, outbound);

    int route_calls = 0;
    bridge.SetInputHandler([&](std::int32_t, std::int32_t, float) { ++route_calls; });

    inbound.Push(ClientCommand{ClientCommandKind::ClientConnected, 1, 0, 0.0F, 0, 0, 0, "alice"});
    inbound.Push(ClientCommand{ClientCommandKind::WantUpdates, 1});
    // Action arrives while the session is connected but has NOT spawned a tank.
    inbound.Push(ClientCommand{ClientCommandKind::ActionInput, 1, 1, 0.5F, 0, 0, 0, {}});
    bridge.Tick(123);

    EXPECT_EQ(route_calls, 0);
}

TEST(MvpOnlineBridge, TwoSpawnedSessionsReceiveUdpUpdatesForEachOther) {
    const auto root = TempMapRoot();
    const auto map_dir = root / "unit_map";
    std::filesystem::create_directories(map_dir);
    WriteTextFile(map_dir / "land", "2x2\n"
                                    "1000x800\n"
                                    "0 10\n"
                                    "0 20\n"
                                    "0 30\n"
                                    "0 40\n");

    WorldBootstrapConfig bootstrap;
    bootstrap.map_name = "unit_map";
    bootstrap.map_root = root.string();
    IncomingCmdQueue inbound;
    OutboundStateQueue outbound;
    MvpOnlineBridge bridge(inbound, outbound, bootstrap);

    inbound.Push(ClientCommand{ClientCommandKind::ClientConnected, 1, 0, 0.0F, 0, 0, 0, "alice"});
    inbound.Push(ClientCommand{ClientCommandKind::ClientConnected, 2, 0, 0.0F, 0, 0, 0, "bob"});
    inbound.Push(ClientCommand{ClientCommandKind::WantUpdates, 1});
    inbound.Push(ClientCommand{ClientCommandKind::WantUpdates, 2});
    // Each picks a team (team-switch) before spawning.
    inbound.Push(ClientCommand{ClientCommandKind::Reincarnate, 1, 0, 0.0F, 1, 0, 0, {}});
    inbound.Push(ClientCommand{ClientCommandKind::Reincarnate, 2, 0, 0.0F, 2, 0, 0, {}});
    inbound.Push(ClientCommand{ClientCommandKind::Reincarnate, 1, 0, 0.0F, 0, 1, 0, {}});
    inbound.Push(ClientCommand{ClientCommandKind::Reincarnate, 2, 0, 0.0F, 0, 2, 0, {}});

    bridge.Tick(123);
    const auto messages = outbound.DrainAll();

    std::array<bool, 3> saw_self{};
    std::array<bool, 3> saw_others{};
    for (const OutboundMessage& msg : messages) {
        // In-game updates are raw UDP datagrams ([opcode byte][body]); spawned players are not
        // sent the reliable TCP entry-map snapshot.
        if (msg.reliable || msg.bytes.empty() || msg.session_id >= saw_self.size()) {
            continue;
        }
        const auto idx = static_cast<std::size_t>(msg.session_id);
        if (msg.bytes.front() == static_cast<std::uint8_t>(Opcode::ViewUpdate)) {
            saw_self.at(idx) = true;
        } else if (msg.bytes.front() == static_cast<std::uint8_t>(Opcode::UpdateArray)) {
            saw_others.at(idx) = true;
        }
    }

    // Each spawned session gets a 0x0F self update AND a 0x0E others update (the other tank).
    EXPECT_TRUE(saw_self.at(1));
    EXPECT_TRUE(saw_self.at(2));
    EXPECT_TRUE(saw_others.at(1));
    EXPECT_TRUE(saw_others.at(2));
    std::filesystem::remove_all(root);
}

// A team switch must reach OTHER clients (UPDATE_STATS 0x1C broadcast) so their roster
// lists reflect the change; the requester gets that record on UDP from its Connection and
// only the REINCARNATE(code 17) confirm here, so it must NOT also get the broadcast.
TEST(MvpOnlineBridge, TeamSwitchBroadcastsUpdateStatsToOtherClients) {
    WorldBootstrapConfig bootstrap;
    bootstrap.map_name = "no_such_map_for_broadcast_test";  // fallback pads; no spawn here
    IncomingCmdQueue inbound;
    OutboundStateQueue outbound;
    MvpOnlineBridge bridge(inbound, outbound, bootstrap);

    inbound.Push(ClientCommand{ClientCommandKind::ClientConnected, 1, 0, 0.0F, 0, 0, 0, "alice"});
    inbound.Push(ClientCommand{ClientCommandKind::ClientConnected, 2, 0, 0.0F, 0, 0, 0, "bob"});
    inbound.Push(ClientCommand{ClientCommandKind::WantUpdates, 1});
    inbound.Push(ClientCommand{ClientCommandKind::WantUpdates, 2});
    bridge.Tick(1);
    (void)outbound.DrainAll();  // discard join/roster/snapshot bring-up

    // Session 1 switches to team 2.
    inbound.Push(ClientCommand{ClientCommandKind::Reincarnate, 1, 0, 0.0F, 2, 0, 0, {}});
    bridge.Tick(2);
    const auto messages = outbound.DrainAll();

    bool peer_got_update_stats = false;
    bool requester_got_update_stats = false;
    for (const OutboundMessage& msg : messages) {
        const Frame frame = FirstFrame(msg.bytes);
        if (frame.opcode != static_cast<std::uint8_t>(Opcode::UpdateStats)) {
            continue;
        }
        if (msg.session_id == 2u) {
            BitReader r(frame.body.data(), frame.body.size());
            EXPECT_EQ(r.ReadI32().value(), 1);   // switcher's player_id
            EXPECT_EQ(r.ReadI32().value(), 6);   // record kind
            EXPECT_EQ(r.ReadU16().value(), 2u);  // new team
            peer_got_update_stats = true;
        }
        if (msg.session_id == 1u) {
            requester_got_update_stats = true;
        }
    }
    EXPECT_TRUE(peer_got_update_stats);
    EXPECT_FALSE(requester_got_update_stats);
}

// M6.1: when a world provider is set (the engine read), its dynamic entities are sent
// ALONGSIDE the map fixtures (pads/bases from the parsed state), not instead of them —
// so the client both sees the engine world AND can open the entry map / pick a pad.
TEST(MvpOnlineBridge, WorldProviderAddsEngineEntitiesToMapFixtures) {
    WorldBootstrapConfig bootstrap;
    bootstrap.map_name = "no_such_map_for_provider_test";  // no state file -> 2 fallback pads
    IncomingCmdQueue inbound;
    OutboundStateQueue outbound;
    MvpOnlineBridge bridge(inbound, outbound, bootstrap);

    // One authoritative engine tank, in addition to the map's repair pads.
    bridge.SetWorldProvider([] {
        MvpEntitySnapshot tank;
        tank.net_id = 99;
        tank.unit_type = 1;
        tank.team = 2;
        tank.is_manned = true;
        tank.pos = {2437.0F, 3269.0F, -180.0F};
        return std::vector<MvpEntitySnapshot>{tank};
    });

    inbound.Push(ClientCommand{ClientCommandKind::ClientConnected, 1, 0, 0.0F, 0, 0, 0, "alice"});
    inbound.Push(ClientCommand{ClientCommandKind::WantUpdates, 1});
    bridge.Tick(7);

    const auto snapshot = FirstViewUpdateForSession(outbound.DrainAll(), 1);
    ASSERT_TRUE(snapshot.has_value());
    const auto entities = DecodeEntitiesInViewUpdate(*snapshot);
    // 2 fallback repair pads (the map fixtures / spawn points) + the 1 engine tank.
    EXPECT_EQ(entities.size(), 3U);
    const bool has_engine_tank =
        std::any_of(entities.begin(), entities.end(),
                    [](const DecodedEntity& e) { return e.net_id == 99 && e.unit_type == 1U; });
    EXPECT_TRUE(has_engine_tank);
    constexpr std::uint32_t kRepairPadType = 27;
    const int pads = CountEntitiesMatching(entities, kRepairPadType, 1U, false) +
                     CountEntitiesMatching(entities, kRepairPadType, 2U, false);
    EXPECT_EQ(pads, 2);
}

// --- UDP reliable-stream handshake (server->client) ------------------------

TEST(UdpHandshake, AckIsOpcodeSubcmdAndTicksBigEndian) {
    const auto bytes = BuildUdpHandshakeAck(7);
    ASSERT_EQ(bytes.size(), 6U);  // [0x02][subcmd 0][i32 ticks]
    EXPECT_EQ(bytes.at(0), 0x02U);
    EXPECT_EQ(bytes.at(1), 0x00U);
    EXPECT_EQ(bytes.at(2), 0U);
    EXPECT_EQ(bytes.at(3), 0U);
    EXPECT_EQ(bytes.at(4), 0U);
    EXPECT_EQ(bytes.at(5), 7U);  // big-endian low byte
}

TEST(UdpHandshake, StreamUnpauseCarriesStreamIdAndSeq) {
    const auto bytes = BuildUdpStreamUnpause(3);
    ASSERT_EQ(bytes.size(), 4U);  // [0x04][byte stream_id][u16 seq]
    EXPECT_EQ(bytes.at(0), 0x04U);
    EXPECT_EQ(bytes.at(1), 3U);
    EXPECT_EQ(bytes.at(2), 0U);
    EXPECT_EQ(bytes.at(3), 1U);  // seq = 1, big-endian
}

TEST(UdpHandshake, PongEchoesTimestamp) {
    const auto bytes = BuildUdpPong(0x12345678);
    ASSERT_EQ(bytes.size(), 5U);  // [0x0C][i32]
    EXPECT_EQ(bytes.at(0), 0x0CU);
    EXPECT_EQ(bytes.at(1), 0x12U);
    EXPECT_EQ(bytes.at(2), 0x34U);
    EXPECT_EQ(bytes.at(3), 0x56U);
    EXPECT_EQ(bytes.at(4), 0x78U);
}

TEST(UdpHandshake, StreamDefsDefineFourGameplayStreams) {
    const auto bytes = BuildUdpStreamDefs(0, 42);
    ASSERT_FALSE(bytes.empty());
    EXPECT_EQ(bytes.at(0), 0x03U);  // D_HANDSHAKE opcode
    wfh::proto::BitReader r(bytes.data() + 1, bytes.size() - 1);
    EXPECT_EQ(r.ReadI32().value_or(-1), 0);   // ticks
    EXPECT_EQ(r.ReadI32().value_or(-1), 42);  // player_id
    EXPECT_EQ(r.ReadI32().value_or(-1), 4);   // def count
    const std::array<std::string_view, 4> names = {"Unreliable", "Reliable", "Stream 2",
                                                   "Game Data"};
    for (std::int32_t i = 0; i < 4; ++i) {
        EXPECT_EQ(r.ReadString(64).value_or(""), names.at(static_cast<std::size_t>(i)));
        EXPECT_EQ(r.ReadI32().value_or(-1), 1);  // id count
        EXPECT_EQ(r.ReadI32().value_or(-1), i);  // stream id
    }
    EXPECT_EQ(r.ReadI32().value_or(-1), 4);  // config count
    for (std::int32_t i = 0; i < 4; ++i) {
        EXPECT_EQ(r.ReadI32().value_or(-1), i);  // stream id
        EXPECT_EQ(r.ReadI32().value_or(-1), 1);  // priority
    }
    EXPECT_FALSE(r.Failed());
}

TEST(Connection, VersionMismatchDrops) {
    ServerConfig cfg;
    IncomingCmdQueue inbound;
    Connection conn(1, cfg, "Key1234", inbound);
    (void)conn.OnAccept();
    const auto bad = MakeFrame(Opcode::Hello, [](wfh::proto::BitWriter& w) {
        w.WriteByte(0x00);
        w.WriteI32(0x1234);  // wrong version
    });
    auto step = conn.OnTcpData(bad.data(), bad.size());
    EXPECT_TRUE(step.close);
    EXPECT_EQ(conn.State(), ConnState::Closed);
}

TEST(Connection, OutOfOrderLoginBeforeKeyEchoDrops) {
    ServerConfig cfg;
    IncomingCmdQueue inbound;
    Connection conn(1, cfg, "Key1234", inbound);
    (void)conn.OnAccept();
    // LOGIN before the UDP link is established is out of order -> drop.
    const auto login =
        MakeFrame(Opcode::Login, [](wfh::proto::BitWriter& w) { w.WriteString("alice"); });
    auto step = conn.OnTcpData(login.data(), login.size());
    EXPECT_TRUE(step.close);
}

TEST(Connection, UnknownOpcodeDrops) {
    ServerConfig cfg;
    IncomingCmdQueue inbound;
    Connection conn(1, cfg, "Key1234", inbound);
    (void)conn.OnAccept();
    // 0x77 is not a known opcode.
    const auto junk = wfh::proto::EncodeTcpFrame(0x77, {0x01, 0x02}).value();
    auto step = conn.OnTcpData(junk.data(), junk.size());
    EXPECT_TRUE(step.close);
}

TEST(Connection, GarbageBytesDoNotCrashAndDrop) {
    ServerConfig cfg;
    IncomingCmdQueue inbound;
    Connection conn(1, cfg, "Key1234", inbound);
    (void)conn.OnAccept();
    // A length prefix below the 3-byte minimum is rejected by the accumulator.
    const std::vector<std::uint8_t> garbage = {0x00, 0x01, 0xFF, 0xFF};
    auto step = conn.OnTcpData(garbage.data(), garbage.size());
    EXPECT_TRUE(step.close);
}

TEST(Connection, WrongKeyEchoDoesNotLink) {
    ServerConfig cfg;
    IncomingCmdQueue inbound;
    Connection conn(1, cfg, "Key1234", inbound);
    (void)conn.OnAccept();
    wfh::proto::BitWriter echo;
    echo.WriteByte(0x01);
    echo.WriteString("WrongKey");
    const auto body = echo.Bytes();
    auto step =
        conn.OnUdpPacket(static_cast<std::uint8_t>(Opcode::Hello), body.data(), body.size());
    EXPECT_TRUE(step.tcp_out.empty());
    EXPECT_FALSE(conn.UdpLinked());
    EXPECT_EQ(conn.State(), ConnState::AwaitingKeyEcho);
}

// --- Queue boundary --------------------------------------------------------

TEST(ConcurrentQueue, ProducerConsumerThreadSafe) {
    IncomingCmdQueue q;
    constexpr int kN = 1000;
    std::thread producer([&] {
        for (int i = 0; i < kN; ++i) {
            q.Push(ClientCommand{ClientCommandKind::ActionInput, static_cast<std::uint64_t>(i)});
        }
    });
    int seen = 0;
    while (seen < kN) {
        auto items = q.DrainAll();
        seen += static_cast<int>(items.size());
        if (items.empty()) {
            std::this_thread::yield();
        }
    }
    producer.join();
    EXPECT_EQ(seen, kN);
    EXPECT_TRUE(q.Empty());
}

// --- Runtime owner ---------------------------------------------------------

TEST(ServerRuntime, StartsAndStopsAcceptorOnEphemeralPort) {
    ServerConfig cfg;
    cfg.bind_port = 0;

    ServerRuntime runtime;
    ASSERT_TRUE(runtime.Start(cfg));
    EXPECT_TRUE(runtime.Running());
    EXPECT_NE(runtime.BoundPort(), 0);

    runtime.Stop();
    EXPECT_FALSE(runtime.Running());
}

// --- Acceptor loopback smoke ----------------------------------------------

// Bind on an ephemeral port, connect a raw TCP client, and assert the server sends
// the initial HELLO burst (UDP_CONFIG/VERSION/SESSION_KEY) on accept.
TEST(Acceptor, LoopbackAcceptSendsHelloBurst) {
    WSADATA wsa{};
    ASSERT_EQ(WSAStartup(MAKEWORD(2, 2), &wsa), 0);

    ServerConfig cfg;
    cfg.bind_port = 0;  // ephemeral
    IncomingCmdQueue inbound;
    OutboundStateQueue outbound;
    Acceptor acceptor(cfg, inbound, outbound);
    ASSERT_TRUE(acceptor.Start());
    const std::uint16_t port = acceptor.BoundPort();
    ASSERT_NE(port, 0);

    SOCKET cli = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    ASSERT_NE(cli, INVALID_SOCKET);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    ASSERT_EQ(connect(cli, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)), 0);

    // Read the HELLO burst the server sends on accept (with a short timeout).
    DWORD tmo = 2000;
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    setsockopt(cli, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&tmo), sizeof(tmo));
    std::array<std::uint8_t, 512> buf{};
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    const int n = recv(cli, reinterpret_cast<char*>(buf.data()), static_cast<int>(buf.size()), 0);
    ASSERT_GT(n, 0);

    // First frame must be HELLO (0x13). Decode and confirm.
    TcpFrameAccumulator acc;
    ASSERT_TRUE(acc.Feed(buf.data(), static_cast<std::size_t>(n)));
    auto frame = acc.Next();
    ASSERT_TRUE(frame.has_value());
    EXPECT_EQ(frame->opcode, static_cast<std::uint8_t>(Opcode::Hello));

    closesocket(cli);
    acceptor.Stop();
    WSACleanup();
}

TEST(Acceptor, TcpDisconnectEnqueuesDisconnectedCommand) {
    WSADATA wsa{};
    ASSERT_EQ(WSAStartup(MAKEWORD(2, 2), &wsa), 0);

    ServerConfig cfg;
    cfg.bind_port = 0;  // ephemeral
    IncomingCmdQueue inbound;
    OutboundStateQueue outbound;
    Acceptor acceptor(cfg, inbound, outbound);
    ASSERT_TRUE(acceptor.Start());

    SOCKET cli = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    ASSERT_NE(cli, INVALID_SOCKET);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(acceptor.BoundPort());
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    ASSERT_EQ(connect(cli, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)), 0);

    closesocket(cli);

    bool saw_disconnect = false;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    while (!saw_disconnect && std::chrono::steady_clock::now() < deadline) {
        for (const auto& cmd : inbound.DrainAll()) {
            saw_disconnect = saw_disconnect || cmd.kind == ClientCommandKind::Disconnected;
        }
        if (!saw_disconnect) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    }

    acceptor.Stop();
    WSACleanup();
    EXPECT_TRUE(saw_disconnect);
}

TEST(Acceptor, RawUdpHelloKeyEchoLinksSession) {
    WSADATA wsa{};
    ASSERT_EQ(WSAStartup(MAKEWORD(2, 2), &wsa), 0);

    ServerConfig cfg;
    cfg.bind_port = 0;  // ephemeral
    IncomingCmdQueue inbound;
    OutboundStateQueue outbound;
    Acceptor acceptor(cfg, inbound, outbound);
    ASSERT_TRUE(acceptor.Start());
    const std::uint16_t port = acceptor.BoundPort();
    ASSERT_NE(port, 0);

    SOCKET tcp = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    ASSERT_NE(tcp, INVALID_SOCKET);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    ASSERT_EQ(connect(tcp, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)), 0);

    DWORD tmo = 2000;
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    setsockopt(tcp, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&tmo), sizeof(tmo));
    std::array<std::uint8_t, 512> buf{};
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    const int hello_count =
        recv(tcp, reinterpret_cast<char*>(buf.data()), static_cast<int>(buf.size()), 0);
    ASSERT_GT(hello_count, 0);
    const std::string key = SessionKeyFromHelloBurst({buf.begin(), buf.begin() + hello_count});
    ASSERT_FALSE(key.empty());

    SOCKET udp = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    ASSERT_NE(udp, INVALID_SOCKET);
    const auto echo = MakeRawUdpHelloKeyEcho(key);
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    ASSERT_EQ(sendto(udp, reinterpret_cast<const char*>(echo.data()), static_cast<int>(echo.size()),
                     0, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)),
              static_cast<int>(echo.size()));

    const int identified_count =
        recv(tcp, reinterpret_cast<char*>(buf.data()), static_cast<int>(buf.size()), 0);
    ASSERT_GT(identified_count, 0);
    const Frame identified = FirstFrame({buf.begin(), buf.begin() + identified_count});
    EXPECT_EQ(identified.opcode, static_cast<std::uint8_t>(Opcode::IdentifiedUdp));

    closesocket(udp);
    closesocket(tcp);
    acceptor.Stop();
    WSACleanup();
}

TEST(Acceptor, LinkedRawUdpReincarnateEnqueuesCommand) {
    WSADATA wsa{};
    ASSERT_EQ(WSAStartup(MAKEWORD(2, 2), &wsa), 0);

    ServerConfig cfg;
    cfg.bind_port = 0;  // ephemeral
    IncomingCmdQueue inbound;
    OutboundStateQueue outbound;
    Acceptor acceptor(cfg, inbound, outbound);
    ASSERT_TRUE(acceptor.Start());
    const std::uint16_t port = acceptor.BoundPort();
    ASSERT_NE(port, 0);

    SOCKET tcp = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    ASSERT_NE(tcp, INVALID_SOCKET);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    ASSERT_EQ(connect(tcp, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)), 0);

    DWORD tmo = 2000;
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    setsockopt(tcp, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&tmo), sizeof(tmo));
    std::array<std::uint8_t, 4096> buf{};
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    const int hello_count =
        recv(tcp, reinterpret_cast<char*>(buf.data()), static_cast<int>(buf.size()), 0);
    ASSERT_GT(hello_count, 0);
    const std::string key = SessionKeyFromHelloBurst({buf.begin(), buf.begin() + hello_count});
    ASSERT_FALSE(key.empty());

    SOCKET udp = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    ASSERT_NE(udp, INVALID_SOCKET);
    const auto echo = MakeRawUdpHelloKeyEcho(key);
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    ASSERT_EQ(sendto(udp, reinterpret_cast<const char*>(echo.data()), static_cast<int>(echo.size()),
                     0, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)),
              static_cast<int>(echo.size()));

    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    const int identified_count =
        recv(tcp, reinterpret_cast<char*>(buf.data()), static_cast<int>(buf.size()), 0);
    ASSERT_GT(identified_count, 0);

    const auto login = MakePythonStyleLoginFrame("codex_a", "pass_local");
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    ASSERT_EQ(
        send(tcp, reinterpret_cast<const char*>(login.data()), static_cast<int>(login.size()), 0),
        static_cast<int>(login.size()));

    auto wait_for_command = [&](ClientCommandKind kind) -> std::optional<ClientCommand> {
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
        while (std::chrono::steady_clock::now() < deadline) {
            for (const auto& cmd : inbound.DrainAll()) {
                if (cmd.kind == kind) {
                    return cmd;
                }
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        return std::nullopt;
    };
    ASSERT_TRUE(wait_for_command(ClientCommandKind::ClientConnected).has_value());

    const auto want_updates = MakeFrame(Opcode::WantUpdates, [](wfh::proto::BitWriter&) {});
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    ASSERT_EQ(send(tcp, reinterpret_cast<const char*>(want_updates.data()),
                   static_cast<int>(want_updates.size()), 0),
              static_cast<int>(want_updates.size()));
    ASSERT_TRUE(wait_for_command(ClientCommandKind::WantUpdates).has_value());

    std::vector<std::uint8_t> spawn{static_cast<std::uint8_t>(Opcode::Reincarnate)};
    const auto body = MakeSpawnRequestBody(0x1234, 5, 99);
    spawn.insert(spawn.end(), body.begin(), body.end());
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    ASSERT_EQ(sendto(udp, reinterpret_cast<const char*>(spawn.data()),
                     static_cast<int>(spawn.size()), 0, reinterpret_cast<sockaddr*>(&addr),
                     sizeof(addr)),
              static_cast<int>(spawn.size()));

    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    setsockopt(udp, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&tmo), sizeof(tmo));
    sockaddr_in ack_from{};
    int ack_from_len = sizeof(ack_from);
    std::array<std::uint8_t, 64> ack_buf{};
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    const int ack_count =
        recvfrom(udp, reinterpret_cast<char*>(ack_buf.data()), static_cast<int>(ack_buf.size()), 0,
                 reinterpret_cast<sockaddr*>(&ack_from), &ack_from_len);
    ASSERT_GT(ack_count, 0);
    ExpectUdpAck(ack_buf.data(), static_cast<std::size_t>(ack_count), 0x1234,
                 static_cast<std::uint8_t>(Opcode::Reincarnate));

    const auto cmd = wait_for_command(ClientCommandKind::Reincarnate);
    ASSERT_TRUE(cmd.has_value());
    EXPECT_EQ(cmd->unit_id, 5);
    EXPECT_EQ(cmd->pad_id, 99);

    closesocket(udp);
    closesocket(tcp);
    acceptor.Stop();
    WSACleanup();
}

// --- Dev console (live engine poke socket) ---------------------------------

auto AddrOf(const void* ptr) -> std::uint32_t {
    // The DLL + tests are 32-bit, so a pointer fits in a u32 dev-console address.
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    return static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(ptr));
}

TEST(DevConsole, ParsesPeek) {
    const auto cmd = ParseDevCommand("peek 0x4f9e20 32");
    EXPECT_EQ(cmd.kind, DevCmdKind::Peek);
    EXPECT_EQ(cmd.addr, 0x004f9e20U);
    EXPECT_EQ(cmd.len, 32U);
    EXPECT_TRUE(cmd.error.empty());
}

TEST(DevConsole, ParsesPokeBytes) {
    const auto cmd = ParseDevCommand("poke 600000 deadBEef");
    EXPECT_EQ(cmd.kind, DevCmdKind::Poke);
    EXPECT_EQ(cmd.addr, 0x00600000U);
    EXPECT_EQ(cmd.bytes, (std::vector<std::uint8_t>{0xDE, 0xAD, 0xBE, 0xEF}));
}

TEST(DevConsole, ParsesHelpAndRejectsGarbage) {
    EXPECT_EQ(ParseDevCommand("help").kind, DevCmdKind::Help);
    EXPECT_EQ(ParseDevCommand("?").kind, DevCmdKind::Help);
    const auto bad = ParseDevCommand("frobnicate 1 2");
    EXPECT_EQ(bad.kind, DevCmdKind::Unknown);
    EXPECT_FALSE(bad.error.empty());
    // Malformed peek (missing len) is an error, not a silent accept.
    EXPECT_FALSE(ParseDevCommand("peek 0x1000").error.empty());
}

TEST(DevConsole, ParsesCall) {
    const auto cmd = ParseDevCommand("call 0x4f9e20 thiscall 0383dd58 09271c48");
    EXPECT_EQ(cmd.kind, DevCmdKind::Call);
    EXPECT_EQ(cmd.addr, 0x004f9e20U);
    EXPECT_EQ(cmd.conv, "thiscall");
    EXPECT_EQ(cmd.args, (std::vector<std::uint32_t>{0x0383dd58U, 0x09271c48U}));
    EXPECT_TRUE(cmd.error.empty());
    EXPECT_FALSE(ParseDevCommand("call 0x1000 bogusconv").error.empty());  // bad convention
    EXPECT_FALSE(ParseDevCommand("call 0x1000").error.empty());            // missing convention
    EXPECT_EQ(ParseDevCommand("bt").kind, DevCmdKind::Backtrace);
}

TEST(DevConsole, HexHelpers) {
    std::uint32_t value = 0;
    EXPECT_TRUE(ParseHexU32("0x4F9e20", value));
    EXPECT_EQ(value, 0x004f9e20U);
    EXPECT_TRUE(ParseHexU32("abc", value));
    EXPECT_EQ(value, 0x00000abcU);
    EXPECT_FALSE(ParseHexU32("xyz", value));
    EXPECT_FALSE(ParseHexU32("", value));
    EXPECT_FALSE(ParseHexU32("123456789", value));  // > 8 hex digits overflows u32

    std::vector<std::uint8_t> bytes;
    EXPECT_TRUE(ParseHexBytes("deadbeef", bytes));
    EXPECT_EQ(bytes, (std::vector<std::uint8_t>{0xDE, 0xAD, 0xBE, 0xEF}));
    EXPECT_FALSE(ParseHexBytes("abc", bytes));  // odd length
    EXPECT_FALSE(ParseHexBytes("gg", bytes));   // non-hex
}

TEST(DevConsole, SafeReadRoundTripsAndFaultsSafely) {
    const std::array<std::uint8_t, 4> src{0x11, 0x22, 0x33, 0x44};
    std::vector<std::uint8_t> out;
    EXPECT_TRUE(SafeReadMemory(AddrOf(src.data()), src.size(), out));
    EXPECT_EQ(out, (std::vector<std::uint8_t>{0x11, 0x22, 0x33, 0x44}));

    // A null read must be caught by the SEH guard, not crash the process.
    out.assign(99, 0xCC);
    EXPECT_FALSE(SafeReadMemory(0, 8, out));
    EXPECT_TRUE(out.empty());
}

TEST(DevConsole, SafeWriteUpdatesAWritableBuffer) {
    std::array<std::uint8_t, 4> dst{0, 0, 0, 0};
    EXPECT_TRUE(SafeWriteMemory(AddrOf(dst.data()), {0xAA, 0xBB, 0xCC, 0xDD}));
    EXPECT_EQ(dst, (std::array<std::uint8_t, 4>{0xAA, 0xBB, 0xCC, 0xDD}));
}

TEST(DevConsole, ExecutePeekDumpsBytesAndHelpLists) {
    const std::array<std::uint8_t, 4> src{0x11, 0x22, 0x33, 0x44};
    DevCommand peek;
    peek.kind = DevCmdKind::Peek;
    peek.addr = AddrOf(src.data());
    peek.len = 4;
    const std::string dump = ExecuteDevCommand(peek);
    EXPECT_NE(dump.find("11 22 33 44"), std::string::npos);

    DevCommand help;
    help.kind = DevCmdKind::Help;
    EXPECT_NE(ExecuteDevCommand(help).find("peek"), std::string::npos);
}

// ===========================================================================
// ACTION input decode (M6.4): the inbound 0x0A/0x09 control-channel decoder.
// Vectors are REAL bytes from tools/captures/action_packets_2026-06-17.txt (the
// `body` is everything AFTER the opcode byte). The wire format is bit-exact and
// was cross-validated against all 826 captures (channel idx 16b; analog 16b over
// [high=1.0, low=-1.0]; digital 1b for ch 4 and ch>=8).
// ===========================================================================

TEST(ActionInput, ClassifiesDigitalVsAnalogChannels) {
    for (const std::int32_t analog : {0, 1, 2, 3, 5, 6, 7}) {
        EXPECT_FALSE(IsDigitalActionChannel(analog)) << "channel " << analog;
    }
    for (const std::int32_t digital : {4, 8, 9, 15, 21}) {
        EXPECT_TRUE(IsDigitalActionChannel(digital)) << "channel " << digital;
    }
}

TEST(ActionInput, DecodesDigitalButtonReleaseFromCapture) {
    // 0a 01 00020bd7 00000000  | ch8(16b)=0x0008 value(1b)=0  -> button 8 released
    const std::vector<std::uint8_t> body{0x01, 0x00, 0x02, 0x0b, 0xd7, 0x00,
                                         0x00, 0x00, 0x00, 0x00, 0x08, 0x00};
    const DecodedActions out = DecodeActionUpdate(body.data(), body.size());
    ASSERT_TRUE(out.ok);
    EXPECT_EQ(out.timestamp, 134103);
    ASSERT_EQ(out.changes.size(), 1U);
    EXPECT_EQ(out.changes.at(0).channel, 8);
    EXPECT_FLOAT_EQ(out.changes.at(0).value, 0.0F);
}

TEST(ActionInput, DecodesDigitalButtonPressFromCapture) {
    // 0a 01 0002151f 00000000  | ch8 value(1b)=1 (high bit of 0x80) -> button 8 pressed
    const std::vector<std::uint8_t> body{0x01, 0x00, 0x02, 0x15, 0x1f, 0x00,
                                         0x00, 0x00, 0x00, 0x00, 0x08, 0x80};
    const DecodedActions out = DecodeActionUpdate(body.data(), body.size());
    ASSERT_TRUE(out.ok);
    EXPECT_EQ(out.timestamp, 136479);
    ASSERT_EQ(out.changes.size(), 1U);
    EXPECT_EQ(out.changes.at(0).channel, 8);
    EXPECT_FLOAT_EQ(out.changes.at(0).value, 1.0F);
}

TEST(ActionInput, DecodesAnalogTurnNearZeroFromCapture) {
    // 0a 01 00005083 00000000 | ch6(turn) level 0x8587 -> ~ -0.043
    const std::vector<std::uint8_t> body{0x01, 0x00, 0x00, 0x50, 0x83, 0x00, 0x00,
                                         0x00, 0x00, 0x00, 0x06, 0x85, 0x87};
    const DecodedActions out = DecodeActionUpdate(body.data(), body.size());
    ASSERT_TRUE(out.ok);
    ASSERT_EQ(out.changes.size(), 1U);
    EXPECT_EQ(out.changes.at(0).channel, 6);
    EXPECT_NEAR(out.changes.at(0).value, -0.0432F, 0.005F);
}

TEST(ActionInput, DecodesAnalogStrafeHalfBothSignsFromCaptures) {
    // ch3(strafe) level 0x4000 -> +0.5
    const std::vector<std::uint8_t> pos{0x01, 0x00, 0x00, 0x6a, 0x46, 0x00, 0x00,
                                        0x00, 0x00, 0x00, 0x03, 0x40, 0x00};
    const DecodedActions a = DecodeActionUpdate(pos.data(), pos.size());
    ASSERT_TRUE(a.ok);
    ASSERT_EQ(a.changes.size(), 1U);
    EXPECT_EQ(a.changes.at(0).channel, 3);
    EXPECT_NEAR(a.changes.at(0).value, 0.5F, 0.005F);

    // ch3 level 0xbfff -> -0.5
    const std::vector<std::uint8_t> neg{0x01, 0x00, 0x00, 0x91, 0x62, 0x00, 0x00,
                                        0x00, 0x00, 0x00, 0x03, 0xbf, 0xff};
    const DecodedActions b = DecodeActionUpdate(neg.data(), neg.size());
    ASSERT_TRUE(b.ok);
    ASSERT_EQ(b.changes.size(), 1U);
    EXPECT_EQ(b.changes.at(0).channel, 3);
    EXPECT_NEAR(b.changes.at(0).value, -0.5F, 0.005F);
}

TEST(ActionInput, DecodesMultiChangeUpdateFromCapture) {
    // 0a 02 00004ae7 00000000 | ch1 level 0x70a2 (~0.120) | ch6 level 0x801f (~0)
    const std::vector<std::uint8_t> body{0x02, 0x00, 0x00, 0x4a, 0xe7, 0x00, 0x00, 0x00, 0x00,
                                         0x00, 0x01, 0x70, 0xa2, 0x00, 0x06, 0x80, 0x1f};
    const DecodedActions out = DecodeActionUpdate(body.data(), body.size());
    ASSERT_TRUE(out.ok);
    EXPECT_EQ(out.timestamp, 19175);
    ASSERT_EQ(out.changes.size(), 2U);
    EXPECT_EQ(out.changes.at(0).channel, 1);
    EXPECT_NEAR(out.changes.at(0).value, 0.120F, 0.005F);
    EXPECT_EQ(out.changes.at(1).channel, 6);
    EXPECT_NEAR(out.changes.at(1).value, 0.0F, 0.01F);
}

TEST(ActionInput, DecodesActionDumpAllChannelsFromCapture) {
    // 09 00004832 00000000 | values of channels 1..21 (positional, no index)
    const std::vector<std::uint8_t> body{0x00, 0x00, 0x48, 0x32, 0x00, 0x00, 0x00, 0x00,
                                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0xcd,
                                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    const DecodedActions out = DecodeActionDump(body.data(), body.size());
    ASSERT_TRUE(out.ok);
    EXPECT_EQ(out.timestamp, 18482);
    ASSERT_EQ(out.changes.size(), 21U);
    // Positional: changes[i] is channel i+1, all in 1..21; analog values stay in [-1,1].
    for (std::size_t i = 0; i < out.changes.size(); ++i) {
        EXPECT_EQ(out.changes.at(i).channel, static_cast<std::int32_t>(i) + 1);
        if (!IsDigitalActionChannel(out.changes.at(i).channel)) {
            EXPECT_GE(out.changes.at(i).value, -1.0F);
            EXPECT_LE(out.changes.at(i).value, 1.0F);
        }
    }
}

// Deterministic bit-mechanics check (incl. cross-byte packing): build a body with the
// exact wire encoding, decode it, and assert the channels + values round-trip. This is
// independent of any single capture and covers the full analog quantize<->dequantize loop.
TEST(ActionInput, RoundTripsAnalogAndDigitalChannels) {
    const auto quantize = [](float value) -> std::uint32_t {
        if (value == 0.0F) {
            return 0U;
        }
        const auto denom = static_cast<float>((1U << kActionAnalogValueBits) - 2U);
        const float clamped =
            std::clamp(value, kActionAnalogHigh - kActionAnalogRange, kActionAnalogHigh);
        return static_cast<std::uint32_t>(((kActionAnalogHigh - clamped) * denom) /
                                          kActionAnalogRange) +
               1U;
    };
    struct Ch {
        std::int32_t channel;
        float value;
    };
    const std::array<Ch, 5> want{{{1, 0.75F}, {4, 1.0F}, {6, -0.25F}, {8, 0.0F}, {3, -1.0F}}};

    wfh::proto::BitWriter writer;
    writer.WriteByte(static_cast<std::uint8_t>(want.size()));  // count
    writer.WriteI32(424242);                                   // timestamp
    writer.WriteI32(0);                                        // seq
    for (const Ch& entry : want) {
        writer.WriteBits(static_cast<std::uint32_t>(entry.channel), kActionChannelIndexBits);
        if (IsDigitalActionChannel(entry.channel)) {
            writer.WriteBits(entry.value != 0.0F ? 1U : 0U, kActionDigitalValueBits);
        } else {
            writer.WriteBits(quantize(entry.value), kActionAnalogValueBits);
        }
    }
    const std::vector<std::uint8_t> body = writer.Bytes();

    const DecodedActions out = DecodeActionUpdate(body.data(), body.size());
    ASSERT_TRUE(out.ok);
    EXPECT_EQ(out.timestamp, 424242);
    ASSERT_EQ(out.changes.size(), want.size());
    for (std::size_t i = 0; i < want.size(); ++i) {
        EXPECT_EQ(out.changes.at(i).channel, want.at(i).channel);
        if (IsDigitalActionChannel(want.at(i).channel)) {
            EXPECT_FLOAT_EQ(out.changes.at(i).value, want.at(i).value);
        } else {
            EXPECT_NEAR(out.changes.at(i).value, want.at(i).value, 0.001F);
        }
    }
}

TEST(ActionInput, RejectsTruncatedAndEmptyBodies) {
    // count=1 but no change bytes -> fail closed.
    const std::vector<std::uint8_t> truncated{0x01, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00};
    EXPECT_FALSE(DecodeActionUpdate(truncated.data(), truncated.size()).ok);
    // Empty body.
    EXPECT_FALSE(DecodeActionUpdate(nullptr, 0).ok);
    EXPECT_FALSE(DecodeActionDump(nullptr, 0).ok);
    // A dump that ends before all 21 channels are read.
    const std::vector<std::uint8_t> short_dump{0x00, 0x00, 0x48, 0x32, 0x00, 0x00, 0x00, 0x00};
    EXPECT_FALSE(DecodeActionDump(short_dump.data(), short_dump.size()).ok);
}

}  // namespace
