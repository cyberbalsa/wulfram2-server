// NOLINTBEGIN(portability-avoid-pragma-once)
// pragma once is the project-wide include-guard convention; intentional.
#pragma once
// NOLINTEND(portability-avoid-pragma-once)

#include <cstdint>

namespace wfh::proto {

// Wulfram II packet opcodes (the first body byte of every frame). Names and values
// are from the M5.0 RE / the proven reference flow. We list the ones the server
// must SEND or ACCEPT; the dispatch is opcode-byte indexed (the debug "MSGTYPE"
// string in the engine's Net_SendStart is never serialized).
enum class Opcode : std::uint8_t {
    DebugString = 0x00,     // client->server: UDP debug text (log/no-op)
    Ack = 0x02,             // ack (subcmd-multiplexed): handshake ack / packet ack
    DHandshake = 0x03,      // client->server: UDP reliable-stream handshake (D_HANDSHAKE)
    HelloThere = 0x08,      // client->server: UDP "Hello There" hello
    ActionDump = 0x09,      // client->server: action snapshot dump
    ActionUpdate = 0x0A,    // client->server: per-tick analog control inputs
    ClientPing = 0x0B,      // client->server: UDP ping (server replies 0x0C pong)
    UdpPing = 0x0C,         // ping/pong timestamp packet
    UpdateArray = 0x0E,     // entity move/state array (others)
    ViewUpdate = 0x0F,      // self/view update + full snapshot
    Hello = 0x13,           // handshake, subtype-multiplexed (0..3)
    DeleteObject = 0x15,    // entity destroy
    WorldStats = 0x16,      // map name/id
    Player = 0x17,          // player record / id assignment
    TankSpawn = 0x18,       // entity create/spawn
    AddToRoster = 0x1A,     // roster add
    UpdateStats = 0x1C,     // server->client: player stat/team record (team-switch broadcast)
    BirthNotice = 0x1E,     // spawn broadcast
    ChatComm = 0x20,        // client->server: chat / comm request
    Login = 0x21,           // client->server: username / password
    LoginStatus = 0x22,     // server->client: login status code
    Motd = 0x23,            // message of the day
    Behavior = 0x24,        // physics tunables
    Reincarnate = 0x25,     // respawn request/grant
    TeamInfo = 0x28,        // team names/metadata
    DropRequest = 0x2B,     // client->server: cargo/flag drop request
    GameClock = 0x2F,       // ticks + phase/length
    Translation = 0x32,     // float quantization table
    TranslationAck = 0x33,  // client->server: ack the translation table
    Viewpoint = 0x35,       // client->server: viewpoint/camera info
    WantUpdates = 0x39,     // client->server: ready for updates
    BeaconRequest = 0x3A,   // client->server: beacon placement request
    IdentifiedUdp = 0x4D,   // server->client: UDP endpoint linked to TCP session
    Bps = 0x4E,             // client->server: bandwidth/rate request; server echoes approval
    Kudos = 0x4F,           // client->server: kudos/commend
    Generic = 0x54,         // client->server: misc/voice toggles; benign for MVP
};

// True if `opcode` is one of the known protocol opcodes above. Anything else from a
// client is rejected (drop the connection) before it can reach the engine.
[[nodiscard]] auto IsKnownOpcode(std::uint8_t opcode) -> bool;

}  // namespace wfh::proto
