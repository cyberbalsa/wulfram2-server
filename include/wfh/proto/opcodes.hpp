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
    HelloThere = 0x08,      // client->server: UDP "Hello There" hello
    UpdateArray = 0x0E,     // entity move/state array (others)
    ViewUpdate = 0x0F,      // self/view update + full snapshot
    Hello = 0x13,           // handshake, subtype-multiplexed (0..3)
    DeleteObject = 0x15,    // entity destroy
    WorldStats = 0x16,      // map name/id
    Player = 0x17,          // player record / id assignment
    TankSpawn = 0x18,       // entity create/spawn
    AddToRoster = 0x1A,     // roster add
    BirthNotice = 0x1E,     // spawn broadcast
    Login = 0x21,           // client->server: username / password
    LoginStatus = 0x22,     // server->client: login status code
    Motd = 0x23,            // message of the day
    Behavior = 0x24,        // physics tunables
    Reincarnate = 0x25,     // respawn request/grant
    TeamInfo = 0x28,        // team names/metadata
    GameClock = 0x2F,       // ticks + phase/length
    Translation = 0x32,     // float quantization table
    TranslationAck = 0x33,  // client->server: ack the translation table
    WantUpdates = 0x39,     // client->server: ready for updates
    IdentifiedUdp = 0x4D,   // server->client: UDP endpoint linked to TCP session
};

// True if `opcode` is one of the known protocol opcodes above. Anything else from a
// client is rejected (drop the connection) before it can reach the engine.
[[nodiscard]] auto IsKnownOpcode(std::uint8_t opcode) -> bool;

}  // namespace wfh::proto
