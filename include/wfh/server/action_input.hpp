// NOLINTBEGIN(portability-avoid-pragma-once)
// pragma once is the project-wide include-guard convention; intentional.
#pragma once
// NOLINTEND(portability-avoid-pragma-once)

#include <cstddef>
#include <cstdint>
#include <vector>

namespace wfh::server {

// One decoded control channel and its value. Analog channels decode to a float in
// [-1, 1]; digital (button) channels decode to 0.0F (released) or 1.0F (pressed).
struct ActionChannelValue {
    std::int32_t channel = 0;
    float value = 0.0F;
};

// Result of decoding an inbound ACTION packet body. `ok` is false (and `changes` is
// not to be trusted) if the bitstream under-ran or was otherwise malformed -- the
// decoder is fail-closed (see proto::BitReader). `timestamp` is the client's monotonic
// game-time stamp carried by the packet (used for input ordering / lag handling).
struct DecodedActions {
    bool ok = false;
    std::int32_t timestamp = 0;
    std::vector<ActionChannelValue> changes;
};

// Channels are quantized per a server-supplied ramp (the TRANSLATION 0x32 packet our
// BuildTranslation emits): analog channels use a 16-bit level over [high=1.0, low=-1.0];
// the channel index is 16 bits; digital channels are 1 bit. These mirror the values our
// server sends, which the client encoded against -- verified against 826 golden captures.
constexpr unsigned kActionChannelIndexBits = 16;
constexpr unsigned kActionAnalogValueBits = 16;
constexpr unsigned kActionDigitalValueBits = 1;
constexpr float kActionAnalogHigh = 1.0F;   // ramp upper bound (value at level 1)
constexpr float kActionAnalogRange = 2.0F;  // high - low; low = high - range = -1.0
// Drivable / valid channel range. The engine indexes 22 channels (0..21); ACTION_DUMP
// carries channels 1..21 (channel 0 is not transmitted in a dump).
constexpr std::int32_t kActionDumpFirstChannel = 1;
constexpr std::int32_t kActionMaxChannel = 21;
// Digital-channel classification: channel 4 is the lone low-index button; every channel
// at or above 8 is also a 1-bit button. Channels 0,1,2,3,5,6,7 are analog axes.
constexpr std::int32_t kActionDigitalLoneChannel = 4;
constexpr std::int32_t kActionFirstHighDigitalChannel = 8;
// Bound the ACTION_UPDATE change loop so a hostile count can't spin (the fail-closed
// reader also stops us once the body is exhausted; this is belt-and-suspenders).
constexpr std::size_t kMaxActionChanges = 32;

// True if `channel` is a 1-bit digital (button) channel: channel 4, or channel >= 8.
// Analog (16-bit) otherwise: channels 0,1,2,3,5,6,7. (Verified from the client's
// SyncAction encoding-class selector.)
[[nodiscard]] auto IsDigitalActionChannel(std::int32_t channel) -> bool;

// Decode an inbound ACTION_UPDATE (0x0A) body (the bytes AFTER the opcode):
//   [count:8][timestamp:i32][seq:i32]  then  count x ( [channel:16][value] )
// where value is 1 bit (digital) or 16-bit analog level by channel class. `changes`
// holds one entry per transmitted channel. Fail-closed: any under-run -> ok=false.
[[nodiscard]] auto DecodeActionUpdate(const std::uint8_t* body, std::size_t len) -> DecodedActions;

// Decode an inbound ACTION_DUMP (0x09) body (bytes after the opcode):
//   [timestamp:i32][seq:i32]  then  the values of channels 1..21 in order (NO index),
// each 1 bit (digital) or 16-bit analog by channel class. Returns all 21 channels.
[[nodiscard]] auto DecodeActionDump(const std::uint8_t* body, std::size_t len) -> DecodedActions;

}  // namespace wfh::server
