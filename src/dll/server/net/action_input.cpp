#include "wfh/server/action_input.hpp"

#include "wfh/proto/bitstream.hpp"

#include <algorithm>
#include <cstdint>

namespace wfh::server {

namespace {

using proto::BitReader;

// Inverse of the server's Quantize (world_packets.cpp): level 0 -> 0.0; otherwise
//   value = high - (level - 1) * range / (2^bits - 2)
// clamped to [high - range, high]. Matches the engine's Range_LevelToValue with
// field[0] = bits, +0x18 = high, +0x20 = range. This is the exact ramp our
// BuildTranslation sends (high=1.0, range=2.0, bits=16), which the client encoded against.
auto DequantizeAnalog(std::uint32_t level) -> float {
    if (level == 0) {
        return 0.0F;
    }
    const auto denom = static_cast<float>((1U << kActionAnalogValueBits) - 2U);
    const float value =
        kActionAnalogHigh - (static_cast<float>(level - 1U) * kActionAnalogRange / denom);
    return std::clamp(value, kActionAnalogHigh - kActionAnalogRange, kActionAnalogHigh);
}

// Read one channel's value off the stream given its index (selects digital vs analog
// width). Returns false (and latches reader failure) on under-run.
auto ReadChannelValue(BitReader& reader, std::int32_t channel, float& out) -> bool {
    if (IsDigitalActionChannel(channel)) {
        const auto bit = reader.ReadBits(kActionDigitalValueBits);
        if (!bit) {
            return false;
        }
        out = (*bit != 0U) ? 1.0F : 0.0F;
        return true;
    }
    const auto level = reader.ReadBits(kActionAnalogValueBits);
    if (!level) {
        return false;
    }
    out = DequantizeAnalog(*level);
    return true;
}

}  // namespace

auto IsDigitalActionChannel(std::int32_t channel) -> bool {
    return channel == kActionDigitalLoneChannel || channel >= kActionFirstHighDigitalChannel;
}

auto DecodeActionUpdate(const std::uint8_t* body, std::size_t len) -> DecodedActions {
    DecodedActions out;
    BitReader reader(body, len);
    const auto count = reader.ReadByte();
    const auto timestamp = reader.ReadI32();
    const auto seq = reader.ReadI32();  // pending-event counter; zeroed each send (unused)
    static_cast<void>(seq);
    if (!count || !timestamp) {
        return out;  // ok stays false
    }
    if (*count > kMaxActionChanges) {
        return out;  // implausible change count -> reject the whole packet
    }
    out.timestamp = *timestamp;
    out.changes.reserve(*count);
    for (std::size_t i = 0; i < *count; ++i) {
        const auto channel = reader.ReadBits(kActionChannelIndexBits);
        if (!channel) {
            return out;  // under-run -> fail closed (ok stays false)
        }
        const auto channel_id = static_cast<std::int32_t>(*channel);
        float value = 0.0F;
        if (!ReadChannelValue(reader, channel_id, value)) {
            return out;
        }
        out.changes.push_back(ActionChannelValue{channel_id, value});
    }
    out.ok = true;
    return out;
}

auto DecodeActionDump(const std::uint8_t* body, std::size_t len) -> DecodedActions {
    DecodedActions out;
    BitReader reader(body, len);
    const auto timestamp = reader.ReadI32();
    const auto seq = reader.ReadI32();  // pending-event counter; zeroed each send (unused)
    static_cast<void>(seq);
    if (!timestamp) {
        return out;
    }
    out.timestamp = *timestamp;
    out.changes.reserve(static_cast<std::size_t>(kActionMaxChannel));
    // DUMP is positional: the values of channels 1..21 in order, with no per-entry index.
    for (std::int32_t channel = kActionDumpFirstChannel; channel <= kActionMaxChannel; ++channel) {
        float value = 0.0F;
        if (!ReadChannelValue(reader, channel, value)) {
            return out;  // under-run before all 21 channels -> reject
        }
        out.changes.push_back(ActionChannelValue{channel, value});
    }
    out.ok = true;
    return out;
}

}  // namespace wfh::server
