// NOLINTBEGIN(portability-avoid-pragma-once)
// pragma once is the project-wide include-guard convention; intentional.
#pragma once
// NOLINTEND(portability-avoid-pragma-once)

#include <cstdint>
#include <string>
#include <string_view>

namespace wfh::server {

// Server settings drawn from the [server] table of headless.toml. Pure value type;
// parsed by ParseServerConfig (header-only scan, same style as wfh::ParseLogLevel).
// Defaults (Wulf-Forge used 2627 for TCP+UDP; 20 Hz matches the engine tick).
constexpr std::uint16_t kDefaultPort = 2627;
constexpr std::uint32_t kDefaultTickHz = 20;

struct ServerConfig {
    std::uint16_t bind_port = kDefaultPort;         // TCP + UDP listen port
    std::uint32_t tick_hz = kDefaultTickHz;         // engine tick cadence (informational)
    std::string map = "bpass";                      // map name advertised in WORLD_STATS
    std::string advertised_udp_host = "127.0.0.1";  // host told to clients for UDP
};

// Parse the [server] keys (bind_port, tick_hz, map) from headless.toml contents.
// Unrecognized/missing keys keep their defaults. Robust to comments and whitespace;
// values may be quoted or bare. Never throws.
[[nodiscard]] auto ParseServerConfig(std::string_view contents) -> ServerConfig;

}  // namespace wfh::server
