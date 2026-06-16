#include "wfh/server/server_config.hpp"

#include "wfh/config.hpp"  // wfh::TrimView

#include <charconv>
#include <cstdint>
#include <string>
#include <string_view>

namespace wfh::server {

namespace {

constexpr std::uint32_t kMaxPort = 65535;

// Extract the value to the right of '=' on a line, unquoting a single "..." pair
// if present, else the trimmed remainder. Empty if there is no '='.
auto ValueOf(std::string_view line) -> std::string_view {
    const std::size_t eq = line.find('=');
    if (eq == std::string_view::npos) {
        return {};
    }
    std::string_view rhs = line.substr(eq + 1);
    // Strip a trailing inline comment (# ...) on bare values; quoted values keep #.
    const std::size_t q1 = rhs.find('"');
    if (q1 != std::string_view::npos) {
        const std::size_t q2 = rhs.find('"', q1 + 1);
        if (q2 != std::string_view::npos) {
            return TrimView(rhs.substr(q1 + 1, q2 - q1 - 1));
        }
    }
    const std::size_t hash = rhs.find('#');
    if (hash != std::string_view::npos) {
        rhs = rhs.substr(0, hash);
    }
    return TrimView(rhs);
}

// Match a line's key (text left of '=') against `key` exactly (trimmed).
auto KeyIs(std::string_view line, std::string_view key) -> bool {
    const std::size_t eq = line.find('=');
    return eq != std::string_view::npos && TrimView(line.substr(0, eq)) == key;
}

auto ParseU32(std::string_view text, std::uint32_t fallback) -> std::uint32_t {
    std::uint32_t out = 0;
    const char* begin = text.data();
    const char* end =
        begin + text.size();  // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    const auto [ptr, ec] = std::from_chars(begin, end, out);
    if (ec != std::errc{} || ptr != end) {
        return fallback;
    }
    return out;
}

void SetIfPresent(std::string& target, std::string_view value) {
    if (!value.empty()) {
        target = std::string(value);
    }
}

void ApplyServerKey(ServerConfig& cfg, std::string_view line) {
    if (KeyIs(line, "bind_port")) {
        const std::uint32_t port = ParseU32(ValueOf(line), cfg.bind_port);
        if (port > 0 && port <= kMaxPort) {
            cfg.bind_port = static_cast<std::uint16_t>(port);
        }
    } else if (KeyIs(line, "tick_hz")) {
        cfg.tick_hz = ParseU32(ValueOf(line), cfg.tick_hz);
    } else if (KeyIs(line, "map")) {
        SetIfPresent(cfg.map, ValueOf(line));
    } else if (KeyIs(line, "advertised_udp_host")) {
        SetIfPresent(cfg.advertised_udp_host, ValueOf(line));
    }
}

auto IsSectionHeader(std::string_view line) -> bool {
    return !line.empty() && line.front() == '[';
}

auto IsServerKeyLine(bool in_server_section, std::string_view line) -> bool {
    return in_server_section && !line.empty() && line.front() != '#';
}

}  // namespace

auto ParseServerConfig(std::string_view contents) -> ServerConfig {
    ServerConfig cfg;
    bool in_server_section = false;

    std::string_view rest = contents;
    while (!rest.empty()) {
        const std::size_t nl = rest.find('\n');
        const std::string_view raw = rest.substr(0, nl);
        const std::string_view line = TrimView(raw);

        if (IsSectionHeader(line)) {
            in_server_section = (line == "[server]");
        } else if (IsServerKeyLine(in_server_section, line)) {
            ApplyServerKey(cfg, line);
        }

        if (nl == std::string_view::npos) {
            break;
        }
        rest.remove_prefix(nl + 1);
    }
    return cfg;
}

}  // namespace wfh::server
