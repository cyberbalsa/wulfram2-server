// NOLINTBEGIN(portability-avoid-pragma-once)
// pragma once is the project-wide include-guard convention; intentional.
#pragma once
// NOLINTEND(portability-avoid-pragma-once)
#include <array>
#include <string_view>
#include <utility>

#include "wfh/log.hpp"

namespace wfh {

// Parse the [log] level from headless.toml contents. Looks for a line containing "level"
// and maps the first recognized token to a Level; defaults to Debug if absent/unrecognized.
// Case-sensitive lowercase tokens: trace/debug/info/warn/error/fatal.
inline auto ParseLogLevel(std::string_view contents) -> Level {
    static constexpr std::array<std::pair<std::string_view, Level>, 6> kTokens{{
        {"trace", Level::Trace},
        {"debug", Level::Debug},
        {"info", Level::Info},
        {"warn", Level::Warn},
        {"error", Level::Error},
        {"fatal", Level::Fatal},
    }};

    // Scan line by line; on the first line containing "level", match a level token.
    std::string_view rest = contents;
    while (!rest.empty()) {
        const std::size_t nl = rest.find('\n');
        const std::string_view line = rest.substr(0, nl);
        if (line.find("level") != std::string_view::npos) {
            for (const auto& [token, level] : kTokens) {
                if (line.find(token) != std::string_view::npos) {
                    return level;
                }
            }
            return Level::Debug;  // "level" line present but no recognized token
        }
        if (nl == std::string_view::npos) {
            break;
        }
        rest.remove_prefix(nl + 1);
    }
    return Level::Debug;  // no "level" line found
}

}  // namespace wfh
