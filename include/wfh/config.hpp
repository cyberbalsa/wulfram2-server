// NOLINTBEGIN(portability-avoid-pragma-once)
// pragma once is the project-wide include-guard convention; intentional.
#pragma once
// NOLINTEND(portability-avoid-pragma-once)
#include <array>
#include <string_view>
#include <utility>

#include "wfh/log.hpp"

namespace wfh {

// Trim ASCII whitespace from both ends of a string_view (header-only, no deps).
inline auto TrimView(std::string_view text) -> std::string_view {
    constexpr std::string_view kWs = " \t\r\n\f\v";
    const std::size_t begin = text.find_first_not_of(kWs);
    if (begin == std::string_view::npos) {
        return {};
    }
    const std::size_t end = text.find_last_not_of(kWs);
    return text.substr(begin, end - begin + 1);
}

// Parse the [log] level from headless.toml contents. The level line is recognized only
// when its key (text left of '=') trims to exactly "level" — so keys like noise_level,
// comments, or values mentioning a level word never mis-fire. The level token is taken
// from the quoted value (between the first pair of quotes) or, if unquoted, the trimmed
// RHS, and compared against exact tokens. Defaults to Debug if absent/unrecognized.
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

    // Scan line by line; the level line is the first whose key trims to exactly "level".
    std::string_view rest = contents;
    while (!rest.empty()) {
        const std::size_t nl = rest.find('\n');
        const std::string_view line = rest.substr(0, nl);
        const std::size_t eq = line.find('=');
        if (eq != std::string_view::npos && TrimView(line.substr(0, eq)) == "level") {
            const std::string_view rhs = line.substr(eq + 1);
            // Prefer the token between the first pair of quotes; else the trimmed RHS.
            std::string_view value;
            const std::size_t q1 = rhs.find('"');
            const std::size_t q2 =
                (q1 == std::string_view::npos) ? std::string_view::npos : rhs.find('"', q1 + 1);
            if (q1 != std::string_view::npos && q2 != std::string_view::npos) {
                value = TrimView(rhs.substr(q1 + 1, q2 - q1 - 1));
            } else {
                value = TrimView(rhs);
            }
            for (const auto& [token, level] : kTokens) {
                if (value == token) {
                    return level;
                }
            }
            return Level::Debug;  // "level" key present but no recognized token
        }
        if (nl == std::string_view::npos) {
            break;
        }
        rest.remove_prefix(nl + 1);
    }
    return Level::Debug;  // no "level" line found
}

}  // namespace wfh
