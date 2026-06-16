// NOLINTBEGIN(portability-avoid-pragma-once)
// pragma once is the project-wide include-guard convention; intentional.
#pragma once
// NOLINTEND(portability-avoid-pragma-once)
#include <cstdint>
#include <filesystem>
#include <string>

namespace wfh {

// Level is stored/compared as int (see the WFH_LOG macro and the atomic<int>
// in log.cpp). Keep the explicit int underlying type rather than shrinking it.
// NOLINTNEXTLINE(performance-enum-size)
enum class Level : int { Trace = 0, Debug = 1, Info = 2, Warn = 3, Error = 4, Fatal = 5 };

auto LevelTag(Level level) -> const char*;  // "TRACE".."FATAL"

class Log {
public:
    static void Init(const std::filesystem::path& file, Level min_level);
    static void Shutdown();
    static void SetTick(std::uint64_t tick);
    static auto MinLevel() -> Level;
    // Write is intentionally a printf-style C variadic so call sites can use a
    // familiar format string; this is the core logging primitive.
    // NOLINTNEXTLINE(cert-dcl50-cpp,modernize-avoid-variadic-functions,bugprone-easily-swappable-parameters)
    static void Write(Level level, const char* category, const char* file, int line,
                      const char* fmt, ...);
};

}  // namespace wfh

// The WFH_* logging macros are deliberately function-like variadic macros: they
// capture __FILE__/__LINE__ at the call site and short-circuit on level before
// evaluating arguments. A constexpr variadic template cannot capture the call
// site's file/line, so the macro form is intentional.
// NOLINTBEGIN(cppcoreguidelines-macro-usage)
#define WFH_LOG(level, category, ...)                                                              \
    do {                                                                                           \
        if (static_cast<int>(level) >= static_cast<int>(::wfh::Log::MinLevel()))                   \
            ::wfh::Log::Write((level), (category), __FILE__, __LINE__, __VA_ARGS__);               \
    } while (0)

#define WFH_TRACE(cat, ...) WFH_LOG(::wfh::Level::Trace, cat, __VA_ARGS__)
#define WFH_DEBUG(cat, ...) WFH_LOG(::wfh::Level::Debug, cat, __VA_ARGS__)
#define WFH_INFO(cat, ...)  WFH_LOG(::wfh::Level::Info, cat, __VA_ARGS__)
#define WFH_WARN(cat, ...)  WFH_LOG(::wfh::Level::Warn, cat, __VA_ARGS__)
#define WFH_ERROR(cat, ...) WFH_LOG(::wfh::Level::Error, cat, __VA_ARGS__)
#define WFH_FATAL(cat, ...) WFH_LOG(::wfh::Level::Fatal, cat, __VA_ARGS__)
// NOLINTEND(cppcoreguidelines-macro-usage)
