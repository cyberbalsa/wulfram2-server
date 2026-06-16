#pragma once
#include <cstdint>
#include <filesystem>
#include <string>

namespace wfh {

enum class Level : int { Trace = 0, Debug = 1, Info = 2, Warn = 3, Error = 4, Fatal = 5 };

const char* LevelTag(Level level);  // "TRACE".."FATAL"

class Log {
public:
    static void Init(const std::filesystem::path& file, Level min_level);
    static void Shutdown();
    static void SetTick(std::uint64_t tick);
    static Level MinLevel();
    static void Write(Level level, const char* category, const char* file, int line,
                      const char* fmt, ...);
};

}  // namespace wfh

#define WFH_LOG(level, category, ...)                                            \
    do {                                                                         \
        if (static_cast<int>(level) >= static_cast<int>(::wfh::Log::MinLevel())) \
            ::wfh::Log::Write((level), (category), __FILE__, __LINE__, __VA_ARGS__); \
    } while (0)

#define WFH_TRACE(cat, ...) WFH_LOG(::wfh::Level::Trace, cat, __VA_ARGS__)
#define WFH_DEBUG(cat, ...) WFH_LOG(::wfh::Level::Debug, cat, __VA_ARGS__)
#define WFH_INFO(cat, ...)  WFH_LOG(::wfh::Level::Info,  cat, __VA_ARGS__)
#define WFH_WARN(cat, ...)  WFH_LOG(::wfh::Level::Warn,  cat, __VA_ARGS__)
#define WFH_ERROR(cat, ...) WFH_LOG(::wfh::Level::Error, cat, __VA_ARGS__)
#define WFH_FATAL(cat, ...) WFH_LOG(::wfh::Level::Fatal, cat, __VA_ARGS__)
