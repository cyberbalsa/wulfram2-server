#include "wfh/log.hpp"

#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <deque>
#include <fstream>
#include <mutex>
#include <thread>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

namespace wfh {

auto LevelTag(Level level) -> const char* {
    switch (level) {
    case Level::Trace: return "TRACE";
    case Level::Debug: return "DEBUG";
    case Level::Info: return "INFO";
    case Level::Warn: return "WARN";
    case Level::Error: return "ERROR";
    case Level::Fatal: return "FATAL";
    }
    return "?????";
}

namespace {

// Worker poll interval and the fixed format-buffer sizes for Write().
constexpr auto kWorkerPollInterval = std::chrono::milliseconds(50);
constexpr std::size_t kBodyBufferSize = 1024;
constexpr std::size_t kHeadBufferSize = 256;

// No destructor by design (see S() and the note below): the special-member rule
// flags the missing destructor alongside the deleted copy/move, but a destructor
// is exactly what must not exist here.
// NOLINTNEXTLINE(cppcoreguidelines-special-member-functions)
struct State {
    std::ofstream file;
    std::mutex mutex;
    std::condition_variable cv;
    std::deque<std::string> queue;  // NOTE: queue is unbounded; backpressure/cap deferred to the
                                    // tick-loop milestone (M4).
    std::thread worker;
    std::atomic<bool> running{false};
    std::atomic<int> min_level{static_cast<int>(Level::Debug)};
    std::atomic<std::uint64_t> tick{0};

    State() = default;

    // No destructor: State is an intentionally-leaked process-lifetime singleton
    // (see S()), so ~State() must never run. On the injected-DLL success path the
    // logger is never Shutdown(), so a destructor here would run during CRT/static
    // teardown near the loader lock, where worker.join() can deadlock the host
    // process on exit. The explicit Shutdown() path (running.exchange(false) +
    // notify + join) is the only clean stop; if it is never called the worker
    // thread is simply reclaimed by the OS at process exit. Because State is never
    // destroyed, the worker can never touch a freed mutex/queue/file either.

    // State is a process-lifetime singleton (see S()); it is never copied or moved.
    State(const State&) = delete;
    State(State&&) = delete;
    auto operator=(const State&) -> State& = delete;
    auto operator=(State&&) -> State& = delete;
};

// Intentionally-leaked singleton: the State is heap-allocated and never deleted so
// its destructor NEVER runs at process/static teardown. This avoids a worker.join()
// hang near the loader lock when the injected DLL never calls Shutdown(). The leak
// is by design and bounded (one State for the process lifetime), so the owning-memory
// (no matching delete) and use-auto checks are suppressed on the deliberate new.
auto S() -> State& {
    // NOLINTNEXTLINE(cppcoreguidelines-owning-memory,modernize-use-auto)
    static State* const state = new State();  // intentionally leaked; ~State never runs
    return *state;
}

void DrainOnce(State& state) {
    std::deque<std::string> local;
    {
        std::unique_lock<std::mutex> lock(state.mutex);
        local.swap(state.queue);
    }
    for (const auto& line : local) {
        if (state.file.is_open()) {
            state.file << line;
        }
        OutputDebugStringA(line.c_str());
    }
    if (state.file.is_open()) {
        state.file.flush();
    }
}

void WorkerMain() {
    State& state = S();
    while (state.running.load()) {
        {
            std::unique_lock<std::mutex> lock(state.mutex);
            state.cv.wait_for(lock, kWorkerPollInterval, [&]() -> bool {
                return !state.queue.empty() || !state.running.load();
            });
        }
        DrainOnce(state);
    }
    DrainOnce(state);  // final flush
}

}  // namespace

void Log::Init(const std::filesystem::path& file, Level min_level) {
    State& state = S();
    if (state.running.load()) {
        return;  // idempotent: a worker is already running
    }
    std::filesystem::create_directories(file.parent_path());
    state.file.open(file, std::ios::app);
    state.min_level.store(static_cast<int>(min_level));
    state.running.store(true);
    state.worker = std::thread(WorkerMain);
}

void Log::Shutdown() {
    State& state = S();
    if (!state.running.exchange(false)) {
        return;
    }
    state.cv.notify_all();
    if (state.worker.joinable()) {
        state.worker.join();
    }
    if (state.file.is_open()) {
        state.file.close();
    }
}

void Log::SetTick(std::uint64_t tick) {
    S().tick.store(tick);
}

auto Log::MinLevel() -> Level {
    return static_cast<Level>(S().min_level.load());
}

// The formatting path below intentionally uses printf-style C variadics and
// fixed stack buffers: this is the low-level logging primitive that runs inside
// an injected DLL where keeping the implementation small and allocation-light
// matters. The cppcoreguidelines/cert vararg + C-array + bounds checks do not
// apply to this deliberate design, so they are suppressed locally.
// NOLINTBEGIN(cppcoreguidelines-pro-type-vararg,cppcoreguidelines-avoid-c-arrays,modernize-avoid-c-arrays,cppcoreguidelines-pro-bounds-array-to-pointer-decay,cppcoreguidelines-pro-bounds-pointer-arithmetic,cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers,cert-dcl50-cpp,modernize-avoid-variadic-functions,bugprone-easily-swappable-parameters,cert-err33-c,cppcoreguidelines-init-variables)
void Log::Write(Level level, const char* category, const char* file, int line, const char* fmt,
                ...) {
    std::array<char, kBodyBufferSize> body{};
    va_list args;
    va_start(args, fmt);
    std::vsnprintf(body.data(), body.size(), fmt, args);
    va_end(args);

    const char* base = std::strrchr(file, '\\');
    base = (base != nullptr) ? base + 1 : file;

    std::array<char, kHeadBufferSize> head{};
    std::snprintf(head.data(), head.size(), "[%s][%s][t%llu][%s:%d] ", LevelTag(level), category,
                  static_cast<unsigned long long>(S().tick.load()), base, line);

    std::string line_str;
    line_str.reserve(std::strlen(head.data()) + std::strlen(body.data()) + 2);
    line_str.append(head.data()).append(body.data()).append("\n");

    State& state = S();
    {
        std::scoped_lock<std::mutex> lock(state.mutex);
        state.queue.emplace_back(std::move(line_str));
    }
    state.cv.notify_one();
}
// NOLINTEND(cppcoreguidelines-pro-type-vararg,cppcoreguidelines-avoid-c-arrays,modernize-avoid-c-arrays,cppcoreguidelines-pro-bounds-array-to-pointer-decay,cppcoreguidelines-pro-bounds-pointer-arithmetic,cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers,cert-dcl50-cpp,modernize-avoid-variadic-functions,bugprone-easily-swappable-parameters,cert-err33-c,cppcoreguidelines-init-variables)

}  // namespace wfh
