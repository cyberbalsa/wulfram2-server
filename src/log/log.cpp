#include "wfh/log.hpp"

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

const char* LevelTag(Level level) {
    switch (level) {
        case Level::Trace: return "TRACE";
        case Level::Debug: return "DEBUG";
        case Level::Info:  return "INFO";
        case Level::Warn:  return "WARN";
        case Level::Error: return "ERROR";
        case Level::Fatal: return "FATAL";
    }
    return "?????";
}

namespace {

struct State {
    std::ofstream file;
    std::mutex mutex;
    std::condition_variable cv;
    std::deque<std::string> queue;  // NOTE: queue is unbounded; backpressure/cap deferred to the tick-loop milestone (M4).
    std::thread worker;
    std::atomic<bool> running{false};
    std::atomic<int> min_level{static_cast<int>(Level::Debug)};
    std::atomic<std::uint64_t> tick{0};

    // Safe teardown if Shutdown() was never called (e.g. injected-DLL path that
    // runs for the whole process lifetime). Destroying a still-joinable
    // std::thread triggers std::terminate(); stop the worker first. Cooperates
    // with Shutdown(): if Shutdown already ran, worker is no longer joinable.
    ~State() {
        running.store(false);
        cv.notify_all();
        if (worker.joinable()) worker.join();
    }
};

State& S() { static State s; return s; }

void DrainOnce(State& s) {
    std::deque<std::string> local;
    {
        std::unique_lock<std::mutex> lock(s.mutex);
        local.swap(s.queue);
    }
    for (const auto& line : local) {
        if (s.file.is_open()) s.file << line;
        OutputDebugStringA(line.c_str());
    }
    if (s.file.is_open()) s.file.flush();
}

void WorkerMain() {
    State& s = S();
    while (s.running.load()) {
        {
            std::unique_lock<std::mutex> lock(s.mutex);
            s.cv.wait_for(lock, std::chrono::milliseconds(50),
                          [&] { return !s.queue.empty() || !s.running.load(); });
        }
        DrainOnce(s);
    }
    DrainOnce(s);  // final flush
}

}  // namespace

void Log::Init(const std::filesystem::path& file, Level min_level) {
    State& s = S();
    if (s.running.load()) return;  // idempotent: a worker is already running
    std::filesystem::create_directories(file.parent_path());
    s.file.open(file, std::ios::app);
    s.min_level.store(static_cast<int>(min_level));
    s.running.store(true);
    s.worker = std::thread(WorkerMain);
}

void Log::Shutdown() {
    State& s = S();
    if (!s.running.exchange(false)) return;
    s.cv.notify_all();
    if (s.worker.joinable()) s.worker.join();
    if (s.file.is_open()) s.file.close();
}

void Log::SetTick(std::uint64_t tick) { S().tick.store(tick); }
Level Log::MinLevel() { return static_cast<Level>(S().min_level.load()); }

void Log::Write(Level level, const char* category, const char* file, int line,
                const char* fmt, ...) {
    char body[1024];
    va_list args;
    va_start(args, fmt);
    std::vsnprintf(body, sizeof(body), fmt, args);
    va_end(args);

    const char* base = std::strrchr(file, '\\');
    base = base ? base + 1 : file;

    char head[256];
    std::snprintf(head, sizeof(head), "[%s][%s][t%llu][%s:%d] ",
                  LevelTag(level), category,
                  static_cast<unsigned long long>(S().tick.load()), base, line);

    std::string line_str;
    line_str.reserve(std::strlen(head) + std::strlen(body) + 2);
    line_str.append(head).append(body).append("\n");

    State& s = S();
    {
        std::lock_guard<std::mutex> lock(s.mutex);
        s.queue.emplace_back(std::move(line_str));
    }
    s.cv.notify_one();
}

}  // namespace wfh
