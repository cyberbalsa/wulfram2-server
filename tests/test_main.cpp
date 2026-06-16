#include <exception>
#include <iostream>
#include <string>

struct TestFailure : std::exception {
    explicit TestFailure(std::string message) : message_(std::move(message)) {}
    const char* what() const noexcept override { return message_.c_str(); }
    std::string message_;
};

[[maybe_unused]] inline void Expect(bool condition, const char* message) {
    if (!condition) throw TestFailure(message);
}

#include "wfh/log.hpp"
#include <filesystem>
#include <fstream>
#include <sstream>

static std::string ReadAll(const std::filesystem::path& p) {
    std::ifstream in(p, std::ios::binary);
    std::ostringstream ss; ss << in.rdbuf(); return ss.str();
}

void test_log_writes_to_file_and_respects_level() {
    const auto dir = std::filesystem::temp_directory_path() / "wfh_log_test";
    std::filesystem::remove_all(dir);
    const auto file = dir / "headless.log";

    wfh::Log::Init(file, wfh::Level::Info);   // min level Info: Debug must be dropped
    WFH_LOG(wfh::Level::Debug, "net", "this should NOT appear %d", 1);
    WFH_LOG(wfh::Level::Warn,  "net", "client %d joined", 7);
    wfh::Log::Shutdown();                     // flushes synchronously

    const std::string contents = ReadAll(file);
    Expect(contents.find("client 7 joined") != std::string::npos, "warn line missing");
    Expect(contents.find("should NOT appear") == std::string::npos, "debug line leaked below min level");
    Expect(contents.find("[WARN]") != std::string::npos, "level tag missing");
    Expect(contents.find("net") != std::string::npos, "category missing");
}

void test_log_double_init_is_safe() {
    const auto dir = std::filesystem::temp_directory_path() / "wfh_log_double_init_test";
    std::filesystem::remove_all(dir);
    const auto file = dir / "headless.log";

    wfh::Log::Init(file, wfh::Level::Info);   // first init starts the worker
    wfh::Log::Init(file, wfh::Level::Info);   // second init must be a no-op (idempotent)
    WFH_LOG(wfh::Level::Warn, "net", "double_init_marker");
    wfh::Log::Shutdown();                     // flushes synchronously

    const std::string contents = ReadAll(file);
    const std::string marker = "double_init_marker";
    std::size_t count = 0;
    for (std::size_t pos = contents.find(marker); pos != std::string::npos;
         pos = contents.find(marker, pos + marker.size())) {
        ++count;
    }
    Expect(count == 1, "double_init_marker should appear exactly once");
}

int main() {
    int failures = 0;
    struct Case { const char* name; void(*fn)(); };
    const Case cases[] = {
        {"log_writes_to_file_and_respects_level", test_log_writes_to_file_and_respects_level},
        {"log_double_init_is_safe", test_log_double_init_is_safe},
    };
    for (const auto& c : cases) {
        try { c.fn(); std::cout << "  ok   " << c.name << "\n"; }
        catch (const std::exception& e) { ++failures; std::cout << "  FAIL " << c.name << ": " << e.what() << "\n"; }
    }
    std::cout << "wfh_tests: " << failures << " failures\n";
    return failures == 0 ? 0 : 1;
}
