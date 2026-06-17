#include "wfh/server/tick_guard.hpp"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <gtest/gtest.h>

#include <cstdint>
#include <filesystem>

namespace {

struct Counter {
    int calls = 0;
};

void __cdecl IncrementCounter(void* user) {
    auto* counter = static_cast<Counter*>(user);
    ++counter->calls;
}

void __cdecl RaiseAccessViolation(void* /*user*/) {
    RaiseException(EXCEPTION_ACCESS_VIOLATION, 0, 0, nullptr);
}

}  // namespace

TEST(TickGuard, RunsCallbackAndMarksSuccess) {
    Counter counter;
    wfh::server::TickBreadcrumb breadcrumb{};
    breadcrumb.tick = 42;
    breadcrumb.phase = "unit-test";

    const wfh::server::TickGuardResult result =
        wfh::server::RunProtectedTick(breadcrumb, &IncrementCounter, &counter);

    EXPECT_TRUE(result.ok);
    EXPECT_EQ(counter.calls, 1);
    EXPECT_EQ(result.tick, 42u);
    EXPECT_EQ(result.seh_code, 0u);
}

TEST(TickGuard, CatchesSehFaultAndReportsBreadcrumb) {
    wfh::server::TickBreadcrumb breadcrumb{};
    breadcrumb.tick = 77;
    breadcrumb.phase = "fault-test";

    const wfh::server::TickGuardResult result =
        wfh::server::RunProtectedTick(breadcrumb, &RaiseAccessViolation, nullptr);

    EXPECT_FALSE(result.ok);
    EXPECT_EQ(result.tick, 77u);
    EXPECT_EQ(result.seh_code, static_cast<std::uint32_t>(EXCEPTION_ACCESS_VIOLATION));
    EXPECT_NE(result.seh_address, 0u);
}

TEST(TickGuard, WritesDumpWhenPathProvided) {
    const std::filesystem::path dump_path =
        std::filesystem::temp_directory_path() / "wfh_tick_guard_fault.dmp";
    std::filesystem::remove(dump_path);

    wfh::server::TickBreadcrumb breadcrumb{};
    breadcrumb.tick = 88;
    breadcrumb.phase = "dump-test";
    wfh::server::TickGuardOptions options{};
    const std::wstring dump_path_text = dump_path.wstring();
    options.dump_path = dump_path_text.c_str();

    const wfh::server::TickGuardResult result =
        wfh::server::RunProtectedTick(breadcrumb, &RaiseAccessViolation, nullptr, options);

    EXPECT_FALSE(result.ok);
    EXPECT_TRUE(result.dump_written);
    EXPECT_TRUE(std::filesystem::exists(dump_path));

    std::filesystem::remove(dump_path);
}
