#include "wfh/injector.hpp"
#include "wfh/log.hpp"
#include "wfh/pe_validate.hpp"

#include <gtest/gtest.h>

#include <cstddef>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

namespace {

std::string ReadAll(const std::filesystem::path& p) {
    std::ifstream in(p, std::ios::binary);
    std::ostringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

}  // namespace

TEST(LogTest, WritesToFileAndRespectsLevel) {
    const auto dir = std::filesystem::temp_directory_path() / "wfh_log_test";
    std::filesystem::remove_all(dir);
    const auto file = dir / "headless.log";

    wfh::Log::Init(file, wfh::Level::Info);  // min level Info: Debug must be dropped
    WFH_LOG(wfh::Level::Debug, "net", "this should NOT appear %d", 1);
    WFH_LOG(wfh::Level::Warn, "net", "client %d joined", 7);
    wfh::Log::Shutdown();  // flushes synchronously

    const std::string contents = ReadAll(file);
    EXPECT_NE(contents.find("client 7 joined"), std::string::npos);
    EXPECT_EQ(contents.find("should NOT appear"), std::string::npos);
    EXPECT_NE(contents.find("[WARN]"), std::string::npos);
    EXPECT_NE(contents.find("net"), std::string::npos);
}

TEST(LogTest, DoubleInitIsSafe) {
    const auto dir = std::filesystem::temp_directory_path() / "wfh_log_double_init_test";
    std::filesystem::remove_all(dir);
    const auto file = dir / "headless.log";

    wfh::Log::Init(file, wfh::Level::Info);  // first init starts the worker
    wfh::Log::Init(file, wfh::Level::Info);  // second init must be a no-op (idempotent)
    WFH_LOG(wfh::Level::Warn, "net", "double_init_marker");
    wfh::Log::Shutdown();  // flushes synchronously

    const std::string contents = ReadAll(file);
    const std::string marker = "double_init_marker";
    std::size_t count = 0;
    for (std::size_t pos = contents.find(marker); pos != std::string::npos;
         pos = contents.find(marker, pos + marker.size())) {
        ++count;
    }
    EXPECT_EQ(count, std::size_t{1});
}

TEST(LoaderArgs, ResolvesPaths) {
    std::vector<std::wstring> argv = {L"C:\\tools\\loader.exe", L"C:\\game\\wulfram2.exe", L"-port",
                                      L"2627"};
    const auto r = wfh::ParseLoaderArgs(argv);
    ASSERT_TRUE(r.ok);
    EXPECT_EQ(r.value.game_exe_path, std::filesystem::path(L"C:\\game\\wulfram2.exe"));
    EXPECT_EQ(r.value.dll_path.filename(), std::filesystem::path(L"wulf_headless.dll"));
    EXPECT_EQ(r.value.dll_path.parent_path(), std::filesystem::path(L"C:\\tools"));
    EXPECT_EQ(r.value.game_arguments, L"-port 2627");
}

TEST(LoaderArgs, RequiresExe) {
    std::vector<std::wstring> argv = {L"loader.exe"};
    const auto r = wfh::ParseLoaderArgs(argv);
    EXPECT_FALSE(r.ok);
}

TEST(PeValidate, ValidateHeadersMatchAndMismatch) {
    wfh::PeHeaderFacts facts;
    facts.time_date_stamp = 0x12345678;
    facts.size_of_image = 0x00300000;
    facts.check_sum = 0x000ABCDE;
    facts.image_base = 0x00400000;
    wfh::BinaryManifest good{0x12345678, 0x00300000, 0x000ABCDE, 0x00400000, nullptr, 0};
    EXPECT_TRUE(wfh::ValidateHeaders(facts, good).ok);
    wfh::BinaryManifest bad = good;
    bad.time_date_stamp = 0xDEADBEEF;
    const auto r = wfh::ValidateHeaders(facts, bad);
    EXPECT_FALSE(r.ok);
    EXPECT_NE(r.error.find("TimeDateStamp"), std::string::npos);
}

TEST(PeValidate, CompareBytesMatchAndMismatch) {
    const std::uint8_t mem[] = {0x55, 0x8B, 0xEC, 0x83, 0xEC};
    const std::uint8_t expect_ok[] = {0x55, 0x8B, 0xEC};
    const std::uint8_t expect_bad[] = {0x55, 0x90, 0xEC};
    EXPECT_TRUE(wfh::CompareBytes(mem, expect_ok, 3).ok);
    EXPECT_FALSE(wfh::CompareBytes(mem, expect_bad, 3).ok);
}
