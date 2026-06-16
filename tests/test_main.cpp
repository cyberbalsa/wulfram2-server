#include "wfh/engine_abi.hpp"
#include "wfh/injector.hpp"
#include "wfh/log.hpp"
#include "wfh/pe_validate.hpp"

// Generated headers (gen/) — proves they compile and carry the right values.
#include "addresses.h"
#include "binary_manifest.h"

#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
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

TEST(PeValidate, CompareBytesEdgeCases) {
    const std::uint8_t a[] = {1, 2, 3};
    const std::uint8_t b[] = {1, 2, 3};
    EXPECT_TRUE(wfh::CompareBytes(a, b, 3).ok);
    EXPECT_TRUE(wfh::CompareBytes(nullptr, nullptr, 0).ok);  // zero length: trivially equal
    EXPECT_FALSE(wfh::CompareBytes(nullptr, b, 3).ok);       // null actual: clean fail, no UB
    EXPECT_FALSE(wfh::CompareBytes(a, nullptr, 3).ok);       // null expected: clean fail, no UB
}

TEST(PeValidate, HookSitesReadableMatch) {
    static const std::uint8_t kBuf[] = {0xDE, 0xAD, 0xBE, 0xEF};
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    wfh::HookSite site{"buf", static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(kBuf)),
                       kBuf, 4};
    wfh::BinaryManifest m{0, 0, 0, 0, &site, 1};
    EXPECT_TRUE(wfh::ValidateHookSitesInProcess(m).ok);
}

TEST(PeValidate, HookSitesReadableMismatch) {
    static const std::uint8_t kBuf[] = {0xDE, 0xAD, 0xBE, 0xEF};
    static const std::uint8_t kWrong[] = {0x00, 0x00, 0x00, 0x00};
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    wfh::HookSite site{"buf", static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(kBuf)),
                       kWrong, 4};
    wfh::BinaryManifest m{0, 0, 0, 0, &site, 1};
    const auto r = wfh::ValidateHookSitesInProcess(m);
    EXPECT_FALSE(r.ok);
    EXPECT_NE(r.error.find("mismatch"), std::string::npos);
}

TEST(GeneratedHeaders, AddressesAndManifestAreSane) {
    // gen/addresses.h constants compile and carry the curated W2VULK values.
    static_assert(wfh::addr::Client_RunMainLoop == 0x004a0aa0u, "address drift");
    static_assert(wfh::addr::Snd_InitDevice == 0x00489fb0u, "address drift");
    static_assert(wfh::addr::Voice_InitSystem == 0x0048b680u, "address drift");
    // gen/binary_manifest.h: real wulfram2.exe identity. Image base is fixed.
    EXPECT_EQ(wfh::kBinaryManifest.image_base, 0x00400000u);
    EXPECT_EQ(wfh::kBinaryManifest.site_count, 0u);
    EXPECT_EQ(wfh::kBinaryManifest.sites, nullptr);
    EXPECT_NE(wfh::kBinaryManifest.time_date_stamp, 0u);
    EXPECT_NE(wfh::kBinaryManifest.size_of_image, 0u);
}

TEST(PeValidate, HookSitesUnreadableAddressFailsSafe) {
    static const std::uint8_t kExpect[] = {0x00};
    wfh::HookSite site{"bogus", 0x1u, kExpect, 4};  // 0x1 is not a committed readable page
    wfh::BinaryManifest m{0, 0, 0, 0, &site, 1};
    const auto r = wfh::ValidateHookSitesInProcess(m);
    EXPECT_FALSE(r.ok);
    EXPECT_NE(r.error.find("unreadable"), std::string::npos);  // must NOT fault the process
}

TEST(EngineAbi, TypedefsResolveFromGeneratedAddresses) {
    // Build an ABI-correct function pointer at a real generated address.
    // We do NOT call it (no live game here) — just verify the binding resolves non-null.
    auto run_main_loop = wfh::abi::Fn<void>::At(wfh::addr::Client_RunMainLoop);
    EXPECT_NE(run_main_loop, nullptr);
    // __thiscall binding (as used for Net_* methods) must also form a valid pointer.
    auto net_accept =
        wfh::abi::Thiscall<int, void*, unsigned short>::At(wfh::addr::Net_InitAcceptSocket);
    EXPECT_NE(net_accept, nullptr);
}

TEST(Injector, RejectsWrongBinaryBeforeSpawning) {
    // A PE whose stamps do NOT match kBinaryManifest must be rejected by the pinning gate,
    // and LaunchAndInject must return !ok WITHOUT creating a process.
    namespace fs = std::filesystem;
    const auto dir = fs::temp_directory_path() / "wfh_inject_test";
    fs::remove_all(dir);
    fs::create_directories(dir);
    const auto fake_exe = dir / "wulfram2.exe";
    // minimal PE32 with deliberately-wrong TimeDateStamp (0xDEADBEEF != real stamp)
    {
        std::vector<unsigned char> buf(0x200, 0);
        buf[0] = 'M';
        buf[1] = 'Z';
        const std::uint32_t e_lfanew = 0x80;
        std::memcpy(&buf[0x3C], &e_lfanew, 4);
        buf[0x80] = 'P';
        buf[0x81] = 'E';
        const std::uint16_t machine = 0x014C;  // I386
        std::memcpy(&buf[0x84], &machine, 2);
        const std::uint16_t nsect = 1;
        std::memcpy(&buf[0x86], &nsect, 2);
        const std::uint32_t stamp = 0xDEADBEEF;
        std::memcpy(&buf[0x88], &stamp, 4);
        const std::uint16_t optsize = 0xE0;
        std::memcpy(&buf[0x94], &optsize, 2);
        const std::uint16_t magic = 0x010B;  // PE32
        std::memcpy(&buf[0x98], &magic, 2);
        std::ofstream(fake_exe, std::ios::binary)
            .write(reinterpret_cast<const char*>(buf.data()),  // NOLINT
                   static_cast<std::streamsize>(buf.size()));
    }
    wfh::InjectionPlan plan;
    plan.game_exe_path = fake_exe;
    plan.dll_path = fake_exe;  // unused — rejection happens before injection
    plan.command_line = L"\"" + fake_exe.wstring() + L"\"";
    const auto r = wfh::LaunchAndInject(plan);
    EXPECT_FALSE(r.ok);  // pinning rejects wrong build; no process spawned
    // Confirm the rejection came from the PINNING path (parsed but mismatched),
    // not a "cannot read PE headers" parse failure.
    EXPECT_NE(r.error.find("mismatch"), std::string::npos);
}
