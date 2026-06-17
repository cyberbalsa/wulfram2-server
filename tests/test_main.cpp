#include "wfh/config.hpp"
#include "wfh/engine_abi.hpp"
#include "wfh/injector.hpp"
#include "wfh/log.hpp"
#include "wfh/pe_validate.hpp"
#include "wfh/ready_event.hpp"

// Generated headers (gen/) — proves they compile and carry the right values.
#include "addresses.h"
#include "binary_manifest.h"

#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <cstring>
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

void WriteBytes(const std::filesystem::path& p, const std::vector<unsigned char>& bytes) {
    std::ofstream out(p, std::ios::binary);
    out.write(reinterpret_cast<const char*>(bytes.data()),  // NOLINT
              static_cast<std::streamsize>(bytes.size()));
}

}  // namespace

TEST(Config, ParseLogLevel) {
    EXPECT_EQ(wfh::ParseLogLevel("[log]\nlevel = \"info\"\n"), wfh::Level::Info);
    EXPECT_EQ(wfh::ParseLogLevel("level = \"trace\""), wfh::Level::Trace);
    EXPECT_EQ(wfh::ParseLogLevel("level=\"warn\""), wfh::Level::Warn);
    EXPECT_EQ(wfh::ParseLogLevel("level = \"error\""), wfh::Level::Error);
    EXPECT_EQ(wfh::ParseLogLevel("[server]\nbind_port = 2627\n"),
              wfh::Level::Trace);                                           // no level line
    EXPECT_EQ(wfh::ParseLogLevel("level = \"bogus\""), wfh::Level::Trace);  // unrecognized
    // Keys that merely *contain* "level" must not be treated as the level line.
    EXPECT_EQ(wfh::ParseLogLevel("noise_level = \"loud\"\n[log]\nlevel = \"warn\""),
              wfh::Level::Warn);
    // A comment/value containing a level word must not mis-fire; only the real key counts.
    EXPECT_EQ(wfh::ParseLogLevel("# set the error budget\nlevel = \"info\""), wfh::Level::Info);
}

TEST(Config, RuntimeConfigDefaultEnablesTrace) {
    const std::string contents = ReadAll(std::filesystem::path("config") / "headless.toml");
    ASSERT_FALSE(contents.empty());
    EXPECT_EQ(wfh::ParseLogLevel(contents), wfh::Level::Trace);
}

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

TEST(PeValidate, ReadPeHeaderFactsRejectsMalformed) {
    namespace fs = std::filesystem;
    const auto dir = fs::temp_directory_path() / "wfh_pe_malformed_test";
    fs::remove_all(dir);
    fs::create_directories(dir);

    // Builds a well-formed PE32 image (e_lfanew=0x80) we can mutate per case.
    auto make_good = []() -> std::vector<unsigned char> {
        std::vector<unsigned char> buf(0x200, 0);
        buf[0] = 'M';
        buf[1] = 'Z';
        const std::uint32_t e_lfanew = 0x80;
        std::memcpy(&buf[0x3C], &e_lfanew, 4);
        buf[0x80] = 'P';
        buf[0x81] = 'E';                       // "PE\0\0" at e_lfanew
        const std::uint16_t machine = 0x014C;  // I386
        std::memcpy(&buf[0x84], &machine, 2);
        const std::uint16_t nsect = 1;
        std::memcpy(&buf[0x86], &nsect, 2);
        const std::uint32_t stamp = 0x11223344;
        std::memcpy(&buf[0x88], &stamp, 4);
        const std::uint16_t optsize = 0xE0;  // SizeOfOptionalHeader
        std::memcpy(&buf[0x94], &optsize, 2);
        const std::uint16_t magic = 0x010B;  // PE32 optional-header magic
        std::memcpy(&buf[0x98], &magic, 2);
        const std::uint32_t image_base = 0x00400000;
        std::memcpy(&buf[0x80 + 24 + 28], &image_base, 4);
        const std::uint32_t size_of_image = 0x00300000;
        std::memcpy(&buf[0x80 + 24 + 56], &size_of_image, 4);
        const std::uint32_t check_sum = 0x000ABCDE;
        std::memcpy(&buf[0x80 + 24 + 64], &check_sum, 4);
        return buf;
    };

    // (a) too small: fewer bytes than sizeof(IMAGE_DOS_HEADER).
    {
        const auto p = dir / "too_small";
        WriteBytes(p, std::vector<unsigned char>(8, 0));
        EXPECT_FALSE(wfh::ReadPeHeaderFacts(p).ok);
    }
    // (b) no "MZ" magic.
    {
        auto buf = make_good();
        buf[0] = 'X';
        buf[1] = 'Y';
        const auto p = dir / "no_mz";
        WriteBytes(p, buf);
        EXPECT_FALSE(wfh::ReadPeHeaderFacts(p).ok);
    }
    // (c) negative e_lfanew.
    {
        auto buf = make_good();
        const std::uint32_t neg = 0xFFFFFFF0u;  // -16 as signed LONG
        std::memcpy(&buf[0x3C], &neg, 4);
        const auto p = dir / "neg_lfanew";
        WriteBytes(p, buf);
        EXPECT_FALSE(wfh::ReadPeHeaderFacts(p).ok);
    }
    // (d) e_lfanew pointing past EOF.
    {
        auto buf = make_good();
        const std::uint32_t past = 0x10000;  // far beyond 0x200-byte file
        std::memcpy(&buf[0x3C], &past, 4);
        const auto p = dir / "lfanew_past_eof";
        WriteBytes(p, buf);
        EXPECT_FALSE(wfh::ReadPeHeaderFacts(p).ok);
    }
    // (e) "MZ" + valid e_lfanew but no "PE\0\0" signature there.
    {
        auto buf = make_good();
        buf[0x80] = 'N';
        buf[0x81] = 'O';
        const auto p = dir / "no_pe_sig";
        WriteBytes(p, buf);
        EXPECT_FALSE(wfh::ReadPeHeaderFacts(p).ok);
    }
    // (f) PE with Machine != I386 (x86-64).
    {
        auto buf = make_good();
        const std::uint16_t machine = 0x8664;  // AMD64
        std::memcpy(&buf[0x84], &machine, 2);
        const auto p = dir / "wrong_machine";
        WriteBytes(p, buf);
        EXPECT_FALSE(wfh::ReadPeHeaderFacts(p).ok);
    }
    // Positive: minimal well-formed PE32 yields .ok with the expected stamps.
    {
        const auto p = dir / "good";
        WriteBytes(p, make_good());
        const auto r = wfh::ReadPeHeaderFacts(p);
        ASSERT_TRUE(r.ok);
        EXPECT_EQ(r.facts.time_date_stamp, 0x11223344u);
        EXPECT_EQ(r.facts.image_base, 0x00400000u);
        EXPECT_EQ(r.facts.size_of_image, 0x00300000u);
        EXPECT_EQ(r.facts.check_sum, 0x000ABCDEu);
    }

    fs::remove_all(dir);
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
    // Hook-site byte capture (--hook-bytes 16) emits one HookSite per hook_sites.txt
    // entry; the table is non-null with exactly 17 captured sites.
    EXPECT_EQ(wfh::kBinaryManifest.site_count, 17u);
    EXPECT_NE(wfh::kBinaryManifest.sites, nullptr);
    EXPECT_NE(wfh::kBinaryManifest.time_date_stamp, 0u);
    EXPECT_NE(wfh::kBinaryManifest.size_of_image, 0u);
    // Each captured site carries 16 real opening bytes at its fixed VA.
    for (std::uint32_t i = 0; i < wfh::kBinaryManifest.site_count; ++i) {
        EXPECT_EQ(wfh::kBinaryManifest.sites[i].length, 16u);     // NOLINT
        EXPECT_NE(wfh::kBinaryManifest.sites[i].bytes, nullptr);  // NOLINT
    }
}

TEST(PeValidate, HookSitesUnreadableAddressFailsSafe) {
    static const std::uint8_t kExpect[] = {0x00};
    wfh::HookSite site{"bogus", 0x1u, kExpect, 4};  // 0x1 is not a committed readable page
    wfh::BinaryManifest m{0, 0, 0, 0, &site, 1};
    const auto r = wfh::ValidateHookSitesInProcess(m);
    EXPECT_FALSE(r.ok);
    EXPECT_NE(r.error.find("unreadable"), std::string::npos);  // must NOT fault the process
}

TEST(ReadyEvent, NameIsPidKeyedAndStable) {
    // The loader and DLL must build the IDENTICAL per-PID event name for the ready
    // handshake; this pins the exact format both sides depend on.
    EXPECT_EQ(wfh::ReadyEventName(1234), std::wstring(L"Local\\WulfHeadlessReady_1234"));
    EXPECT_EQ(wfh::ReadyEventName(0), std::wstring(L"Local\\WulfHeadlessReady_0"));
    EXPECT_NE(wfh::ReadyEventName(1), wfh::ReadyEventName(2));
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
