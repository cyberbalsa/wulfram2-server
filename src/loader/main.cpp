#include "wfh/injector.hpp"
#include "wfh/log.hpp"

#include <filesystem>
#include <iostream>
#include <string>
#include <vector>

// Loader entry point: parse argv, build an injection plan, then suspended-launch
// the pinned wulfram2.exe and inject wulf_headless.dll. wmain receives wide argv
// so game paths/arguments survive non-ASCII characters.
auto wmain(int argc, wchar_t** argv) -> int {
    wfh::Log::Init(std::filesystem::current_path() / "logs" / "loader.log", wfh::Level::Debug);

    std::vector<std::wstring> args;
    args.reserve(static_cast<std::size_t>(argc < 0 ? 0 : argc));
    for (int i = 0; i < argc; ++i) {
        // argv is a C array of wide strings; indexed access is the contract of wmain.
        // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        args.emplace_back(argv[i]);
    }

    const auto parsed = wfh::ParseLoaderArgs(args);
    if (!parsed.ok) {
        std::wcerr << parsed.error << L'\n';
        wfh::Log::Shutdown();
        return 2;
    }
    const auto plan = wfh::CreateInjectionPlan(parsed.value);
    if (!plan.ok) {
        std::cerr << "plan failed: " << plan.error << '\n';
        wfh::Log::Shutdown();
        return 2;
    }
    const auto launch = wfh::LaunchAndInject(plan.value);
    if (!launch.ok) {
        std::cerr << "inject failed: " << launch.error << '\n';
        wfh::Log::Shutdown();
        return 1;
    }
    std::wcout << L"headless server started, pid=" << launch.process_id << L'\n';
    wfh::Log::Shutdown();
    return 0;
}
