#include "wfh/injector.hpp"
#include "wfh/log.hpp"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <filesystem>
#include <iostream>
#include <string>
#include <vector>

namespace {

// Resolve the directory the loader executable itself lives in (cwd-independent),
// mirroring how the DLL's init.cpp resolves its own module directory. Falls back
// to the current path only if GetModuleFileNameW fails outright.
auto ExeDirectory() -> std::filesystem::path {
    std::wstring buffer(MAX_PATH, L'\0');
    for (;;) {
        const DWORD copied =
            GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
        if (copied == 0) {
            return std::filesystem::current_path();
        }
        if (copied < buffer.size()) {
            buffer.resize(copied);
            break;
        }
        buffer.resize(buffer.size() * 2);  // path was truncated; grow and retry
    }
    return std::filesystem::path(buffer).parent_path();
}

}  // namespace

// Loader entry point: parse argv, build an injection plan, then suspended-launch
// the pinned wulfram2.exe and inject wulf_headless.dll. wmain receives wide argv
// so game paths/arguments survive non-ASCII characters.
auto wmain(int argc, wchar_t** argv) -> int {
    // Log next to the loader executable, not the (cwd-dependent) working directory,
    // so the log location is deterministic regardless of how the loader is launched.
    wfh::Log::Init(ExeDirectory() / "logs" / "loader.log", wfh::Level::Debug);

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
