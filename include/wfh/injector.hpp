// NOLINTBEGIN(portability-avoid-pragma-once)
// pragma once is the project-wide include-guard convention; intentional.
#pragma once
// NOLINTEND(portability-avoid-pragma-once)
#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace wfh {

struct LoaderOptions {
    std::filesystem::path loader_path;
    std::filesystem::path game_exe_path;
    std::filesystem::path dll_path;
    std::wstring game_arguments;
};

struct LoaderArgsResult {
    bool ok = false;
    std::wstring error;
    LoaderOptions value;
};

auto ParseLoaderArgs(const std::vector<std::wstring>& args) -> LoaderArgsResult;

struct InjectionPlan {
    std::filesystem::path game_exe_path;
    std::filesystem::path dll_path;
    std::wstring command_line;
};

struct PlanResult {
    bool ok = false;
    std::string error;
    InjectionPlan value;
};
auto CreateInjectionPlan(const LoaderOptions& options) -> PlanResult;

struct LaunchResult {
    bool ok = false;
    std::uint32_t process_id = 0;
    std::string error;
};
// Implemented in Task 4 (injector.cpp). Declared here only.
auto LaunchAndInject(const InjectionPlan& plan) -> LaunchResult;

}  // namespace wfh
