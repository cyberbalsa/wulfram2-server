#include "wfh/injector.hpp"

#include <iterator>

namespace wfh {

namespace {
auto JoinArgs(const std::vector<std::wstring>& args, std::size_t start) -> std::wstring {
    std::wstring out;
    if (start >= args.size()) {
        return out;
    }
    for (auto it = std::next(args.begin(), static_cast<std::ptrdiff_t>(start)); it != args.end();
         ++it) {
        if (!out.empty()) {
            out += L' ';
        }
        out += *it;
    }
    return out;
}
}  // namespace

auto ParseLoaderArgs(const std::vector<std::wstring>& args) -> LoaderArgsResult {
    LoaderArgsResult result;
    if (args.size() < 2) {
        result.error = L"usage: loader.exe <path-to-wulfram2.exe> [game args...]";
        return result;
    }
    result.value.loader_path = std::filesystem::path(args.at(0));
    result.value.game_exe_path = std::filesystem::path(args.at(1));

    std::filesystem::path loader_dir = result.value.loader_path.parent_path();
    if (loader_dir.empty()) {
        loader_dir = std::filesystem::current_path();
    }
    result.value.dll_path = std::filesystem::absolute(loader_dir / L"wulf_headless.dll");
    result.value.game_arguments = JoinArgs(args, 2);
    result.ok = true;
    return result;
}

auto CreateInjectionPlan(const LoaderOptions& options) -> PlanResult {
    PlanResult result;
    if (!std::filesystem::exists(options.game_exe_path)) {
        result.error = "game exe not found";
        return result;
    }
    if (!std::filesystem::exists(options.dll_path)) {
        result.error = "wulf_headless.dll not found beside loader";
        return result;
    }
    result.value.game_exe_path = options.game_exe_path;
    result.value.dll_path = options.dll_path;
    result.value.command_line =
        L"\"" + options.game_exe_path.wstring() + L"\" " + options.game_arguments;
    result.ok = true;
    return result;
}

}  // namespace wfh
