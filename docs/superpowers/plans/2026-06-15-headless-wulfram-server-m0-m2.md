# Wulfram II Headless Server — Implementation Plan (Milestones 0–2)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stand up the foundation for the headless server — a build system, a verbose logging subsystem, a suspended-inject loader, binary-version pinning, and an address/ABI-binding layer — so that `loader.exe` launches `wulfram2.exe` suspended, confirms it is the exact known binary, injects `wulf_headless.dll`, and the DLL brings up logging on an init thread and validates every hook-site byte, all **before** any head-chop or loop-hijack happens.

**Architecture:** A 32-bit Windows CMake project mirroring `Wulf-Forge/wulfram-lua/`. `loader.exe` does `CreateProcessW(CREATE_SUSPENDED)` → `VirtualAllocEx`/`WriteProcessMemory` → `CreateRemoteThread(LoadLibraryW)` → `ResumeThread`. `wulf_headless.dll` has a minimal `DllMain` that spawns `InitThread`; the thread validates the target binary against a generated manifest, brings up logging, then (in later milestones) installs MinHook detours. A Python generator turns the Ghidra `functions.tsv` export into `addresses.h` (typed function pointers + global offsets) and `binary_manifest.h` (PE stamps + expected bytes at each hook site).

**Tech Stack:** C++17, MSVC (x86/Win32 only), CMake ≥ 3.24 + Ninja, MinHook (FetchContent), Python 3.12 (address generator + pytest), Win32 API (`<windows.h>`, `dbghelp`, Winsock later).

**Scope:** This plan covers **Milestone 0** (toolchain + logging), **Milestone 1** (loader + injection + binary pinning), and **Milestone 2** (address generation + ABI bindings + hook-site self-check). Milestones 3–7 are deferred — see "Deferred Milestones" at the end.

**Source spec:** `docs/superpowers/specs/2026-06-15-headless-wulfram-server-design.md`

---

## File Structure (created by this plan)

```
Wulf_Forge_Headless/
  CMakeLists.txt              # top-level: x86 enforcement, MinHook fetch, targets, flags
  .clang-tidy                # lint ruleset (mirrors wulfram-lua)
  build.ps1                  # vcvars32 + cmake + test runner
  include/wfh/
    log.hpp                  # logging subsystem public API + macros
    pe_validate.hpp          # PE manifest model + validator
    injector.hpp             # loader args + LaunchAndInject
    binary_manifest.hpp      # hand-written struct types used by generated binary_manifest.h
    engine_abi.hpp           # ABI typedef helpers (thiscall/cdecl/stdcall pointer types)
  src/
    log/log.cpp              # logging implementation (file + OutputDebugString + async flush)
    common/pe_validate.cpp   # PE header read + manifest compare + hook-site byte compare
    loader/
      injector.cpp           # CreateProcessW(SUSPENDED)+CreateRemoteThread injection
      loader_args.cpp        # argument parsing + dll path resolution
      main.cpp               # loader.exe entry (wmain)
    dll/
      dllmain.cpp            # minimal DllMain → InitThread
      init.cpp               # InitThread: validate binary, bring up logging, (later) hooks
  gen/
    gen_addresses.py         # functions.tsv -> addresses.h + binary_manifest.h
    addresses.h              # GENERATED (do not edit)
    binary_manifest.h        # GENERATED (do not edit)
  tests/
    test_main.cpp            # C++ unit tests (exception-based, mirrors wulfram-lua)
    test_gen_addresses.py    # pytest for the generator
  config/
    headless.toml            # bind port, map, tick rate, exe path, log level
  logs/                      # runtime log output (gitignored)
```

**Design boundaries:**
- `log` knows nothing about the engine — pure logging.
- `pe_validate` is pure: takes bytes + an expected manifest, returns a result. No injection, no globals.
- `injector` is loader-side only; it never runs in the target.
- `init.cpp` is the only DLL code that touches both logging and (later) hooks; kept thin.
- Generated headers are the single source of truth for addresses/bytes; never hand-edit.

---

## Milestone 0 — Toolchain + Logging Foundation

### Task 0: Repo, CMake skeleton, MinHook fetch, 32-bit enforcement

**Files:**
- Create: `CMakeLists.txt`
- Create: `.clang-tidy`
- Create: `.gitignore`
- Create: `build.ps1`
- Create: `src/dll/dllmain.cpp` (temporary stub so the SHARED target links)
- Create: `tests/test_main.cpp` (empty harness so the test target links)

- [ ] **Step 1: Initialize git**

The project directory is not yet a git repo.

Run:
```bash
cd /c/Users/balsa/desktop/WulframII/Wulf_Forge_Headless
git init
git add docs/
git commit -m "chore: add design spec and implementation plan"
```
Expected: a repo with the spec + this plan committed.

- [ ] **Step 2: Write `.gitignore`**

```gitignore
/build/
/logs/
*.dmp
*.log
__pycache__/
.pytest_cache/
```

- [ ] **Step 3: Write the top-level `CMakeLists.txt`**

```cmake
cmake_minimum_required(VERSION 3.24)
project(wulf_forge_headless LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT WIN32)
    message(FATAL_ERROR "wulf_forge_headless targets Windows; it injects into wulfram2.exe.")
endif()
if(NOT CMAKE_SIZEOF_VOID_P EQUAL 4)
    message(FATAL_ERROR "wulf_forge_headless must be built as x86/Win32 to match wulfram2.exe.")
endif()

option(WFH_STRICT "Treat warnings as errors (/WX)" ON)
option(WFH_ENABLE_CLANG_TIDY "Run clang-tidy during build" OFF)
option(WFH_MSVC_ANALYZE "Enable MSVC /analyze" OFF)

include(FetchContent)
FetchContent_Declare(
    minhook
    GIT_REPOSITORY https://github.com/TsudaKageyu/minhook.git
    GIT_TAG v1.3.3
    GIT_SHALLOW TRUE
)
FetchContent_MakeAvailable(minhook)

# --- our static libraries ---
add_library(wfh_log STATIC src/log/log.cpp)
target_include_directories(wfh_log PUBLIC include)

add_library(wfh_pe STATIC src/common/pe_validate.cpp)
target_include_directories(wfh_pe PUBLIC include gen)

add_library(wfh_loader_core STATIC src/loader/injector.cpp src/loader/loader_args.cpp)
target_include_directories(wfh_loader_core PUBLIC include gen)
target_link_libraries(wfh_loader_core PUBLIC wfh_log wfh_pe)

# --- executables / dll ---
add_executable(loader src/loader/main.cpp)
target_link_libraries(loader PRIVATE wfh_loader_core wfh_log)

add_library(wulf_headless SHARED src/dll/dllmain.cpp src/dll/init.cpp)
target_include_directories(wulf_headless PRIVATE include gen)
target_link_libraries(wulf_headless PRIVATE wfh_log wfh_pe minhook dbghelp)

add_executable(wfh_tests tests/test_main.cpp)
target_link_libraries(wfh_tests PRIVATE wfh_log wfh_pe wfh_loader_core)

set(WFH_TARGETS wfh_log wfh_pe wfh_loader_core loader wulf_headless wfh_tests)

if(MSVC)
    foreach(target ${WFH_TARGETS})
        target_compile_options(${target} PRIVATE
            /W4 /permissive- /sdl /Zc:__cplusplus /Zc:preprocessor
            /Zc:inline /volatile:iso /diagnostics:caret /utf-8)
        if(WFH_STRICT)
            target_compile_options(${target} PRIVATE /WX)
        endif()
        if(WFH_MSVC_ANALYZE)
            target_compile_options(${target} PRIVATE /analyze)
        endif()
    endforeach()
endif()

# MinHook is third-party: do not apply our strict flags to it.
if(MSVC AND TARGET minhook)
    target_compile_options(minhook PRIVATE /W0)
endif()

if(WFH_ENABLE_CLANG_TIDY)
    find_program(CLANG_TIDY_EXE NAMES clang-tidy)
    if(NOT CLANG_TIDY_EXE)
        message(FATAL_ERROR "WFH_ENABLE_CLANG_TIDY is ON but clang-tidy was not found.")
    endif()
    set(CMAKE_CXX_CLANG_TIDY "${CLANG_TIDY_EXE};--warnings-as-errors=*")
endif()
```

- [ ] **Step 4: Write `.clang-tidy`** (mirror `wulfram-lua`)

```yaml
Checks: >
  -*,
  bugprone-*,
  cert-*,
  clang-analyzer-*,
  cppcoreguidelines-*,
  performance-*,
  portability-*,
  readability-*,
  modernize-*
WarningsAsErrors: '*'
HeaderFilterRegex: '.*wfh.*'
FormatStyle: file
CheckOptions:
  - key: readability-identifier-length.MinimumVariableNameLength
    value: '2'
  - key: readability-function-cognitive-complexity.Threshold
    value: '25'
  - key: modernize-use-trailing-return-type.StrictMode
    value: 'false'
```

- [ ] **Step 5: Write temporary stubs so all targets link**

`src/dll/dllmain.cpp`:
```cpp
#include <windows.h>

BOOL APIENTRY DllMain(HMODULE /*module*/, DWORD /*reason*/, LPVOID /*reserved*/) {
    return TRUE;
}
```

`src/dll/init.cpp`:
```cpp
// Placeholder; real InitThread arrives in Task 5/Task 9.
namespace wfh { void init_placeholder() {} }
```

`tests/test_main.cpp`:
```cpp
#include <exception>
#include <iostream>
#include <string>

struct TestFailure : std::exception {
    explicit TestFailure(std::string message) : message_(std::move(message)) {}
    const char* what() const noexcept override { return message_.c_str(); }
    std::string message_;
};

inline void Expect(bool condition, const char* message) {
    if (!condition) throw TestFailure(message);
}

int main() {
    int failures = 0;
    // Tests are registered below in later tasks.
    std::cout << "wfh_tests: " << failures << " failures\n";
    return failures == 0 ? 0 : 1;
}
```

- [ ] **Step 6: Write `build.ps1`** (mirror `wulfram-lua` flow)

```powershell
param(
    [string]$BuildDir = "build",
    [string]$Config = "Debug",
    [switch]$SkipTests,
    [switch]$Strict = $true
)
$ErrorActionPreference = "Stop"
$VcVars = "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars32.bat"
if (-not (Test-Path $VcVars)) { throw "vcvars32.bat not found at $VcVars" }

cmd /c "`"$VcVars`" && cmake -S . -B $BuildDir -G Ninja -DCMAKE_BUILD_TYPE=$Config -DWFH_STRICT=$([int][bool]$Strict)"
if ($LASTEXITCODE -ne 0) { throw "cmake configure failed" }

cmd /c "`"$VcVars`" && cmake --build $BuildDir"
if ($LASTEXITCODE -ne 0) { throw "cmake build failed" }

if (-not $SkipTests) {
    & ".\$BuildDir\wfh_tests.exe"
    if ($LASTEXITCODE -ne 0) { throw "tests failed" }
}
```

- [ ] **Step 7: Configure and build to verify the skeleton compiles**

Run:
```powershell
.\build.ps1 -SkipTests
```
Expected: CMake configures (errors out clearly if not 32-bit), MinHook is fetched, all six targets build. If `vcvars32.bat` path differs, install "Desktop development with C++" (x86) via the VS Installer and adjust the path.

- [ ] **Step 8: Commit**

```bash
git add CMakeLists.txt .clang-tidy .gitignore build.ps1 src/ tests/
git commit -m "build: 32-bit CMake skeleton with MinHook, strict MSVC flags, test harness"
```

---

### Task 1: Logging subsystem — levels, sinks, macros

**Files:**
- Create: `include/wfh/log.hpp`
- Create: `src/log/log.cpp`
- Test: `tests/test_main.cpp` (add cases)

- [ ] **Step 1: Write the failing test**

Add to `tests/test_main.cpp` above `main()`:
```cpp
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
```

Register it inside `main()`'s body (replace the comment) with the harness runner pattern:
```cpp
    struct Case { const char* name; void(*fn)(); };
    const Case cases[] = {
        {"log_writes_to_file_and_respects_level", test_log_writes_to_file_and_respects_level},
    };
    for (const auto& c : cases) {
        try { c.fn(); std::cout << "  ok   " << c.name << "\n"; }
        catch (const std::exception& e) { ++failures; std::cout << "  FAIL " << c.name << ": " << e.what() << "\n"; }
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run:
```powershell
.\build.ps1
```
Expected: compile failure — `wfh/log.hpp` not found / `wfh::Log` undefined.

- [ ] **Step 3: Write `include/wfh/log.hpp`**

```cpp
#pragma once
#include <cstdint>
#include <filesystem>
#include <string>

namespace wfh {

enum class Level : int { Trace = 0, Debug = 1, Info = 2, Warn = 3, Error = 4, Fatal = 5 };

const char* LevelTag(Level level);  // "TRACE".."FATAL"

class Log {
public:
    // Brings up the file sink + OutputDebugString sink and the async flush thread.
    static void Init(const std::filesystem::path& file, Level min_level);
    // Flushes and tears down the flush thread. Safe to call when not initialized.
    static void Shutdown();
    // Sets the active runtime tick counter shown on each line (server loop updates this).
    static void SetTick(std::uint64_t tick);
    static Level MinLevel();
    // printf-style; already filtered by level before formatting.
    static void Write(Level level, const char* category, const char* file, int line,
                      const char* fmt, ...);
};

}  // namespace wfh

// Zero-cost below the active level: the printf args are not evaluated.
#define WFH_LOG(level, category, ...)                                            \
    do {                                                                         \
        if (static_cast<int>(level) >= static_cast<int>(::wfh::Log::MinLevel())) \
            ::wfh::Log::Write((level), (category), __FILE__, __LINE__, __VA_ARGS__); \
    } while (0)

#define WFH_TRACE(cat, ...) WFH_LOG(::wfh::Level::Trace, cat, __VA_ARGS__)
#define WFH_DEBUG(cat, ...) WFH_LOG(::wfh::Level::Debug, cat, __VA_ARGS__)
#define WFH_INFO(cat, ...)  WFH_LOG(::wfh::Level::Info,  cat, __VA_ARGS__)
#define WFH_WARN(cat, ...)  WFH_LOG(::wfh::Level::Warn,  cat, __VA_ARGS__)
#define WFH_ERROR(cat, ...) WFH_LOG(::wfh::Level::Error, cat, __VA_ARGS__)
#define WFH_FATAL(cat, ...) WFH_LOG(::wfh::Level::Fatal, cat, __VA_ARGS__)
```

- [ ] **Step 4: Write `src/log/log.cpp`**

```cpp
#include "wfh/log.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdarg>
#include <cstdio>
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
    std::deque<std::string> queue;
    std::thread worker;
    std::atomic<bool> running{false};
    std::atomic<int> min_level{static_cast<int>(Level::Debug)};
    std::atomic<std::uint64_t> tick{0};
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
    std::snprintf(head, sizeof(head), "[%-5s][%s][t%llu][%s:%d] ",
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
```

- [ ] **Step 5: Run test to verify it passes**

Run:
```powershell
.\build.ps1
```
Expected: `ok log_writes_to_file_and_respects_level`, `wfh_tests: 0 failures`.

- [ ] **Step 6: Commit**

```bash
git add include/wfh/log.hpp src/log/log.cpp tests/test_main.cpp
git commit -m "feat(log): leveled async logging with file + OutputDebugString sinks"
```

---

## Milestone 1 — Loader + Injection + Binary Pinning

### Task 2: Loader argument parsing + DLL path resolution

**Files:**
- Create: `include/wfh/injector.hpp`
- Create: `src/loader/loader_args.cpp`
- Test: `tests/test_main.cpp` (add cases)

- [ ] **Step 1: Write the failing test**

Add to `tests/test_main.cpp`:
```cpp
#include "wfh/injector.hpp"

void test_parse_loader_args_resolves_paths() {
    std::vector<std::wstring> argv = {
        L"C:\\tools\\loader.exe", L"C:\\game\\wulfram2.exe", L"-port", L"2627"};
    const auto r = wfh::ParseLoaderArgs(argv);
    Expect(r.ok, "expected ok parse");
    Expect(r.value.game_exe_path == std::filesystem::path(L"C:\\game\\wulfram2.exe"), "exe path wrong");
    Expect(r.value.dll_path.filename() == std::filesystem::path(L"wulf_headless.dll"), "dll name wrong");
    Expect(r.value.dll_path.parent_path() == std::filesystem::path(L"C:\\tools"), "dll should sit beside loader");
    Expect(r.value.game_arguments == L"-port 2627", "game args join wrong");
}

void test_parse_loader_args_requires_exe() {
    std::vector<std::wstring> argv = {L"loader.exe"};
    const auto r = wfh::ParseLoaderArgs(argv);
    Expect(!r.ok, "expected failure when exe missing");
}
```
Register both in the `cases[]` array.

- [ ] **Step 2: Run to verify it fails**

Run: `.\build.ps1`
Expected: compile failure — `wfh/injector.hpp` not found.

- [ ] **Step 3: Write `include/wfh/injector.hpp`**

```cpp
#pragma once
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

LoaderArgsResult ParseLoaderArgs(const std::vector<std::wstring>& args);

struct InjectionPlan {
    std::filesystem::path game_exe_path;
    std::filesystem::path dll_path;
    std::wstring command_line;
};

struct PlanResult { bool ok = false; std::string error; InjectionPlan value; };
PlanResult CreateInjectionPlan(const LoaderOptions& options);

struct LaunchResult { bool ok = false; std::uint32_t process_id = 0; std::string error; };
// Validates the target binary against the generated manifest BEFORE injecting.
LaunchResult LaunchAndInject(const InjectionPlan& plan);

}  // namespace wfh
```

- [ ] **Step 4: Write `src/loader/loader_args.cpp`**

```cpp
#include "wfh/injector.hpp"

namespace wfh {

namespace {
std::wstring JoinArgs(const std::vector<std::wstring>& args, std::size_t start) {
    std::wstring out;
    for (std::size_t i = start; i < args.size(); ++i) {
        if (!out.empty()) out += L' ';
        out += args[i];
    }
    return out;
}
}  // namespace

LoaderArgsResult ParseLoaderArgs(const std::vector<std::wstring>& args) {
    LoaderArgsResult result;
    if (args.size() < 2) {
        result.error = L"usage: loader.exe <path-to-wulfram2.exe> [game args...]";
        return result;
    }
    result.value.loader_path = std::filesystem::path(args[0]);
    result.value.game_exe_path = std::filesystem::path(args[1]);

    std::filesystem::path loader_dir = result.value.loader_path.parent_path();
    if (loader_dir.empty()) loader_dir = std::filesystem::current_path();
    result.value.dll_path = std::filesystem::absolute(loader_dir / L"wulf_headless.dll");
    result.value.game_arguments = JoinArgs(args, 2);
    result.ok = true;
    return result;
}

PlanResult CreateInjectionPlan(const LoaderOptions& options) {
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
    // Command line: argv[0] must be the exe path itself, then game args.
    result.value.command_line = L"\"" + options.game_exe_path.wstring() + L"\" " + options.game_arguments;
    result.ok = true;
    return result;
}

}  // namespace wfh
```

- [ ] **Step 5: Run to verify it passes**

Run: `.\build.ps1`
Expected: both arg tests `ok`.

- [ ] **Step 6: Commit**

```bash
git add include/wfh/injector.hpp src/loader/loader_args.cpp tests/test_main.cpp
git commit -m "feat(loader): argument parsing and injection-plan construction"
```

---

### Task 3: PE manifest model + validator (pure, testable)

**Files:**
- Create: `include/wfh/pe_validate.hpp`
- Create: `include/wfh/binary_manifest.hpp`
- Create: `src/common/pe_validate.cpp`
- Test: `tests/test_main.cpp` (add cases)

- [ ] **Step 1: Write `include/wfh/binary_manifest.hpp`** (hand-written types the generated header fills)

```cpp
#pragma once
#include <cstdint>

namespace wfh {

// One expected byte signature at a known address (the first bytes of a hooked/called fn).
struct HookSite {
    const char* name;          // e.g. "Client_RunMainLoop"
    std::uint32_t address;     // absolute VA (image base 0x00400000)
    const std::uint8_t* bytes; // expected opening bytes
    std::uint32_t length;      // number of expected bytes
};

// The whole-binary identity manifest, emitted by gen_addresses.py into binary_manifest.h.
struct BinaryManifest {
    std::uint32_t time_date_stamp;  // PE FileHeader.TimeDateStamp
    std::uint32_t size_of_image;    // OptionalHeader.SizeOfImage
    std::uint32_t check_sum;        // OptionalHeader.CheckSum
    std::uint32_t image_base;       // expected 0x00400000
    const HookSite* sites;
    std::uint32_t site_count;
};

}  // namespace wfh
```

- [ ] **Step 2: Write the failing test**

Add to `tests/test_main.cpp`:
```cpp
#include "wfh/pe_validate.hpp"

void test_validate_headers_matches_and_detects_mismatch() {
    wfh::PeHeaderFacts facts;
    facts.time_date_stamp = 0x12345678;
    facts.size_of_image = 0x00300000;
    facts.check_sum = 0x000ABCDE;
    facts.image_base = 0x00400000;

    wfh::BinaryManifest good{0x12345678, 0x00300000, 0x000ABCDE, 0x00400000, nullptr, 0};
    Expect(wfh::ValidateHeaders(facts, good).ok, "identical headers must validate");

    wfh::BinaryManifest bad = good;
    bad.time_date_stamp = 0xDEADBEEF;
    const auto r = wfh::ValidateHeaders(facts, bad);
    Expect(!r.ok, "different timestamp must fail");
    Expect(r.error.find("TimeDateStamp") != std::string::npos, "error should name the field");
}

void test_validate_hook_site_bytes() {
    const std::uint8_t mem[] = {0x55, 0x8B, 0xEC, 0x83, 0xEC};       // what's "in memory"
    const std::uint8_t expect_ok[] = {0x55, 0x8B, 0xEC};
    const std::uint8_t expect_bad[] = {0x55, 0x90, 0xEC};
    Expect(wfh::CompareBytes(mem, expect_ok, 3).ok, "matching prefix should pass");
    Expect(!wfh::CompareBytes(mem, expect_bad, 3).ok, "differing byte should fail");
}
```
Register both.

- [ ] **Step 3: Run to verify it fails**

Run: `.\build.ps1`
Expected: compile failure — `wfh/pe_validate.hpp` not found.

- [ ] **Step 4: Write `include/wfh/pe_validate.hpp`**

```cpp
#pragma once
#include <cstdint>
#include <filesystem>
#include <string>

#include "wfh/binary_manifest.hpp"

namespace wfh {

struct PeHeaderFacts {
    std::uint32_t time_date_stamp = 0;
    std::uint32_t size_of_image = 0;
    std::uint32_t check_sum = 0;
    std::uint32_t image_base = 0;
};

struct ValidateResult { bool ok = false; std::string error; };

// Parse the PE headers of an on-disk file (loader-side, pre-launch).
struct ReadFactsResult { bool ok = false; std::string error; PeHeaderFacts facts; };
ReadFactsResult ReadPeHeaderFacts(const std::filesystem::path& exe_path);

// Pure comparisons (no I/O) — unit-testable.
ValidateResult ValidateHeaders(const PeHeaderFacts& actual, const BinaryManifest& expected);
ValidateResult CompareBytes(const std::uint8_t* actual, const std::uint8_t* expected,
                            std::uint32_t length);

// In-process (DLL-side): verify every manifest hook-site's opening bytes in live memory.
ValidateResult ValidateHookSitesInProcess(const BinaryManifest& manifest);

}  // namespace wfh
```

- [ ] **Step 5: Write `src/common/pe_validate.cpp`**

```cpp
#include "wfh/pe_validate.hpp"

#include <cstring>
#include <fstream>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

namespace wfh {

ReadFactsResult ReadPeHeaderFacts(const std::filesystem::path& exe_path) {
    ReadFactsResult out;
    std::ifstream in(exe_path, std::ios::binary);
    if (!in) { out.error = "cannot open exe"; return out; }
    std::vector<char> buf((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    if (buf.size() < sizeof(IMAGE_DOS_HEADER)) { out.error = "file too small"; return out; }

    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(buf.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) { out.error = "not a DOS image"; return out; }
    const std::size_t nt_off = static_cast<std::size_t>(dos->e_lfanew);
    if (nt_off + sizeof(IMAGE_NT_HEADERS32) > buf.size()) { out.error = "bad e_lfanew"; return out; }

    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS32*>(buf.data() + nt_off);
    if (nt->Signature != IMAGE_NT_SIGNATURE) { out.error = "not a PE image"; return out; }
    if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_I386) { out.error = "not an x86 image"; return out; }

    out.facts.time_date_stamp = nt->FileHeader.TimeDateStamp;
    out.facts.size_of_image = nt->OptionalHeader.SizeOfImage;
    out.facts.check_sum = nt->OptionalHeader.CheckSum;
    out.facts.image_base = nt->OptionalHeader.ImageBase;
    out.ok = true;
    return out;
}

ValidateResult ValidateHeaders(const PeHeaderFacts& a, const BinaryManifest& e) {
    if (a.time_date_stamp != e.time_date_stamp)
        return {false, "PE TimeDateStamp mismatch (wrong wulfram2.exe build)"};
    if (a.size_of_image != e.size_of_image)
        return {false, "PE SizeOfImage mismatch"};
    if (a.check_sum != e.check_sum)
        return {false, "PE CheckSum mismatch"};
    if (a.image_base != e.image_base)
        return {false, "PE ImageBase mismatch (relocation?)"};
    return {true, {}};
}

ValidateResult CompareBytes(const std::uint8_t* actual, const std::uint8_t* expected,
                            std::uint32_t length) {
    if (std::memcmp(actual, expected, length) != 0)
        return {false, "hook-site byte mismatch"};
    return {true, {}};
}

ValidateResult ValidateHookSitesInProcess(const BinaryManifest& manifest) {
    for (std::uint32_t i = 0; i < manifest.site_count; ++i) {
        const HookSite& site = manifest.sites[i];
        const auto* mem = reinterpret_cast<const std::uint8_t*>(static_cast<std::uintptr_t>(site.address));
        const auto r = CompareBytes(mem, site.bytes, site.length);
        if (!r.ok) {
            std::string err = "hook-site mismatch at ";
            err += site.name ? site.name : "?";
            return {false, err};
        }
    }
    return {true, {}};
}

}  // namespace wfh
```

- [ ] **Step 6: Run to verify it passes**

Run: `.\build.ps1`
Expected: both PE tests `ok`.

- [ ] **Step 7: Commit**

```bash
git add include/wfh/pe_validate.hpp include/wfh/binary_manifest.hpp src/common/pe_validate.cpp tests/test_main.cpp
git commit -m "feat(pe): pure PE-header + hook-site byte validation"
```

---

### Task 4: Injector — suspended launch, binary pre-check, inject, resume

**Files:**
- Create: `src/loader/injector.cpp`
- Create: `src/loader/main.cpp`
- (Note: full injection is verified at integration time in Task 9; this task builds it and unit-tests the parts that don't require a live process.)

- [ ] **Step 1: Write `src/loader/injector.cpp`** (adapted from the proven `wulfram-lua` `LaunchAndInject`, with a binary pre-check added)

```cpp
#include "wfh/injector.hpp"
#include "wfh/pe_validate.hpp"
#include "wfh/log.hpp"

#include <string>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "binary_manifest.h"  // generated; provides wfh::kBinaryManifest

namespace wfh {
namespace {

std::string LastErrorMessage(const char* api) {
    const DWORD code = GetLastError();
    char buf[256] = {0};
    FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, nullptr, code,
                   0, buf, sizeof(buf), nullptr);
    return std::string(api) + " failed (" + std::to_string(code) + "): " + buf;
}

void CloseProcessInfo(PROCESS_INFORMATION& pi) {
    if (pi.hThread) CloseHandle(pi.hThread);
    if (pi.hProcess) CloseHandle(pi.hProcess);
}

}  // namespace

LaunchResult LaunchAndInject(const InjectionPlan& plan) {
    // --- Binary pinning gate (loader side): refuse the wrong build before we touch it. ---
    const auto facts = ReadPeHeaderFacts(plan.game_exe_path);
    if (!facts.ok) {
        WFH_FATAL("loader", "cannot read PE headers: %s", facts.error.c_str());
        return {false, 0, facts.error};
    }
    const auto headers_ok = ValidateHeaders(facts.facts, kBinaryManifest);
    if (!headers_ok.ok) {
        WFH_FATAL("loader", "binary pinning failed: %s", headers_ok.error.c_str());
        return {false, 0, headers_ok.error};
    }
    WFH_INFO("loader", "binary pinning OK (stamp=%08x size=%08x)",
             facts.facts.time_date_stamp, facts.facts.size_of_image);

    STARTUPINFOW si{}; si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    std::vector<wchar_t> cmd(plan.command_line.begin(), plan.command_line.end());
    cmd.push_back(L'\0');

    const std::filesystem::path work_dir = plan.game_exe_path.parent_path();
    const BOOL created = CreateProcessW(
        plan.game_exe_path.c_str(), cmd.data(), nullptr, nullptr, FALSE,
        CREATE_SUSPENDED, nullptr,
        work_dir.empty() ? nullptr : work_dir.c_str(), &si, &pi);
    if (!created) return {false, 0, LastErrorMessage("CreateProcessW")};
    WFH_INFO("loader", "created suspended pid=%lu", pi.dwProcessId);

    const std::wstring dll = plan.dll_path.wstring();
    const SIZE_T bytes = (dll.size() + 1) * sizeof(wchar_t);
    LPVOID remote = VirtualAllocEx(pi.hProcess, nullptr, bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote) { auto e = LastErrorMessage("VirtualAllocEx"); TerminateProcess(pi.hProcess,1); CloseProcessInfo(pi); return {false,0,e}; }

    SIZE_T wrote = 0;
    if (!WriteProcessMemory(pi.hProcess, remote, dll.c_str(), bytes, &wrote) || wrote != bytes) {
        auto e = LastErrorMessage("WriteProcessMemory");
        VirtualFreeEx(pi.hProcess, remote, 0, MEM_RELEASE); TerminateProcess(pi.hProcess,1); CloseProcessInfo(pi);
        return {false,0,e};
    }

    HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
    auto* load = reinterpret_cast<LPTHREAD_START_ROUTINE>(GetProcAddress(k32, "LoadLibraryW"));
    if (!load) { auto e = LastErrorMessage("GetProcAddress(LoadLibraryW)"); VirtualFreeEx(pi.hProcess,remote,0,MEM_RELEASE); TerminateProcess(pi.hProcess,1); CloseProcessInfo(pi); return {false,0,e}; }

    HANDLE thr = CreateRemoteThread(pi.hProcess, nullptr, 0, load, remote, 0, nullptr);
    if (!thr) { auto e = LastErrorMessage("CreateRemoteThread"); VirtualFreeEx(pi.hProcess,remote,0,MEM_RELEASE); TerminateProcess(pi.hProcess,1); CloseProcessInfo(pi); return {false,0,e}; }

    WaitForSingleObject(thr, INFINITE);
    DWORD remote_exit = 0; GetExitCodeThread(thr, &remote_exit); CloseHandle(thr);
    VirtualFreeEx(pi.hProcess, remote, 0, MEM_RELEASE);
    if (remote_exit == 0) { TerminateProcess(pi.hProcess,1); CloseProcessInfo(pi); return {false,0,"remote LoadLibraryW returned null"}; }
    WFH_INFO("loader", "injected wulf_headless.dll");

    ResumeThread(pi.hThread);
    const DWORD id = pi.dwProcessId;
    CloseProcessInfo(pi);
    return {true, id, {}};
}

}  // namespace wfh
```

- [ ] **Step 2: Write `src/loader/main.cpp`**

```cpp
#include "wfh/injector.hpp"
#include "wfh/log.hpp"

#include <filesystem>
#include <iostream>
#include <vector>

int wmain(int argc, wchar_t** argv) {
    wfh::Log::Init(std::filesystem::current_path() / "logs" / "loader.log", wfh::Level::Debug);

    std::vector<std::wstring> args;
    for (int i = 0; i < argc; ++i) args.emplace_back(argv[i]);

    const auto parsed = wfh::ParseLoaderArgs(args);
    if (!parsed.ok) { std::wcerr << parsed.error << L'\n'; wfh::Log::Shutdown(); return 2; }

    const auto plan = wfh::CreateInjectionPlan(parsed.value);
    if (!plan.ok) { std::cerr << "plan failed: " << plan.error << '\n'; wfh::Log::Shutdown(); return 2; }

    const auto launch = wfh::LaunchAndInject(plan.value);
    if (!launch.ok) { std::cerr << "inject failed: " << launch.error << '\n'; wfh::Log::Shutdown(); return 1; }

    std::wcout << L"headless server started, pid=" << launch.process_id << L'\n';
    wfh::Log::Shutdown();
    return 0;
}
```

- [ ] **Step 3: Build (cannot fully run yet — needs generated `binary_manifest.h` from Task 5)**

Run: `.\build.ps1 -SkipTests`
Expected: this will **fail to compile** with `cannot open binary_manifest.h` because the generated header does not exist yet. That's expected — Task 5 generates it. Do not fix by hand-writing the header.

- [ ] **Step 4: Commit (work-in-progress is fine; the generator in Task 5 unblocks the build)**

```bash
git add src/loader/injector.cpp src/loader/main.cpp
git commit -m "feat(loader): suspended-inject with binary-pinning gate (needs generated manifest)"
```

---

## Milestone 2 — Address Generation + ABI Bindings + Hook-Site Self-Check

### Task 5: `gen_addresses.py` — functions.tsv → addresses.h + binary_manifest.h

**Files:**
- Create: `gen/gen_addresses.py`
- Create: `tests/test_gen_addresses.py`
- Generates: `gen/addresses.h`, `gen/binary_manifest.h`

**Inputs:** `../Wulf-Forge/reverseengineering/programs/wulfram2.exe/functions.tsv` (address source of truth) and the live `wulfram2.exe` (for PE stamps + hook-site bytes). For determinism the generator reads the exe path and a curated list of "wanted" function names from a small TOML/JSON config so the header only contains what we use.

- [ ] **Step 1: Write the failing pytest**

`tests/test_gen_addresses.py`:
```python
import subprocess, sys, struct, pathlib, textwrap

GEN = pathlib.Path(__file__).resolve().parents[1] / "gen" / "gen_addresses.py"

def make_min_pe(path):
    # Minimal but valid-enough PE32 for header parsing: DOS stub + NT headers.
    e_lfanew = 0x80
    dos = bytearray(0x100)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, e_lfanew)
    nt = bytearray()
    nt += b"PE\x00\x00"
    # FileHeader: Machine=0x14C (i386), NumSections=1, TimeDateStamp=0x11223344, ...
    nt += struct.pack("<HHIIIHH", 0x14C, 1, 0x11223344, 0, 0, 0xE0, 0x0102)
    # OptionalHeader (PE32): Magic=0x10B ... ImageBase=0x400000 ... SizeOfImage=0x300000 ... CheckSum
    opt = bytearray(0xE0)
    struct.pack_into("<H", opt, 0, 0x10B)
    struct.pack_into("<I", opt, 28, 0x00400000)   # ImageBase
    struct.pack_into("<I", opt, 56, 0x00300000)   # SizeOfImage
    struct.pack_into("<I", opt, 64, 0x000ABCDE)   # CheckSum
    nt += opt
    blob = dos + nt
    path.write_bytes(blob)

def test_generates_headers(tmp_path):
    tsv = tmp_path / "functions.tsv"
    tsv.write_text("name\taddress\nClient_RunMainLoop\t0x004a0aa0\nSnd_InitDevice\t0x00489fb0\n")
    exe = tmp_path / "wulfram2.exe"; make_min_pe(exe)
    cfg = tmp_path / "wanted.txt"
    cfg.write_text("Client_RunMainLoop\nSnd_InitDevice\n")
    out_dir = tmp_path / "out"; out_dir.mkdir()

    r = subprocess.run([sys.executable, str(GEN),
                        "--tsv", str(tsv), "--exe", str(exe),
                        "--wanted", str(cfg), "--out", str(out_dir),
                        "--hook-bytes", "0"],  # 0 = skip live byte read for unit test
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr

    addr = (out_dir / "addresses.h").read_text()
    assert "0x004a0aa0" in addr.lower()
    assert "Client_RunMainLoop" in addr

    manifest = (out_dir / "binary_manifest.h").read_text()
    assert "0x11223344" in manifest.lower()   # TimeDateStamp
    assert "0x00300000" in manifest.lower()   # SizeOfImage
    assert "kBinaryManifest" in manifest
```

- [ ] **Step 2: Run to verify it fails**

Run:
```powershell
python -m pytest tests/test_gen_addresses.py -v
```
Expected: FAIL — `gen/gen_addresses.py` does not exist.

- [ ] **Step 3: Write `gen/gen_addresses.py`**

```python
#!/usr/bin/env python3
"""Generate addresses.h and binary_manifest.h from the Ghidra functions.tsv export.

addresses.h:        typed function-pointer constants + global offsets we actually use.
binary_manifest.h:  PE identity (TimeDateStamp/SizeOfImage/CheckSum/ImageBase) plus the
                    expected opening bytes at each hook site, for binary pinning.
"""
import argparse, pathlib, struct, sys

def read_pe_facts(exe: pathlib.Path):
    blob = exe.read_bytes()
    e_lfanew = struct.unpack_from("<I", blob, 0x3C)[0]
    assert blob[e_lfanew:e_lfanew + 4] == b"PE\x00\x00", "not a PE"
    # FileHeader starts at e_lfanew+4: Machine(H) Sections(H) TimeDateStamp(I) ...
    time_date_stamp = struct.unpack_from("<I", blob, e_lfanew + 8)[0]
    opt = e_lfanew + 24  # OptionalHeader
    image_base = struct.unpack_from("<I", blob, opt + 28)[0]
    size_of_image = struct.unpack_from("<I", blob, opt + 56)[0]
    check_sum = struct.unpack_from("<I", blob, opt + 64)[0]
    return dict(time_date_stamp=time_date_stamp, size_of_image=size_of_image,
                check_sum=check_sum, image_base=image_base)

def read_functions(tsv: pathlib.Path):
    out = {}
    for i, line in enumerate(tsv.read_text().splitlines()):
        if i == 0 and line.lower().startswith("name"):
            continue
        if not line.strip():
            continue
        name, addr = line.split("\t")[:2]
        out[name.strip()] = int(addr, 16)
    return out

def read_site_bytes(exe_facts, funcs, names, count):
    # count==0 → skip (unit test). Real runs read the section bytes from the exe on disk
    # by RVA; for simplicity here we read from the live process is NOT done — disk read by
    # file offset requires section mapping, added when count>0 in the real binary.
    return {}  # populated for real binary in Task 6 follow-up; unit test passes count=0

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tsv", required=True, type=pathlib.Path)
    ap.add_argument("--exe", required=True, type=pathlib.Path)
    ap.add_argument("--wanted", required=True, type=pathlib.Path)
    ap.add_argument("--out", required=True, type=pathlib.Path)
    ap.add_argument("--hook-bytes", type=int, default=16,
                    help="bytes to capture per hook site; 0 to skip")
    args = ap.parse_args()

    facts = read_pe_facts(args.exe)
    funcs = read_functions(args.tsv)
    wanted = [w.strip() for w in args.wanted.read_text().splitlines() if w.strip()]

    missing = [w for w in wanted if w not in funcs]
    if missing:
        print("ERROR: wanted functions not in tsv: " + ", ".join(missing), file=sys.stderr)
        return 2

    # --- addresses.h ---
    lines = ["// GENERATED by gen_addresses.py — DO NOT EDIT", "#pragma once",
             "#include <cstdint>", "", "namespace wfh {", "namespace addr {", ""]
    for name in wanted:
        lines.append(f"constexpr std::uint32_t {name} = 0x{funcs[name]:08x};")
    lines += ["", "}  // namespace addr", "}  // namespace wfh", ""]
    (args.out / "addresses.h").write_text("\n".join(lines))

    # --- binary_manifest.h ---
    site_bytes = read_site_bytes(facts, funcs, wanted, args.hook_bytes)
    m = ["// GENERATED by gen_addresses.py — DO NOT EDIT", "#pragma once",
         '#include "wfh/binary_manifest.hpp"', "", "namespace wfh {", ""]
    site_count = 0
    if site_bytes:
        for name, bs in site_bytes.items():
            arr = ", ".join(f"0x{b:02x}" for b in bs)
            m.append(f"static const std::uint8_t kSite_{name}[] = {{ {arr} }};")
        m.append("")
        m.append("static const HookSite kSites[] = {")
        for name in site_bytes:
            m.append(f'    {{ "{name}", 0x{funcs[name]:08x}, kSite_{name}, '
                     f'sizeof(kSite_{name}) }},')
        m.append("};")
        site_count = len(site_bytes)
    else:
        m.append("static const HookSite* kSites = nullptr;")

    m += ["",
          "inline constexpr BinaryManifest kBinaryManifest = {",
          f"    0x{facts['time_date_stamp']:08x},  // time_date_stamp",
          f"    0x{facts['size_of_image']:08x},  // size_of_image",
          f"    0x{facts['check_sum']:08x},  // check_sum",
          f"    0x{facts['image_base']:08x},  // image_base",
          "    kSites,",
          f"    {site_count},",
          "};", "", "}  // namespace wfh", ""]
    (args.out / "binary_manifest.h").write_text("\n".join(m))
    print("generated addresses.h and binary_manifest.h")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
```

- [ ] **Step 4: Run pytest to verify it passes**

Run:
```powershell
python -m pytest tests/test_gen_addresses.py -v
```
Expected: PASS.

- [ ] **Step 5: Generate the real headers from the actual binary + TSV**

Create `gen/wanted.txt` with the Milestone-0/1 functions we already reference (loop seam + one head seam, expand later):
```
Client_RunMainLoop
Snd_InitDevice
```

Run:
```powershell
python gen/gen_addresses.py `
  --tsv "..\Wulf-Forge\reverseengineering\programs\wulfram2.exe\functions.tsv" `
  --exe "..\Game\wulfram2.exe" `
  --wanted gen\wanted.txt --out gen --hook-bytes 16
```
Expected: `gen/addresses.h` and `gen/binary_manifest.h` written with the real PE stamps. (If `--hook-bytes 16` errors because section-by-RVA byte reading isn't implemented yet, run with `--hook-bytes 0` and capture site bytes in the Task 6 follow-up.)

- [ ] **Step 6: Build the loader now that the manifest exists**

Run: `.\build.ps1 -SkipTests`
Expected: `loader` and `wulf_headless` compile (injector.cpp finds `binary_manifest.h`).

- [ ] **Step 7: Commit**

```bash
git add gen/gen_addresses.py gen/wanted.txt gen/addresses.h gen/binary_manifest.h tests/test_gen_addresses.py
git commit -m "feat(gen): functions.tsv -> addresses.h + binary_manifest.h with pytest"
```

---

### Task 6: ABI-correct binding typedefs + static_assert

**Files:**
- Create: `include/wfh/engine_abi.hpp`
- Test: `tests/test_main.cpp` (compile-time `static_assert` + a tiny runtime check)

- [ ] **Step 1: Write the failing test**

Add to `tests/test_main.cpp`:
```cpp
#include "wfh/engine_abi.hpp"
#include "addresses.h"

void test_engine_abi_typedefs_resolve() {
    // The function-pointer typedefs must be constructible from the generated addresses.
    auto run_main_loop = wfh::abi::Fn<void>::At(wfh::addr::Client_RunMainLoop);
    Expect(run_main_loop != nullptr, "Client_RunMainLoop ptr should be non-null");
    // We do NOT call it here (no live engine in the test process).
}
```
Register it.

- [ ] **Step 2: Run to verify it fails**

Run: `.\build.ps1`
Expected: compile failure — `wfh/engine_abi.hpp` not found.

- [ ] **Step 3: Write `include/wfh/engine_abi.hpp`**

```cpp
#pragma once
#include <cstdint>

// ABI-correct binding helpers for calling wulfram2.exe's own functions by absolute address.
// 32-bit MSVC calling conventions are explicit so the compiler emits the right call/cleanup:
//   __cdecl    : caller cleans the stack
//   __stdcall  : callee cleans the stack
//   __thiscall : `this` in ECX, callee cleans the stack (for C++ member functions)
namespace wfh {
namespace abi {

template <typename Ret, typename... Args>
struct Cdecl {
    using Ptr = Ret(__cdecl*)(Args...);
    static Ptr At(std::uint32_t address) { return reinterpret_cast<Ptr>(static_cast<std::uintptr_t>(address)); }
};

template <typename Ret, typename... Args>
struct Stdcall {
    using Ptr = Ret(__stdcall*)(Args...);
    static Ptr At(std::uint32_t address) { return reinterpret_cast<Ptr>(static_cast<std::uintptr_t>(address)); }
};

template <typename Ret, typename... Args>
struct Thiscall {
    using Ptr = Ret(__thiscall*)(Args...);
    static Ptr At(std::uint32_t address) { return reinterpret_cast<Ptr>(static_cast<std::uintptr_t>(address)); }
};

// Convenience alias for the common __cdecl/no-arg case used in smoke checks.
template <typename Ret>
using Fn = Cdecl<Ret>;

}  // namespace abi
}  // namespace wfh
```

- [ ] **Step 4: Run to verify it passes**

Run: `.\build.ps1`
Expected: `ok engine_abi_typedefs_resolve`.

- [ ] **Step 5: Commit**

```bash
git add include/wfh/engine_abi.hpp tests/test_main.cpp
git commit -m "feat(abi): explicit cdecl/stdcall/thiscall binding typedefs by absolute address"
```

---

### Task 7: Minimal DllMain + InitThread with binary self-check

**Files:**
- Modify: `src/dll/dllmain.cpp`
- Modify: `src/dll/init.cpp`
- Create: `include/wfh/init.hpp`

- [ ] **Step 1: Write `include/wfh/init.hpp`**

```cpp
#pragma once
#include <windows.h>

namespace wfh {
// Worker started off the loader lock; safe place to log / hook / validate.
DWORD WINAPI InitThread(LPVOID module_handle);
}  // namespace wfh
```

- [ ] **Step 2: Replace `src/dll/dllmain.cpp` with the minimal stub**

```cpp
#include "wfh/init.hpp"

#include <windows.h>

// MINIMAL: runs under the loader lock. No hooks, no LoadLibrary, no logging backend,
// no synchronization primitives here (Codex finding: doing so deadlocks the loader lock).
BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID /*reserved*/) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(module);
        const HANDLE thread = CreateThread(nullptr, 0, wfh::InitThread, module, 0, nullptr);
        if (thread) CloseHandle(thread);
    }
    return TRUE;
}
```

- [ ] **Step 3: Replace `src/dll/init.cpp` with the real init thread**

```cpp
#include "wfh/init.hpp"
#include "wfh/log.hpp"
#include "wfh/pe_validate.hpp"

#include <filesystem>

#include <windows.h>

#include "binary_manifest.h"  // generated; wfh::kBinaryManifest

namespace wfh {

DWORD WINAPI InitThread(LPVOID module_handle) {
    // 1. Logging up first (off the loader lock, so file/thread ops are safe now).
    wchar_t path[MAX_PATH] = {0};
    GetModuleFileNameW(static_cast<HMODULE>(module_handle), path, MAX_PATH);
    const std::filesystem::path dll_dir = std::filesystem::path(path).parent_path();
    Log::Init(dll_dir / "logs" / "headless.log", Level::Debug);
    WFH_INFO("init", "InitThread alive; logging up");

    // 2. Binary self-check: confirm we are inside the exact known wulfram2.exe build.
    //    (Header facts are validated loader-side; here we verify hook-site bytes in memory.)
    const auto sites_ok = ValidateHookSitesInProcess(kBinaryManifest);
    if (!sites_ok.ok) {
        WFH_FATAL("init", "hook-site self-check failed: %s — aborting", sites_ok.error.c_str());
        Log::Shutdown();
        ExitProcess(0x5746);  // 'WF'
    }
    WFH_INFO("init", "hook-site self-check OK (%u sites)", kBinaryManifest.site_count);

    // 3. (Milestone 3+) MinHook init + head-seam detours + loop hijack go here.
    WFH_INFO("init", "foundation ready; head-chop deferred to Milestone 3");
    return 0;
}

}  // namespace wfh
```

- [ ] **Step 4: Build**

Run: `.\build.ps1`
Expected: all targets compile and unit tests pass. (`ValidateHookSitesInProcess` with a null `kSites`/`site_count==0` returns ok, which is fine until Task 5 captures real site bytes.)

- [ ] **Step 5: Commit**

```bash
git add include/wfh/init.hpp src/dll/dllmain.cpp src/dll/init.cpp
git commit -m "feat(dll): minimal DllMain + InitThread with logging and hook-site self-check"
```

---

### Task 8: Config file + wire log level

**Files:**
- Create: `config/headless.toml`
- Modify: `src/dll/init.cpp` (read log level/exe from config if present)

- [ ] **Step 1: Write `config/headless.toml`**

```toml
# Wulfram II headless server config
[server]
bind_port = 2627        # matches the client default (0xa43)
tick_hz = 20            # fixed-timestep rate (Milestone 4)
map = "arena_city"

[log]
level = "debug"         # trace|debug|info|warn|error|fatal

[paths]
# Optional explicit path; loader CLI arg overrides this.
wulfram2_exe = "..\\Game\\wulfram2.exe"
```

- [ ] **Step 2: Add a tiny TOML-less reader (one key we need now: log level)**

Add to `src/dll/init.cpp`, before `Log::Init`, a minimal line scan (avoid a TOML dep for one value):
```cpp
    Level level = Level::Debug;
    {
        std::ifstream cfg(dll_dir / "config" / "headless.toml");
        std::string line;
        while (std::getline(cfg, line)) {
            if (line.find("level") != std::string::npos) {
                if (line.find("trace") != std::string::npos) level = Level::Trace;
                else if (line.find("info") != std::string::npos) level = Level::Info;
                else if (line.find("warn") != std::string::npos) level = Level::Warn;
                else if (line.find("error") != std::string::npos) level = Level::Error;
                else level = Level::Debug;
                break;
            }
        }
    }
```
And change `Log::Init(dll_dir / "logs" / "headless.log", Level::Debug);` to use `level`. Add `#include <fstream>` and `#include <string>`.

- [ ] **Step 3: Build**

Run: `.\build.ps1`
Expected: compiles, tests pass.

- [ ] **Step 4: Commit**

```bash
git add config/headless.toml src/dll/init.cpp
git commit -m "feat(config): headless.toml with runtime log level wired into InitThread"
```

---

### Task 9: Integration smoke test (manual, against the real binary)

**Files:** none (manual verification + a recorded result note).

- [ ] **Step 1: Capture real hook-site bytes into the manifest**

Re-run the generator pointing at the real binary with byte capture on (extend `read_site_bytes` to read by file offset via section mapping if `--hook-bytes 16` was skipped earlier; the function is stubbed for the unit test but must read real bytes for production). Verify `gen/binary_manifest.h` now lists `kSite_Client_RunMainLoop` with 16 bytes and `site_count >= 1`.

Run: `.\build.ps1 -SkipTests`
Expected: rebuilds with the populated manifest.

- [ ] **Step 2: Run the loader against the real game (headless smoke)**

Copy `wulf_headless.dll`, `config/`, and `gen/`-derived headers' runtime outputs beside `loader.exe` (the build already places the DLL next to the loader in `build/`). Then:

Run:
```powershell
.\build\loader.exe "..\Game\wulfram2.exe" -windowed
```
Expected behavior to verify in `build/logs/headless.log` and DebugView:
- `loader`: "binary pinning OK", "created suspended pid=…", "injected wulf_headless.dll".
- `init`: "InitThread alive", "hook-site self-check OK (N sites)", "foundation ready; head-chop deferred".

Because no head-chop or loop-hijack exists yet, the real client will continue to boot normally (it may open its window). That is expected at this milestone — we have only proven injection + pinning + self-check + logging, not the chop.

- [ ] **Step 3: Negative test — wrong binary is rejected**

Point the loader at any other exe (e.g. `..\Game\wvp.exe`):
```powershell
.\build\loader.exe "..\Game\wvp.exe"
```
Expected: loader exits non-zero with "binary pinning failed: PE TimeDateStamp mismatch" in `logs/loader.log`, and the process is **not** launched.

- [ ] **Step 4: Record the result and commit a short run note**

Create `docs/superpowers/notes/2026-06-15-m0-m2-smoke.md` with the observed log excerpts (pinning OK, self-check OK, wrong-binary rejected), then:
```bash
git add docs/superpowers/notes/2026-06-15-m0-m2-smoke.md
git commit -m "docs: M0-M2 integration smoke results (inject + pin + self-check)"
```

---

## Self-Review (against the spec)

**Spec coverage for M0–M2:**
- Toolchain + `/W4 /WX` + clang-tidy + MinHook fetch → Task 0. ✓
- Logging subsystem (levels, file + OutputDebugString, async, macros, FILE:LINE + tick) → Tasks 1, 8. ✓
- Loader: `CREATE_SUSPENDED` → inject → resume → Task 4. ✓
- `DllMain` minimal stub + `InitThread` (loader-lock deadlock avoidance) → Task 7. ✓
- Binary pinning (PE stamps loader-side + hook-site bytes in-process) → Tasks 3, 4, 5, 7, 9. ✓
- `gen_addresses.py` → `addresses.h` + `binary_manifest.h` with pytest → Task 5. ✓
- ABI-correct typedefs (`__thiscall`/`__cdecl`/`__stdcall`) → Task 6. ✓
- Crash diagnostics minidump (`dbghelp`) — linked in CMake (Task 0); **the unhandled-exception filter + `MiniDumpWriteDump` install lands in Milestone 4** with the SEH boundary (noted, not a placeholder).

**Known deferral (documented, not a gap):** real hook-site byte capture by file-offset/RVA in `gen_addresses.py` is stubbed for the unit test (`--hook-bytes 0`) and completed for the real binary in Task 9 Step 1.

---

## Deferred Milestones (separate plans, written when preconditions land)

Each gets its own `docs/superpowers/plans/` file because each depends on runtime discoveries from the milestone before it. Entry criteria:

- **M3 — Head chop.** Precondition: M0–M2 green; loader injects and self-check passes. Work: detour the 12 confirmed `*_Init` seams to logged no-ops returning **minimal valid objects**; add hidden message-pump if any init needs an `HWND`; boot trace must show the full body-init chain runs with **zero access violations** and reaches the loop seam with no window/GPU/audio. Discovery needed: each seam's required success return value; whether any kept body-init derefs a head global.
- **M4 — Loop hijack + fixed timestep + SEH.** Detour `Client_RunMainLoop`; fixed-timestep accumulator (clamped delta); install the `__try/__except` + breadcrumb + `MiniDumpWriteDump` unhandled-exception filter.
- **M5 — Net object + sessions.** Precondition: full reverse of the `Net` connection object layout (offsets `+0x18/+0x24/+0x30…`) + documented protocol schema. Stand up listen sockets via reused `Net_InitMultiUdpIpAccept`/`Net_InitAcceptSocket`; round-trip packet corpus; token-based session table; one real client joins.
- **M6 — Physics drive.** Per-entity `VehicleTuning_ComputeControlScalars` → `Vehicle_ApplyThrustForces` → `EntityPhysics_IntegrateStep` on the sim thread; physics-parity test vs `wulfsim`. Discovery: entity lifetime/ownership; stack-alignment for FP paths.
- **M7 — Multi-client + game rules.** "Current player" singleton audit; two-client corruption test; port roster/cargo/map semantics from `Wulf-Forge`.
