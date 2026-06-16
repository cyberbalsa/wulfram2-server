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

file(MAKE_DIRECTORY "${CMAKE_BINARY_DIR}/config")
configure_file("${CMAKE_SOURCE_DIR}/config/headless.toml"
               "${CMAKE_BINARY_DIR}/config/headless.toml" COPYONLY)

include(FetchContent)
FetchContent_Declare(
    minhook
    GIT_REPOSITORY https://github.com/TsudaKageyu/minhook.git
    GIT_TAG v1.3.4
    GIT_SHALLOW TRUE
)
FetchContent_MakeAvailable(minhook)

# GoogleTest for the test harness. Pinned tag, shallow clone. It inherits the
# x86/MSVC toolchain from the top-level configure (vcvars32), so it builds 32-bit.
FetchContent_Declare(
    googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG v1.15.2
    GIT_SHALLOW TRUE
)
# Match our targets' CRT (we build with the dynamic CRT under MSVC); otherwise
# gtest defaults to the static CRT on Windows and link errors result. Must be
# set BEFORE FetchContent_MakeAvailable(googletest).
if(MSVC)
    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
endif()
FetchContent_MakeAvailable(googletest)

enable_testing()
include(GoogleTest)

# MinHook v1.3.4 ships its own CMakeLists.txt, so FetchContent_MakeAvailable
# defines the `minhook` target itself and this block does not run. It is kept
# as a defensive fallback: older tags (e.g. v1.3.3) ship no CMakeLists, leaving
# the sources populated but no target — in that case we define it ourselves.
if(NOT TARGET minhook)
    add_library(minhook STATIC
        ${minhook_SOURCE_DIR}/src/buffer.c
        ${minhook_SOURCE_DIR}/src/hook.c
        ${minhook_SOURCE_DIR}/src/trampoline.c
        ${minhook_SOURCE_DIR}/src/hde/hde32.c
        ${minhook_SOURCE_DIR}/src/hde/hde64.c)
    target_include_directories(minhook PUBLIC ${minhook_SOURCE_DIR}/include)
endif()

add_library(wfh_log STATIC src/log/log.cpp)
target_include_directories(wfh_log PUBLIC include)

add_library(wfh_pe STATIC src/common/pe_validate.cpp)
target_include_directories(wfh_pe PUBLIC include gen)

# Wire-protocol codec: pure, engine-less, host-testable. The security boundary that
# parses untrusted bytes (bit reader/writer, TCP/UDP framing, validators).
add_library(wfh_proto STATIC
    src/dll/server/proto/bitstream.cpp
    src/dll/server/proto/framing.cpp
    src/dll/server/proto/validate.cpp)
target_include_directories(wfh_proto PUBLIC include)

# Threaded socket server: WinSock2 listener + per-connection handshake state machine.
# Engine-isolated (the cardinal rule): it only touches sockets, the proto codec, and
# the queue boundary — never engine memory.
add_library(wfh_server_net STATIC
    src/dll/server/net/server_config.cpp
    src/dll/server/net/bringup_packets.cpp
    src/dll/server/net/world_packets.cpp
    src/dll/server/net/connection.cpp
    src/dll/server/net/acceptor.cpp
    src/dll/server/net/runtime.cpp
    src/dll/server/net/world_host.cpp
    src/dll/server/net/entity_snapshot.cpp)
target_include_directories(wfh_server_net PUBLIC include)
target_link_libraries(wfh_server_net PUBLIC wfh_proto wfh_log PRIVATE ws2_32)

add_library(wfh_server_tick STATIC src/dll/server/tick_guard.cpp)
target_include_directories(wfh_server_tick PUBLIC include)
target_link_libraries(wfh_server_tick PUBLIC wfh_log dbghelp)

add_library(wfh_loader_core STATIC src/loader/injector.cpp src/loader/loader_args.cpp)
target_include_directories(wfh_loader_core PUBLIC include gen)
target_link_libraries(wfh_loader_core PUBLIC wfh_log wfh_pe)

add_executable(loader src/loader/main.cpp)
target_link_libraries(loader PRIVATE wfh_loader_core wfh_log)

add_library(wulf_headless SHARED
    src/dll/dllmain.cpp
    src/dll/init.cpp
    src/dll/hooks/engine_hooks.cpp
    src/dll/hooks/head_stubs.cpp
    src/dll/server/world_host_engine.cpp
    src/dll/server/engine_thunks.cpp)
target_include_directories(wulf_headless PRIVATE include gen src/dll)
target_link_libraries(wulf_headless PRIVATE wfh_log wfh_pe wfh_proto wfh_server_net
    wfh_server_tick minhook dbghelp)

add_executable(wfh_tests tests/test_main.cpp tests/test_proto.cpp tests/test_server_net.cpp
    tests/test_server_tick.cpp tests/test_world_host.cpp tests/test_entity_snapshot.cpp)
target_link_libraries(wfh_tests PRIVATE wfh_log wfh_pe wfh_proto wfh_server_net wfh_server_tick
    wfh_loader_core GTest::gtest_main ws2_32)
gtest_discover_tests(wfh_tests)

set(WFH_TARGETS wfh_log wfh_pe wfh_proto wfh_server_net wfh_server_tick wfh_loader_core loader
    wulf_headless wfh_tests)

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
