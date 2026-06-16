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
    GIT_TAG v1.3.4
    GIT_SHALLOW TRUE
)
FetchContent_MakeAvailable(minhook)

# MinHook v1.3.3 ships no CMakeLists.txt (only MSBuild projects), so
# FetchContent populates the sources but defines no `minhook` target.
# Define the target ourselves from the fetched sources when it is missing.
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

add_library(wfh_loader_core STATIC src/loader/injector.cpp src/loader/loader_args.cpp)
target_include_directories(wfh_loader_core PUBLIC include gen)
target_link_libraries(wfh_loader_core PUBLIC wfh_log wfh_pe)

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
