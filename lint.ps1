# lint.ps1 - Static-analysis gate for wulf_forge_headless.
#
# Runs BOTH clang-tidy and cppcheck over OUR source only (src/ + include/),
# excluding the CMake build tree (build/) and FetchContent dependencies
# (build/_deps: minhook, googletest, googlemock). Exits non-zero if either
# analyzer reports a finding, so CI can gate on it.
#
# Tools are referenced by absolute path because they are installed but may not
# be on PATH:
#   clang-tidy: C:\Program Files\LLVM\bin\clang-tidy.exe  (LLVM 22.x)
#   cppcheck:   C:\Program Files\Cppcheck\cppcheck.exe     (2.21.x)
#
# clang-tidy / MSVC friction notes:
#   * The compile_commands.json is produced by MSVC cl.exe. clang-tidy drives
#     clang to parse it, and clang does not understand every MSVC-only switch.
#     Two extra-args are required for a clean run:
#       --extra-arg=-Wno-unknown-warning-option : clang ignores -W flags it does
#           not recognize instead of erroring.
#       --extra-arg=-Qunused-arguments : the MSVC-only flag /Zc:preprocessor (and
#           friends) is accepted by cl but unused by clang's parse; without this
#           clang emits clang-diagnostic-unused-command-line-argument, which the
#           .clang-tidy 'WarningsAsErrors: *' turns into a hard error and aborts
#           the file. -Qunused-arguments silences that specific friction.
#     We do NOT pass /EHsc on the command line: it is already present in
#     compile_commands.json, and forwarding it again via --extra-arg gets mangled
#     by some shells (a leading-slash arg can be path-rewritten). If a future
#     MSVC-only flag breaks parsing, add a matching --extra-arg here.
#   * HeaderFilterRegex in .clang-tidy stays '.*wfh.*' so only our headers are
#     diagnosed (system/STL headers are ignored), matching repo convention.

param(
    [string]$BuildDir = "build"
)
$ErrorActionPreference = "Stop"

$ClangTidy = "C:\Program Files\LLVM\bin\clang-tidy.exe"
$CppCheck  = "C:\Program Files\Cppcheck\cppcheck.exe"
foreach ($tool in @($ClangTidy, $CppCheck)) {
    if (-not (Test-Path $tool)) { throw "lint tool not found: $tool" }
}
if (-not (Test-Path (Join-Path $BuildDir "compile_commands.json"))) {
    throw "compile_commands.json not found in '$BuildDir' - run .\build.ps1 first."
}

$RepoRoot = $PSScriptRoot
$Failed = $false

# --- clang-tidy --------------------------------------------------------------
# Run over our .cpp translation units; clang-tidy pulls the headers itself and
# the .clang-tidy HeaderFilterRegex limits header diagnostics to wfh headers.
Write-Host "==> clang-tidy" -ForegroundColor Cyan
$Sources = Get-ChildItem -Path (Join-Path $RepoRoot "src") -Recurse -Filter *.cpp |
    Select-Object -ExpandProperty FullName
$TidyFailed = $false
foreach ($src in $Sources) {
    & $ClangTidy -p $BuildDir --extra-arg=-Wno-unknown-warning-option --extra-arg=-Qunused-arguments $src
    if ($LASTEXITCODE -ne 0) { $TidyFailed = $true }
}
if ($TidyFailed) {
    Write-Host "clang-tidy: FINDINGS" -ForegroundColor Red
    $Failed = $true
} else {
    Write-Host "clang-tidy: clean" -ForegroundColor Green
}

# --- cppcheck ----------------------------------------------------------------
# Analyze only src/ (with include/ on the include path). build/ and _deps are
# never passed in, so third-party code is excluded. --error-exitcode=1 makes a
# finding fail the gate; missingIncludeSystem noise (system headers cppcheck
# cannot find) is suppressed.
Write-Host "==> cppcheck" -ForegroundColor Cyan
& $CppCheck --enable=warning,performance,portability,style `
    --error-exitcode=1 --inline-suppr --std=c++17 `
    --suppress=missingIncludeSystem `
    -I (Join-Path $RepoRoot "include") (Join-Path $RepoRoot "src")
if ($LASTEXITCODE -ne 0) {
    Write-Host "cppcheck: FINDINGS" -ForegroundColor Red
    $Failed = $true
} else {
    Write-Host "cppcheck: clean" -ForegroundColor Green
}

# --- summary -----------------------------------------------------------------
Write-Host ""
if ($Failed) {
    Write-Host "LINT: FAIL" -ForegroundColor Red
    exit 1
} else {
    Write-Host "LINT: PASS" -ForegroundColor Green
    exit 0
}
