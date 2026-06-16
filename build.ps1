param(
    [string]$BuildDir = "build",
    [string]$Config = "Debug",
    [switch]$SkipTests,
    [switch]$Strict = $true
)
$ErrorActionPreference = "Stop"
$VcVars = "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars32.bat"
if (-not (Test-Path $VcVars)) { throw "vcvars32.bat not found at $VcVars" }

# Resolve cmake: prefer one on PATH, else fall back to the VS-bundled absolute path.
$CMake = (Get-Command cmake -ErrorAction SilentlyContinue)?.Source
if (-not $CMake) {
    $BundledCMake = "C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe"
    if (Test-Path $BundledCMake) {
        $CMake = $BundledCMake
    } else {
        throw "cmake not found on PATH and not at bundled location $BundledCMake"
    }
}

# ctest lives next to cmake; resolve it from the same directory so we do not
# depend on it being separately on PATH.
$CTest = Join-Path (Split-Path $CMake -Parent) "ctest.exe"
if (-not (Test-Path $CTest)) {
    $CTestCmd = (Get-Command ctest -ErrorAction SilentlyContinue)?.Source
    if ($CTestCmd) { $CTest = $CTestCmd } else { throw "ctest not found next to cmake or on PATH" }
}

$StrictVal = [int][bool]$Strict

cmd /c "`"$VcVars`" && `"$CMake`" -S . -B $BuildDir -G Ninja -DCMAKE_BUILD_TYPE=$Config -DWFH_STRICT=$StrictVal"
if ($LASTEXITCODE -ne 0) { throw "cmake configure failed" }
cmd /c "`"$VcVars`" && `"$CMake`" --build $BuildDir"
if ($LASTEXITCODE -ne 0) { throw "cmake build failed" }
if (-not $SkipTests) {
    # Run the GoogleTest suite through CTest (tests are registered via
    # gtest_discover_tests). Go through vcvars32 so the x86 runtime is on PATH.
    cmd /c "`"$VcVars`" && `"$CTest`" --test-dir $BuildDir --output-on-failure"
    if ($LASTEXITCODE -ne 0) { throw "tests failed" }
}
