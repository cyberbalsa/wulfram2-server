# Quality Gate (versioned git hooks)

This repo enforces a strict, zero-warning quality gate through **versioned git
hooks** stored in `.githooks/` and shared via the repository. The hooks are
split into a fast pre-commit check and a heavy pre-push gate.

This is a **Windows-only** project (32-bit MSVC toolchain). The gate assumes
Git-for-Windows (so hooks run under Git Bash `sh`), the LLVM and Cppcheck tools
listed below, and **PowerShell 7+ (`pwsh`)** — see "Required tools".

## Activation (required once per clone)

The hooks live in-repo but git does not use them until you point `core.hooksPath`
at the directory. After cloning, run:

```sh
git config core.hooksPath .githooks
```

This is a per-clone local setting (it lives in `.git/config`, which is not
versioned), so **every contributor must run it once**. Until they do, the hooks
do not fire for them.

## Required tools

The hooks shell out to tools installed at fixed absolute paths (they are not
assumed to be on `PATH`):

| Tool          | Path                                          | Used by      |
|---------------|-----------------------------------------------|--------------|
| clang-format  | `C:\Program Files\LLVM\bin\clang-format.exe`  | pre-commit   |
| clang-tidy    | `C:\Program Files\LLVM\bin\clang-tidy.exe`    | pre-push (via `lint.ps1`) |
| cppcheck      | `C:\Program Files\Cppcheck\cppcheck.exe`      | pre-push (via `lint.ps1`) |
| MSVC (x86)    | Visual Studio 2022, driven through `vcvars32` | pre-push (via `build.ps1`) |
| PowerShell 7  | `pwsh` on `PATH` (`winget install Microsoft.PowerShell`) | pre-push (runs the `.ps1` scripts) |

The pre-push hook runs `build.ps1` / `lint.ps1` via **`pwsh`**. Those scripts use
PowerShell 7+ syntax (e.g. the `?.` operator) that Windows PowerShell 5.1
(`powershell.exe`) cannot parse, so PowerShell 7 is **required**: if `pwsh` is
not on `PATH` the hook blocks the push with an install hint rather than silently
running a PowerShell that would misreport the gate. Install it with
`winget install Microsoft.PowerShell`.

The hooks run under Git Bash (`sh`) because this is Git-for-Windows. The hook
files are kept LF-terminated (enforced via `.gitattributes`) so the `#!/bin/sh`
shebang parses on every clone regardless of `core.autocrlf`.

## `.githooks/pre-commit` — fast, formatting only

Runs on `git commit`. It is deliberately light so committing stays fast:

- Looks only at **staged** C/C++ files (`git diff --cached --name-only
  --diff-filter=ACM`, filtered to `*.cpp` / `*.hpp` / `*.h`).
- Runs `clang-format --dry-run -Werror` on each. If any staged file is not
  clang-format clean, it prints the offending files and the fix command, then
  exits non-zero (commit blocked).
- If no C/C++ files are staged, it exits 0 immediately.
- It does **not** build or run clang-tidy/cppcheck — those belong to pre-push.

Fix a formatting failure with:

```sh
"C:\Program Files\LLVM\bin\clang-format.exe" -i <file...>
```

then re-stage and commit. The repo-root `.clang-format` (LLVM base, 4-space
indent, 100-column limit, left pointer alignment, no namespace indent, inline
short functions) defines the canonical style.

## `.githooks/pre-push` — the hard gate

Runs on `git push`. It ignores the ref list git feeds on stdin and **always**
runs the full gate:

1. `pwsh -NoProfile -ExecutionPolicy Bypass -File ./build.ps1`
   - CMake configure + build under **`/W4 /WX`** (any warning fails the build),
     then `ctest`. **Tests are part of the push gate.**
   - On failure: prints `PUSH BLOCKED: build/tests failed (zero-warning /W4 /WX
     gate)` and exits non-zero.
2. `pwsh -NoProfile -ExecutionPolicy Bypass -File ./lint.ps1`
   - clang-tidy (`WarningsAsErrors: '*'`) + cppcheck (`--error-exitcode=1`) over
     `src/` + `include/`.
   - On failure: prints `PUSH BLOCKED: static analysis (clang-tidy/cppcheck)
     failed` and exits non-zero.

On success it prints `QUALITY GATE PASSED` and exits 0, allowing the push.

Because pre-push performs a full configure + build + tests + static analysis, it
can take noticeably longer than a commit. That is intentional: the real gate
lives here, not in the commit path.

## Emergency bypass (discouraged)

Both hooks honor git's `--no-verify`:

```sh
git commit --no-verify    # skip pre-commit formatting check
git push   --no-verify    # skip the full pre-push quality gate
```

**This should not be routine.** Bypassing pre-push skips the zero-warning build,
the tests, and all static analysis — i.e. the entire quality guarantee. Use it
only to recover from a genuine emergency (e.g. a hotfix when a tool is broken or
unavailable), and fix the underlying problem immediately afterward.
