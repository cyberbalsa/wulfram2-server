// NOLINTBEGIN(portability-avoid-pragma-once)
// pragma once is the project-wide include-guard convention; intentional.
#pragma once
// NOLINTEND(portability-avoid-pragma-once)

#include <cstdint>

namespace wfh::server {

// Callback shape for one unit of tick-thread work. Kept C-like so the SEH wrapper
// can call it from a raw __try block without C++ unwinding requirements.
using TickCallback = void(__cdecl*)(void* user);

struct TickBreadcrumb {
    std::uint64_t tick = 0;
    const char* phase = "tick";
};

struct TickGuardOptions {
    const wchar_t* dump_path = nullptr;
};

struct TickGuardResult {
    bool ok = true;
    std::uint64_t tick = 0;
    std::uint32_t seh_code = 0;
    std::uintptr_t seh_address = 0;
    bool dump_written = false;
};

[[nodiscard]] auto RunProtectedTick(const TickBreadcrumb& breadcrumb, TickCallback callback,
                                    void* user) -> TickGuardResult;

[[nodiscard]] auto RunProtectedTick(const TickBreadcrumb& breadcrumb, TickCallback callback,
                                    void* user, const TickGuardOptions& options) -> TickGuardResult;

}  // namespace wfh::server
