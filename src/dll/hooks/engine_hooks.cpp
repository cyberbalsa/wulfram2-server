#include "engine_hooks.hpp"

#include "wfh/log.hpp"

// MinHook is third-party; its header trips a few /W4 diagnostics. Suppress them
// locally so our translation unit stays /W4 /WX clean without relaxing warnings
// for our own code below the include.
#ifdef _MSC_VER
#pragma warning(push, 0)
#endif
#include <MinHook.h>
#ifdef _MSC_VER
#pragma warning(pop)
#endif

#include <cstdint>

// Every WFH_* logging call expands to the project's intentional do-while(0) guard
// macro that forwards a printf-style C variadic to Log::Write. Suppress the two
// macro-inherent findings file-wide so the call sites stay readable; all other
// checks remain on.
// NOLINTBEGIN(cppcoreguidelines-avoid-do-while,cppcoreguidelines-pro-type-vararg)
namespace wfh {
namespace {

// Render a code pointer as an integer for logging. reinterpret_cast is the only
// way to get the numeric address; it is read-only and never dereferenced.
auto AddrOf(const void* ptr) -> std::uintptr_t {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    return reinterpret_cast<std::uintptr_t>(ptr);
}

}  // namespace

auto HooksInit() -> bool {
    const MH_STATUS status = MH_Initialize();
    if (status != MH_OK) {
        WFH_FATAL("hooks", "MH_Initialize failed: %s", MH_StatusToString(status));
        return false;
    }
    return true;
}

auto InstallDetour(void* target, void* detour, void** original) -> bool {
    WFH_INFO("hooks", "installing detour at %08x", static_cast<unsigned>(AddrOf(target)));

    const MH_STATUS created = MH_CreateHook(target, detour, original);
    if (created != MH_OK) {
        WFH_FATAL("hooks", "MH_CreateHook(%08x) failed: %s", static_cast<unsigned>(AddrOf(target)),
                  MH_StatusToString(created));
        return false;
    }
    WFH_INFO("hooks", "MH_CreateHook(%08x) OK", static_cast<unsigned>(AddrOf(target)));

    const MH_STATUS enabled = MH_EnableHook(target);
    if (enabled != MH_OK) {
        WFH_FATAL("hooks", "MH_EnableHook(%08x) failed: %s", static_cast<unsigned>(AddrOf(target)),
                  MH_StatusToString(enabled));
        return false;
    }
    WFH_INFO("hooks", "MH_EnableHook(%08x) OK", static_cast<unsigned>(AddrOf(target)));
    return true;
}

void HooksShutdown() {
    const MH_STATUS disabled = MH_DisableHook(MH_ALL_HOOKS);
    if (disabled != MH_OK) {
        WFH_WARN("hooks", "MH_DisableHook(ALL) failed: %s", MH_StatusToString(disabled));
    }
    const MH_STATUS uninit = MH_Uninitialize();
    if (uninit != MH_OK) {
        WFH_WARN("hooks", "MH_Uninitialize failed: %s", MH_StatusToString(uninit));
    }
}

}  // namespace wfh
// NOLINTEND(cppcoreguidelines-avoid-do-while,cppcoreguidelines-pro-type-vararg)
