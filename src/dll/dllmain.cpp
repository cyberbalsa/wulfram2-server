#include "wfh/init.hpp"

#include <windows.h>

// DllMain must do the ABSOLUTE MINIMUM: it runs under the loader lock, so any
// LoadLibrary/file I/O/logging/sync primitive here risks a loader-lock deadlock.
// All real work is deferred to wfh::InitThread, which runs after the lock releases.
//
// DllMain's signature (BOOL APIENTRY ...) is fixed by the Windows loader ABI, so
// a trailing return type does not apply here.
// NOLINTNEXTLINE(modernize-use-trailing-return-type)
BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID /*reserved*/) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(module);
        const HANDLE thread = CreateThread(nullptr, 0, wfh::InitThread, module, 0, nullptr);
        if (thread != nullptr) {
            CloseHandle(thread);
        }
    }
    return TRUE;
}
