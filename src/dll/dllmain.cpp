#include <windows.h>

// DllMain's signature (BOOL APIENTRY ...) is fixed by the Windows loader ABI, so
// a trailing return type does not apply here.
// NOLINTNEXTLINE(modernize-use-trailing-return-type)
BOOL APIENTRY DllMain(HMODULE /*module*/, DWORD /*reason*/, LPVOID /*reserved*/) {
    return TRUE;
}
