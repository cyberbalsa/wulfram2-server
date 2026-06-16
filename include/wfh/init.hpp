// NOLINTBEGIN(portability-avoid-pragma-once)
// pragma once is the project-wide include-guard convention; intentional.
#pragma once
// NOLINTEND(portability-avoid-pragma-once)
#include <windows.h>

namespace wfh {

// Thread entry executed AFTER the loader lock releases (started from DllMain).
// Signature is fixed by the LPTHREAD_START_ROUTINE ABI, so a trailing return
// type does not apply here.
// NOLINTNEXTLINE(modernize-use-trailing-return-type)
DWORD WINAPI InitThread(LPVOID module_handle);

}  // namespace wfh
