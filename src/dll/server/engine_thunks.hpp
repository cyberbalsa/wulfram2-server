// NOLINTBEGIN(portability-avoid-pragma-once)
// pragma once is the project-wide include-guard convention; intentional.
#pragma once
// NOLINTEND(portability-avoid-pragma-once)

namespace wfh::server {

// Hand-written asm thunks for engine functions whose calling convention no MSVC
// keyword can express. Kept in their own translation unit so the register-precise
// assembly stays isolated from the analyzable C++.

// Call Client_SetCurrentWorld @ 0x4b9eb0 with its TRUE convention (verified from the
// engine's own call site Net_HandleWorldStats; Ghidra mislabels it __fastcall):
//   ECX = world_flag, EDX = map_name, stack = [world_type, scale], caller-cleans 8.
// See memory/client-setcurrentworld-abi. Loads ./data/maps/<map_name>, runs its
// start_script, and builds the spatial/collision tree (sets DAT_006785e4).
void EngineLoadWorld(char* map_name, int world_type, int world_flag, float scale);

}  // namespace wfh::server
