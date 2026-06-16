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

// Call Obj_Create @ 0x419a70 with its true (non-__thiscall) convention, verified from
// disassembly + the call site Net_HandleTankSpawn:
//   ECX = creator, EBX = oid, 6 caller-cleaned stack args
//   (is_local, type, owner, team, deco5, deco6); returns the new entity in EAX, or
//   null if the oid is rejected (LoseOid). Plain-RET => caller cleans the 24 bytes.
auto EngineObjCreate(int creator, int oid, int is_local, int type, int owner, int team, int deco5,
                     int deco6) -> void*;

// Call Obj_InitFromSpawn @ 0x419880: entity in EAX, 6 caller-cleaned stack args
// (pos x,y,z then euler ox,oy,oz). Sets the transform and pushes the entity into the
// world list (*DAT_006785e4) AND the spatial index. Plain-RET => caller cleans 24.
// Only enters-world (grabs the local camera) if the entity OID == DAT_005b83e0 (-1
// for a pure server), so a real-OID spawn stays a non-local object.
void EngineObjInitFromSpawn(void* entity, float pos_x, float pos_y, float pos_z, float rot_x,
                            float rot_y, float rot_z);

}  // namespace wfh::server
