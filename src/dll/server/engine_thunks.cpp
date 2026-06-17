#include "server/engine_thunks.hpp"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>  // EXCEPTION_EXECUTE_HANDLER for the SEH-guarded invoker

namespace wfh::server {

// __declspec(naked): emit no compiler prologue/epilogue and (critically) no /RTC1
// ESP check, so we control the registers, the stack-arg push order, and the
// caller-side cleanup exactly. x86-only, which matches this 32-bit DLL.
//
// Params are intentionally unnamed: the body reads them straight off the frame via
// [ebp+N], so naming them would only trip the unreferenced-parameter warning under
// /W4 /WX. Frame layout after `push ebp; mov ebp,esp`:
//   [ebp+0x08] map_name   [ebp+0x0c] world_type
//   [ebp+0x10] world_flag  [ebp+0x14] scale (float bits)
//
// Target convention (Net_HandleWorldStats @ 0x46cf50 is the reference call):
//   ECX = world_flag, EDX = map_name, push scale then world_type, caller cleans 8.
// NOLINTNEXTLINE(readability-named-parameter,hicpp-named-parameter)
__declspec(naked) void EngineLoadWorld(char*, int, int, float) {
    __asm {
        push ebp
        mov  ebp, esp
        mov  edx, [ebp+0x08]  // map_name   -> EDX
        mov  ecx, [ebp+0x10]  // world_flag -> ECX
        mov  eax, [ebp+0x14]  // scale (float bits)
        push eax  // pushed first  -> callee [EBP+0x0c]
        mov  eax, [ebp+0x0c]  // world_type
        push eax  // pushed last   -> callee [EBP+0x08]
        mov  eax, 4b9eb0h  // Client_SetCurrentWorld
        call eax
        add  esp, 8  // caller-clean the two stack args (plain-RET callee)
        mov  esp, ebp
        pop  ebp
        ret
    }
}

// Obj_Create @ 0x419a70 — ECX=creator, EBX=oid, 6 caller-cleaned stack args; entity
// returned in EAX. EBX is callee-saved by the C++ caller, so we save/restore it.
// Frame after `push ebp; mov ebp,esp`:
//   [ebp+0x08] creator [ebp+0x0c] oid    [ebp+0x10] is_local [ebp+0x14] type
//   [ebp+0x18] owner   [ebp+0x1c] team   [ebp+0x20] deco5    [ebp+0x24] deco6
// NOLINTNEXTLINE(readability-named-parameter,hicpp-named-parameter)
__declspec(naked) auto EngineObjCreate(int, int, int, int, int, int, int, int) -> void* {
    __asm {
        push ebp
        mov  ebp, esp
        push ebx  // preserve EBX (we load oid into it)
        mov  eax, [ebp+0x24]  // deco6, pushed right-to-left ...
        push eax
        mov  eax, [ebp+0x20]  // deco5
        push eax
        mov  eax, [ebp+0x1c]  // team
        push eax
        mov  eax, [ebp+0x18]  // owner
        push eax
        mov  eax, [ebp+0x14]  // type
        push eax
        mov  eax, [ebp+0x10]  // is_local
        push eax
        mov  ecx, [ebp+0x08]  // creator -> ECX
        mov  ebx, [ebp+0x0c]  // oid     -> EBX
        mov  eax, 419a70h  // Obj_Create -> entity in EAX (or 0)
        call eax
        add  esp, 0x18  // caller-clean the 6 stack args (plain-RET callee)
        pop  ebx  // restore EBX (EAX = return value, untouched)
        mov  esp, ebp
        pop  ebp
        ret
    }
}

// Obj_InitFromSpawn @ 0x419880 — entity in EAX, 6 caller-cleaned stack args. Only
// EAX/EDX are clobbered (both caller-saved), so nothing to preserve.
// Frame: [ebp+0x08] entity [ebp+0x0c] pos_x [ebp+0x10] pos_y [ebp+0x14] pos_z
//        [ebp+0x18] rot_x  [ebp+0x1c] rot_y [ebp+0x20] rot_z
// NOLINTNEXTLINE(readability-named-parameter,hicpp-named-parameter)
__declspec(naked) void EngineObjInitFromSpawn(void*, float, float, float, float, float, float) {
    __asm {
        push ebp
        mov  ebp, esp
        mov  eax, [ebp+0x20]  // rot_z, pushed right-to-left ...
        push eax
        mov  eax, [ebp+0x1c]  // rot_y
        push eax
        mov  eax, [ebp+0x18]  // rot_x
        push eax
        mov  eax, [ebp+0x14]  // pos_z
        push eax
        mov  eax, [ebp+0x10]  // pos_y
        push eax
        mov  eax, [ebp+0x0c]  // pos_x
        push eax
        mov  eax, [ebp+0x08]  // entity -> EAX
        mov  edx, 419880h  // Obj_InitFromSpawn
        call edx
        add  esp, 0x18  // caller-clean the 6 stack args (plain-RET callee)
        mov  esp, ebp
        pop  ebp
        ret
    }
}

// Tank_Construct @ 0x4f9a40 — __fastcall(ECX = controller). 0 stack args; returns the
// controller in EAX (it preserves ESI internally). `mov esp,ebp` is a safety net.
// Frame: [ebp+0x08] controller
// NOLINTNEXTLINE(readability-named-parameter,hicpp-named-parameter)
__declspec(naked) auto EngineTankConstruct(void*) -> void* {
    __asm {
        push ebp
        mov  ebp, esp
        mov  ecx, [ebp+0x08]  // controller -> ECX
        mov  eax, 4f9a40h  // Tank_Construct -> controller in EAX
        call eax
        mov  esp, ebp
        pop  ebp
        ret
    }
}

// VehicleInstance_InitForEntity @ 0x4f63c0 — __thiscall(ECX = controller; stack args
// param_1=entity, param_2). __thiscall pushes right-to-left (param_2 first) and the callee
// cleans the 8 bytes; `mov esp,ebp` restores ESP regardless (belt-and-suspenders).
// Frame: [ebp+0x08] controller [ebp+0x0c] entity [ebp+0x10] param2
// NOLINTNEXTLINE(readability-named-parameter,hicpp-named-parameter)
__declspec(naked) void EngineVehicleInitForEntity(void*, void*, void*) {
    __asm {
        push ebp
        mov  ebp, esp
        mov  eax, [ebp+0x10]  // param2 (pushed first)
        push eax
        mov  eax, [ebp+0x0c]  // entity (pushed last)
        push eax
        mov  ecx, [ebp+0x08]  // controller -> ECX
        mov  eax, 4f63c0h  // VehicleInstance_InitForEntity (callee-clean 8)
        call eax
        mov  esp, ebp
        pop  ebp
        ret
    }
}

// Universal x86 invoker. Frame after `push ebp; mov ebp,esp`:
//   [ebp+0x08] addr  [ebp+0x0c] ecx  [ebp+0x10] edx  [ebp+0x14] args  [ebp+0x18] argc
// Pushes args right-to-left, sets ECX/EDX, calls addr; then `lea esp,[ebp-8]` discards the
// pushed args AND any callee-side cleanup difference, so it is convention-agnostic. EAX
// (the return value) is never touched by the epilogue.
// NOLINTNEXTLINE(readability-named-parameter,hicpp-named-parameter)
__declspec(naked) auto EngineRawInvoke(std::uint32_t, std::uint32_t, std::uint32_t,
                                       const std::uint32_t*, int) -> std::uint32_t {
    __asm {
        push ebp
        mov  ebp, esp
        push esi
        push edi
        mov  esi, [ebp+0x14]  // args ptr
        mov  edi, [ebp+0x18]  // argc
        test edi, edi
        jz   skip_args
        lea  esi, [esi + edi*4 - 4]  // &args[argc-1]
    push_loop:
        push dword ptr [esi]  // push args right-to-left
        sub  esi, 4
        dec  edi
        jnz  push_loop
    skip_args:
        mov  ecx, [ebp+0x0c]  // ECX (this / fastcall arg0)
        mov  edx, [ebp+0x10]  // EDX (fastcall arg1)
        mov  eax, [ebp+0x08]  // target
        call eax  // result in EAX
        lea  esp, [ebp-8]  // drop pushed args (+ any callee-clean diff); esp -> edi slot
        pop  edi
        pop  esi
        pop  ebp
        ret
    }
}

// SEH wrapper. Kept C-like (InvokeResult is trivially destructible) so MSVC accepts __try.
auto SafeEngineInvoke(std::uint32_t addr, std::uint32_t ecx, std::uint32_t edx,
                      const std::uint32_t* args, int argc) -> InvokeResult {
    InvokeResult result;
    __try {
        result.eax = EngineRawInvoke(addr, ecx, edx, args, argc);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        result.faulted = true;
    }
    return result;
}

}  // namespace wfh::server
