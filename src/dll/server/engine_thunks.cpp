#include "server/engine_thunks.hpp"

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

}  // namespace wfh::server
