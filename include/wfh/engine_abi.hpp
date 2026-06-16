#pragma once
#include <cstdint>

// ABI-correct binding helpers for calling wulfram2.exe's own functions by absolute address.
// 32-bit MSVC calling conventions are explicit so the compiler emits the right call/cleanup:
//   __cdecl    : caller cleans the stack
//   __stdcall  : callee cleans the stack
//   __thiscall : `this` in ECX, callee cleans the stack (C++ member functions)
namespace wfh {
namespace abi {

template <typename Ret, typename... Args> struct Cdecl {
    using Ptr = Ret(__cdecl*)(Args...);
    static auto At(std::uint32_t address) -> Ptr {
        // Binding a typed function pointer to an absolute address in the target image
        // is the entire purpose of this helper; the int-to-ptr cast is intentional.
        return reinterpret_cast<
            Ptr>(  // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast,performance-no-int-to-ptr)
            static_cast<std::uintptr_t>(address));
    }
};

template <typename Ret, typename... Args> struct Stdcall {
    using Ptr = Ret(__stdcall*)(Args...);
    static auto At(std::uint32_t address) -> Ptr {
        // Binding a typed function pointer to an absolute address in the target image
        // is the entire purpose of this helper; the int-to-ptr cast is intentional.
        return reinterpret_cast<
            Ptr>(  // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast,performance-no-int-to-ptr)
            static_cast<std::uintptr_t>(address));
    }
};

template <typename Ret, typename... Args> struct Thiscall {
    using Ptr = Ret(__thiscall*)(Args...);
    static auto At(std::uint32_t address) -> Ptr {
        // Binding a typed function pointer to an absolute address in the target image
        // is the entire purpose of this helper; the int-to-ptr cast is intentional.
        return reinterpret_cast<
            Ptr>(  // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast,performance-no-int-to-ptr)
            static_cast<std::uintptr_t>(address));
    }
};

// Convenience alias for the common __cdecl case.
template <typename Ret, typename... Args> using Fn = Cdecl<Ret, Args...>;

}  // namespace abi
}  // namespace wfh
