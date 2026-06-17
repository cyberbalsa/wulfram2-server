// NOLINTBEGIN(portability-avoid-pragma-once)
// pragma once is the project-wide include-guard convention; intentional.
#pragma once
// NOLINTEND(portability-avoid-pragma-once)

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace wfh::server {

// ---------------------------------------------------------------------------
// Dev console: a localhost-only TCP command socket for live, in-process poking of
// the injected engine while it runs. DEV TOOLING — gated behind a config port so it
// never opens in a normal run. The command grammar is line-based ASCII; responses are
// ASCII too, so it is drivable straight from PowerShell/netcat/python.
//
// Increment 1 (this file): memory read/write (peek/poke). Increment 2 adds engine
// CALL (executed on the tick thread) + breakpoints/callstacks (VEH + DbgHelp); those
// kinds parse here already so the grammar is stable.
// ---------------------------------------------------------------------------

// NOLINTNEXTLINE(performance-enum-size)
enum class DevCmdKind {
    Unknown,     // unrecognized verb (error set)
    Help,        // list commands
    Peek,        // peek <hexaddr> <len>            -> hex dump of len bytes
    Poke,        // poke <hexaddr> <hexbytes>       -> write bytes
    Call,        // call <hexaddr> <conv> [args..]  -> invoke (increment 2; on tick thread)
    Backtrace,   // bt                            -> engine-thread callstack (increment 2)
    Break,       // bp <hexaddr>                  -> trace breakpoint (increment 2)
    BreakClear,  // bc <hexaddr>                 -> remove breakpoint (increment 2)
    Hook,        // hook <hexaddr>               -> logging hook (increment 3)
};

// One parsed command line. `error` non-empty means the line was malformed (the socket
// layer echoes it back). Numeric fields are populated per-kind.
struct DevCommand {
    DevCmdKind kind = DevCmdKind::Unknown;
    std::uint32_t addr = 0;           // peek/poke/call/bp/bc/hook target
    std::uint32_t len = 0;            // peek length (bytes)
    std::vector<std::uint8_t> bytes;  // poke payload
    std::vector<std::uint32_t> args;  // call stack args
    std::string conv;                 // call convention token (cdecl/stdcall/fastcall/thiscall)
    std::string error;                // non-empty => parse failure description
};

// Caps so a hostile/typo'd line can't ask for a gigabyte dump or write.
constexpr std::size_t kDevMaxPeekLen = 4096;
constexpr std::size_t kDevMaxPokeLen = 4096;

// --- Pure parsing helpers (host-tested) ------------------------------------

// Parse a 32-bit hex value, with or without a leading "0x"/"0X". Returns false on
// empty/overflow/non-hex input.
[[nodiscard]] auto ParseHexU32(std::string_view text, std::uint32_t& out) -> bool;

// Parse an even-length hex string ("deadbeef") into bytes. Returns false on odd length
// or non-hex characters or if it would exceed kDevMaxPokeLen.
[[nodiscard]] auto ParseHexBytes(std::string_view text, std::vector<std::uint8_t>& out) -> bool;

// Render bytes as an offset-prefixed hex+ascii dump (16 bytes/line), addr-anchored.
[[nodiscard]] auto HexDumpBytes(std::uint32_t base_addr, const std::uint8_t* data, std::size_t len)
    -> std::string;

// Parse one command line into a DevCommand. Never throws; malformed input yields
// kind/Unknown or a populated `error`.
[[nodiscard]] auto ParseDevCommand(std::string_view line) -> DevCommand;

// --- SEH-guarded memory ops (platform; defined in the .cpp) ----------------

// Copy `len` bytes FROM engine address `addr` into `out` under an SEH guard. Returns
// false (and leaves `out` empty) if the read faults. Safe to call while the engine runs.
[[nodiscard]] auto SafeReadMemory(std::uint32_t addr, std::size_t len,
                                  std::vector<std::uint8_t>& out) -> bool;

// Write `bytes` TO engine address `addr` under an SEH guard (flipping page protection as
// needed). Returns false if the write faults.
[[nodiscard]] auto SafeWriteMemory(std::uint32_t addr, const std::vector<std::uint8_t>& bytes)
    -> bool;

// Engine-touching commands (call/bt/bp/bc/hook) need DLL-side code (asm invoker, the tick
// thread, VEH/DbgHelp) the host-testable lib can't provide. The DLL registers a handler;
// peek/poke are always handled here directly. If no handler is set, those verbs report so.
using DevEngineHandler = auto (*)(const DevCommand&) -> std::string;
void SetDevEngineHandler(DevEngineHandler handler);

// Execute one parsed command and return the ASCII response text (no trailing newline).
[[nodiscard]] auto ExecuteDevCommand(const DevCommand& cmd) -> std::string;

// --- The TCP server --------------------------------------------------------

// Starts a localhost listener on `port` (process-lifetime, leaked like the logger/runtime
// to avoid teardown joins). No-op if port == 0 or already started. Returns false if the
// socket bind fails. One client at a time; each recv'd line is parsed + executed +
// answered. Localhost-bound only.
[[nodiscard]] auto StartDevConsole(std::uint16_t port) -> bool;

}  // namespace wfh::server
