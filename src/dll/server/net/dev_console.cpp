#include "wfh/server/dev_console.hpp"

#include "wfh/log.hpp"

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
// windows.h after winsock2.h to avoid winsock1 clash.
#include <windows.h>

#include <array>
#include <charconv>
#include <cstring>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

// WFH_* logging macros expand to the project's do-while(0) printf-variadic guard; suppress
// the two macro-inherent findings file-wide (matches the other server TUs).
// NOLINTBEGIN(cppcoreguidelines-avoid-do-while,cppcoreguidelines-pro-type-vararg)
namespace wfh::server {

namespace {

constexpr std::uint8_t kHexLetterBase = 10;    // 'a'/'A' encodes nibble value 10
constexpr std::size_t kMaxHexU32Digits = 8;    // a u32 is at most 8 hex digits
constexpr std::uint8_t kAsciiPrintMin = 0x20;  // ' '
constexpr std::uint8_t kAsciiPrintMax = 0x7E;  // '~'
constexpr std::uint8_t kLowNibbleMask = 0x0FU;
constexpr std::size_t kHexBytesPerLine = 16;
constexpr std::array<char, 16> kHexDigitChars = {'0', '1', '2', '3', '4', '5', '6', '7',
                                                 '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

auto HexNibble(char chr, std::uint8_t& out) -> bool {
    if (chr >= '0' && chr <= '9') {
        out = static_cast<std::uint8_t>(chr - '0');
    } else if (chr >= 'a' && chr <= 'f') {
        out = static_cast<std::uint8_t>(chr - 'a' + kHexLetterBase);
    } else if (chr >= 'A' && chr <= 'F') {
        out = static_cast<std::uint8_t>(chr - 'A' + kHexLetterBase);
    } else {
        return false;
    }
    return true;
}

auto StripHexPrefix(std::string_view text) -> std::string_view {
    if (text.size() >= 2) {
        const std::string_view head = text.substr(0, 2);
        if (head == "0x" || head == "0X") {
            return text.substr(2);
        }
    }
    return text;
}

// SEH-isolated raw copies: kept C-like (no objects needing unwinding) so MSVC accepts the
// __try, exactly like tick_guard's RunProtectedRaw. memcpy faults are swallowed.
auto RawCopy(void* dst, const void* src, std::size_t len) -> bool {
    __try {
        std::memcpy(dst, src, len);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

}  // namespace

auto ParseHexU32(std::string_view text, std::uint32_t& out) -> bool {
    const std::string_view body = StripHexPrefix(text);
    if (body.empty() || body.size() > kMaxHexU32Digits) {
        return false;
    }
    std::uint32_t value = 0;
    for (const char chr : body) {
        std::uint8_t nibble = 0;
        if (!HexNibble(chr, nibble)) {
            return false;
        }
        value = (value << 4U) | nibble;
    }
    out = value;
    return true;
}

auto ParseHexBytes(std::string_view text, std::vector<std::uint8_t>& out) -> bool {
    const std::string_view body = StripHexPrefix(text);
    if (body.empty() || (body.size() % 2) != 0 || (body.size() / 2) > kDevMaxPokeLen) {
        return false;
    }
    out.clear();
    out.reserve(body.size() / 2);
    for (std::size_t i = 0; i < body.size(); i += 2) {
        std::uint8_t high = 0;
        std::uint8_t low = 0;
        if (!HexNibble(body.at(i), high) || !HexNibble(body.at(i + 1), low)) {
            out.clear();
            return false;
        }
        out.push_back(static_cast<std::uint8_t>((high << 4U) | low));
    }
    return true;
}

auto HexDumpBytes(std::uint32_t base_addr, const std::uint8_t* data, std::size_t len)
    -> std::string {
    std::ostringstream out;
    out << std::hex;
    for (std::size_t off = 0; off < len; off += kHexBytesPerLine) {
        const std::uint32_t line_addr = base_addr + static_cast<std::uint32_t>(off);
        out << "0x" << line_addr << ": ";
        std::string ascii;
        for (std::size_t col = 0; col < kHexBytesPerLine; ++col) {
            if (off + col < len) {
                // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
                const std::uint8_t byte = data[off + col];
                out << kHexDigitChars.at(byte >> 4U) << kHexDigitChars.at(byte & kLowNibbleMask)
                    << ' ';
                const bool printable = byte >= kAsciiPrintMin && byte <= kAsciiPrintMax;
                ascii.push_back(printable ? static_cast<char>(byte) : '.');
            } else {
                out << "   ";
            }
        }
        out << " |" << ascii << "|\n";
    }
    return out.str();
}

namespace {

// Per-verb argument fillers, split out to keep ParseDevCommand's cognitive complexity low.
void FillPeek(const std::vector<std::string>& tok, DevCommand& cmd) {
    if (tok.size() < 3 || !ParseHexU32(tok.at(1), cmd.addr)) {
        cmd.error = "usage: peek <hexaddr> <len>";
        return;
    }
    std::uint32_t len = 0;
    const std::string& num = tok.at(2);
    const char* first = num.data();
    const char* last =
        first + num.size();  // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    if (std::from_chars(first, last, len).ec != std::errc{} || len == 0 || len > kDevMaxPeekLen) {
        cmd.error = "peek len must be 1..4096 (decimal)";
        return;
    }
    cmd.kind = DevCmdKind::Peek;
    cmd.len = len;
}

void FillPoke(const std::vector<std::string>& tok, DevCommand& cmd) {
    if (tok.size() < 3 || !ParseHexU32(tok.at(1), cmd.addr) ||
        !ParseHexBytes(tok.at(2), cmd.bytes)) {
        cmd.error = "usage: poke <hexaddr> <hexbytes>";
        return;
    }
    cmd.kind = DevCmdKind::Poke;
}

auto AddrVerbKind(const std::string& verb) -> DevCmdKind {
    if (verb == "call") {
        return DevCmdKind::Call;
    }
    if (verb == "bp") {
        return DevCmdKind::Break;
    }
    if (verb == "bc") {
        return DevCmdKind::BreakClear;
    }
    return DevCmdKind::Hook;
}

void FillAddrVerb(const std::vector<std::string>& tok, const std::string& verb, DevCommand& cmd) {
    if (tok.size() < 2 || !ParseHexU32(tok.at(1), cmd.addr)) {
        cmd.error = "usage: " + verb + " <hexaddr> ...";
        return;
    }
    cmd.kind = AddrVerbKind(verb);
}

auto ConvOk(const std::string& conv) -> bool {
    return conv == "cdecl" || conv == "stdcall" || conv == "thiscall" || conv == "fastcall";
}

void FillCall(const std::vector<std::string>& tok, DevCommand& cmd) {
    if (tok.size() < 3 || !ParseHexU32(tok.at(1), cmd.addr) || !ConvOk(tok.at(2))) {
        cmd.error = "usage: call <hexaddr> <cdecl|stdcall|thiscall|fastcall> [hexargs...]";
        return;
    }
    cmd.conv = tok.at(2);
    for (std::size_t i = 3; i < tok.size(); ++i) {
        std::uint32_t arg = 0;
        if (!ParseHexU32(tok.at(i), arg)) {
            cmd.error = "call args must be hex u32";
            return;
        }
        cmd.args.push_back(arg);
    }
    cmd.kind = DevCmdKind::Call;
}

// The DLL-registered engine handler lives in a function-local static (off file scope).
auto EngineHandlerSlot() -> DevEngineHandler& {
    static DevEngineHandler handler = nullptr;
    return handler;
}

}  // namespace

void SetDevEngineHandler(DevEngineHandler handler) {
    EngineHandlerSlot() = handler;
}

auto ParseDevCommand(std::string_view line) -> DevCommand {
    DevCommand cmd;
    std::istringstream stream{std::string(line)};
    std::vector<std::string> tok;
    for (std::string word; stream >> word;) {
        tok.push_back(word);
    }
    if (tok.empty()) {
        return cmd;  // blank line: Unknown, no error
    }
    const std::string& verb = tok.front();
    if (verb == "help" || verb == "?") {
        cmd.kind = DevCmdKind::Help;
    } else if (verb == "peek") {
        FillPeek(tok, cmd);
    } else if (verb == "poke") {
        FillPoke(tok, cmd);
    } else if (verb == "bt") {
        cmd.kind = DevCmdKind::Backtrace;
    } else if (verb == "call") {
        FillCall(tok, cmd);
    } else if (verb == "bp" || verb == "bc" || verb == "hook") {
        FillAddrVerb(tok, verb, cmd);
    } else {
        cmd.error = "unknown command '" + verb + "' (try: help)";
    }
    return cmd;
}

// addr/len are distinct concepts (address vs byte count); the swap check is a false alarm.
// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
auto SafeReadMemory(std::uint32_t addr, std::size_t len, std::vector<std::uint8_t>& out) -> bool {
    out.assign(len, 0);
    // NOLINTNEXTLINE(performance-no-int-to-ptr,cppcoreguidelines-pro-type-reinterpret-cast)
    const void* src = reinterpret_cast<const void*>(static_cast<std::uintptr_t>(addr));
    if (!RawCopy(out.data(), src, len)) {
        out.clear();
        return false;
    }
    return true;
}

auto SafeWriteMemory(std::uint32_t addr, const std::vector<std::uint8_t>& bytes) -> bool {
    if (bytes.empty()) {
        return false;
    }
    // NOLINTNEXTLINE(performance-no-int-to-ptr,cppcoreguidelines-pro-type-reinterpret-cast)
    void* dst = reinterpret_cast<void*>(static_cast<std::uintptr_t>(addr));
    DWORD old_protect = 0;
    const BOOL unlocked = VirtualProtect(dst, bytes.size(), PAGE_EXECUTE_READWRITE, &old_protect);
    const bool wrote = RawCopy(dst, bytes.data(), bytes.size());
    if (unlocked != FALSE) {
        DWORD ignore = 0;
        VirtualProtect(dst, bytes.size(), old_protect, &ignore);
        FlushInstructionCache(GetCurrentProcess(), dst, bytes.size());
    }
    return wrote;
}

auto ExecuteDevCommand(const DevCommand& cmd) -> std::string {
    if (!cmd.error.empty()) {
        return "err: " + cmd.error;
    }
    switch (cmd.kind) {
    case DevCmdKind::Help:
        return "commands: peek <hexaddr> <len> | poke <hexaddr> <hexbytes> | bt | "
               "call/bp/bc/hook <hexaddr> (increment 2/3) | help";
    case DevCmdKind::Peek: {
        std::vector<std::uint8_t> data;
        if (!SafeReadMemory(cmd.addr, cmd.len, data)) {
            return "err: read faulted at the given address";
        }
        return HexDumpBytes(cmd.addr, data.data(), data.size());
    }
    case DevCmdKind::Poke: {
        if (!SafeWriteMemory(cmd.addr, cmd.bytes)) {
            return "err: write faulted at the given address";
        }
        std::ostringstream out;
        out << "ok: wrote " << cmd.bytes.size() << " byte(s) to 0x" << std::hex << cmd.addr;
        return out.str();
    }
    case DevCmdKind::Backtrace:
    case DevCmdKind::Call:
    case DevCmdKind::Break:
    case DevCmdKind::BreakClear:
    case DevCmdKind::Hook: {
        const DevEngineHandler handler = EngineHandlerSlot();
        if (handler != nullptr) {
            return handler(cmd);
        }
        return "err: engine handler not registered (call/bt/bp/bc/hook need the injected DLL)";
    }
    case DevCmdKind::Unknown: return "err: unknown command (try: help)";
    }
    return "err: unhandled";
}

namespace {

// Send an ASCII line (appends newline) on a connected socket.
void SendLine(SOCKET sock, const std::string& text) {
    std::string out = text;
    if (out.empty() || out.back() != '\n') {
        out.push_back('\n');
    }
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    send(sock, out.data(), static_cast<int>(out.size()), 0);
}

constexpr int kDevRecvChunk = 2048;

// Service one connected dev client: read lines, execute, answer, until it disconnects.
void ServeClient(SOCKET client) {
    SendLine(client, "wulf-forge dev console — type 'help'");
    std::string pending;
    std::array<char, kDevRecvChunk> buf{};
    for (;;) {
        const int got = recv(client, buf.data(), static_cast<int>(buf.size()), 0);
        if (got <= 0) {
            return;  // client closed or error
        }
        pending.append(buf.data(), static_cast<std::size_t>(got));
        std::size_t nl = pending.find('\n');
        while (nl != std::string::npos) {
            std::string line = pending.substr(0, nl);
            pending.erase(0, nl + 1);
            if (!line.empty() && line.back() == '\r') {
                line.pop_back();
            }
            const DevCommand cmd = ParseDevCommand(line);
            const std::string response = ExecuteDevCommand(cmd);
            WFH_DEBUG("dev", "cmd='%s' -> %zu byte response", line.c_str(), response.size());
            SendLine(client, response);
            nl = pending.find('\n');
        }
    }
}

void DevConsoleLoop(SOCKET listener) {
    for (;;) {
        const SOCKET client = accept(listener, nullptr, nullptr);
        if (client == INVALID_SOCKET) {
            return;  // listener closed
        }
        WFH_INFO("dev", "dev console client connected");
        ServeClient(client);
        closesocket(client);
        WFH_INFO("dev", "dev console client disconnected");
    }
}

}  // namespace

auto StartDevConsole(std::uint16_t port) -> bool {
    static bool started = false;
    if (port == 0 || started) {
        return false;
    }

    WSADATA wsa{};
    WSAStartup(MAKEWORD(2, 2), &wsa);

    const SOCKET listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listener == INVALID_SOCKET) {
        WFH_WARN("dev", "dev console socket() failed wsa=%d", WSAGetLastError());
        return false;
    }
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);  // localhost-only
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    if (bind(listener, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR ||
        listen(listener, 1) == SOCKET_ERROR) {
        WFH_WARN("dev", "dev console bind/listen failed port=%u wsa=%d",
                 static_cast<unsigned>(port), WSAGetLastError());
        closesocket(listener);
        return false;
    }

    started = true;
    WFH_INFO("dev", "dev console listening on 127.0.0.1:%u", static_cast<unsigned>(port));
    // Detached, process-lifetime thread (leaked like the runtime/logger to avoid teardown
    // joins near loader-lock-sensitive exit).
    std::thread(DevConsoleLoop, listener).detach();
    return true;
}

}  // namespace wfh::server
// NOLINTEND(cppcoreguidelines-avoid-do-while,cppcoreguidelines-pro-type-vararg)
