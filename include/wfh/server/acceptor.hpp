// NOLINTBEGIN(portability-avoid-pragma-once)
// pragma once is the project-wide include-guard convention; intentional.
#pragma once
// NOLINTEND(portability-avoid-pragma-once)

#include "wfh/server/queues.hpp"
#include "wfh/server/server_config.hpp"

#include <atomic>
#include <cstdint>
#include <memory>
#include <thread>

namespace wfh::server {

// The network I/O front end. Owns the TCP listen socket + the UDP socket and a
// single I/O thread that select()-multiplexes the listener, all accepted TCP
// connections, and the UDP socket. ALL socket work and ALL untrusted parsing live
// on this thread; it pushes validated ClientCommands to `inbound` and pops
// OutboundMessages from `outbound` to send. It NEVER calls engine code — that is
// the cardinal isolation rule (see the plan's threading model).
//
// Concurrency choice: a SINGLE select-based I/O thread (not thread-per-connection).
// For a 2006-era game server the connection count is small (tens), select() handles
// the whole fd set cheaply, and one thread sidesteps per-connection locking entirely
// — the only shared state is the two already-thread-safe queues. Simple and robust.
class Acceptor {
public:
    Acceptor(ServerConfig cfg, IncomingCmdQueue& inbound, OutboundStateQueue& outbound);
    ~Acceptor();

    Acceptor(const Acceptor&) = delete;
    auto operator=(const Acceptor&) -> Acceptor& = delete;
    Acceptor(Acceptor&&) = delete;
    auto operator=(Acceptor&&) -> Acceptor& = delete;

    // Bind TCP+UDP on cfg.bind_port and start the I/O thread. Returns false if the
    // sockets could not be created/bound (port in use, WSA failure, etc.).
    [[nodiscard]] auto Start() -> bool;

    // Signal the I/O thread to stop and join it. Safe to call more than once.
    void Stop();

    [[nodiscard]] auto Running() const -> bool { return running_.load(); }
    [[nodiscard]] auto BoundPort() const -> std::uint16_t { return bound_port_; }

    // Opaque to callers (defined in acceptor.cpp where WinSock types are in scope);
    // public only so the file-local I/O helpers in acceptor.cpp can name it.
    struct Impl;

private:
    void Run();

    ServerConfig cfg_;
    IncomingCmdQueue& inbound_;
    OutboundStateQueue& outbound_;
    std::unique_ptr<Impl> impl_;
    std::thread thread_;
    std::atomic<bool> running_{false};
    std::atomic<bool> stop_{false};
    std::uint16_t bound_port_ = 0;
};

}  // namespace wfh::server
