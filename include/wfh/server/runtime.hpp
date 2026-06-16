// NOLINTBEGIN(portability-avoid-pragma-once)
// pragma once is the project-wide include-guard convention; intentional.
#pragma once
// NOLINTEND(portability-avoid-pragma-once)

#include "wfh/server/acceptor.hpp"
#include "wfh/server/queues.hpp"
#include "wfh/server/server_config.hpp"

#include <cstdint>
#include <memory>

namespace wfh::server {

// Process-lifetime owner for the independent network front end. This class owns
// only socket/session state plus the queue boundary. Engine memory is still owned
// exclusively by the tick thread; bridge code will drain/push these queues later.
class ServerRuntime {
public:
    ServerRuntime() = default;
    ~ServerRuntime();

    ServerRuntime(const ServerRuntime&) = delete;
    auto operator=(const ServerRuntime&) -> ServerRuntime& = delete;
    ServerRuntime(ServerRuntime&&) = delete;
    auto operator=(ServerRuntime&&) -> ServerRuntime& = delete;

    [[nodiscard]] auto Start(ServerConfig cfg) -> bool;
    void Stop();

    [[nodiscard]] auto Running() const -> bool;
    [[nodiscard]] auto BoundPort() const -> std::uint16_t;
    [[nodiscard]] auto Config() const -> const ServerConfig& { return cfg_; }

    [[nodiscard]] auto Inbound() -> IncomingCmdQueue& { return inbound_; }
    [[nodiscard]] auto Outbound() -> OutboundStateQueue& { return outbound_; }

private:
    ServerConfig cfg_;
    IncomingCmdQueue inbound_;
    OutboundStateQueue outbound_;
    std::unique_ptr<Acceptor> acceptor_;
};

// Intentionally leaked for the injected process lifetime, mirroring the logger.
// This prevents socket-thread joins during CRT/static teardown near loader-lock
// sensitive process exit. Tests may instantiate ServerRuntime directly.
[[nodiscard]] auto ProcessRuntime() -> ServerRuntime&;

}  // namespace wfh::server
