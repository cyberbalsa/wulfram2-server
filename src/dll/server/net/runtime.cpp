#include "wfh/server/runtime.hpp"

#include "wfh/log.hpp"

#include <memory>
#include <utility>

// Every WFH_* logging call expands to the project's intentional do-while(0) guard
// macro that forwards a printf-style C variadic to Log::Write. Suppress the two
// macro-inherent findings file-wide so the call sites stay readable; all other
// checks remain on.
// NOLINTBEGIN(cppcoreguidelines-avoid-do-while,cppcoreguidelines-pro-type-vararg)
namespace wfh::server {

ServerRuntime::~ServerRuntime() {
    Stop();
}

auto ServerRuntime::Start(ServerConfig cfg) -> bool {
    if (Running()) {
        WFH_DEBUG("runtime", "Start ignored; runtime already running on port %u",
                  static_cast<unsigned>(BoundPort()));
        return true;
    }

    WFH_DEBUG("runtime", "starting socket runtime bind_port=%u tick_hz=%u map=%s",
              static_cast<unsigned>(cfg.bind_port), static_cast<unsigned>(cfg.tick_hz),
              cfg.map.c_str());
    cfg_ = cfg;
    auto next = std::make_unique<Acceptor>(std::move(cfg), inbound_, outbound_);
    if (!next->Start()) {
        WFH_ERROR("runtime", "socket runtime start failed");
        return false;
    }

    acceptor_ = std::move(next);
    WFH_DEBUG("runtime", "socket runtime started bound_port=%u",
              static_cast<unsigned>(BoundPort()));
    return true;
}

void ServerRuntime::Stop() {
    if (acceptor_) {
        WFH_DEBUG("runtime", "stopping socket runtime on port %u",
                  static_cast<unsigned>(BoundPort()));
        acceptor_->Stop();
        acceptor_.reset();
        WFH_DEBUG("runtime", "socket runtime stopped");
    } else {
        WFH_TRACE("runtime", "Stop ignored; runtime is not running");
    }
}

auto ServerRuntime::Running() const -> bool {
    return acceptor_ != nullptr && acceptor_->Running();
}

auto ServerRuntime::BoundPort() const -> std::uint16_t {
    return acceptor_ ? acceptor_->BoundPort() : 0;
}

auto ProcessRuntime() -> ServerRuntime& {
    // NOLINTNEXTLINE(cppcoreguidelines-owning-memory,modernize-use-auto)
    static ServerRuntime* const runtime = new ServerRuntime();  // intentionally leaked
    return *runtime;
}

}  // namespace wfh::server
// NOLINTEND(cppcoreguidelines-avoid-do-while,cppcoreguidelines-pro-type-vararg)
