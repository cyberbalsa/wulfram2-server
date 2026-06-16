// NOLINTBEGIN(portability-avoid-pragma-once)
// pragma once is the project-wide include-guard convention; intentional.
#pragma once
// NOLINTEND(portability-avoid-pragma-once)

#include <condition_variable>
#include <cstdint>
#include <deque>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace wfh::server {

// ===========================================================================
// The thread boundary between the (untrusted) network I/O threads and the
// (single-threaded, non-thread-safe) engine tick thread.
//
// Inbound: net threads parse + VALIDATE bytes into POD ClientCommands and push
// them here; the engine tick thread drains and applies them (M5.2). Outbound:
// the tick thread snapshots authoritative state into OutboundMessages; net
// threads pop and send them per connection (M6.1). No engine pointer ever
// crosses this boundary — everything here is plain data, copied by value.
// ===========================================================================

// Kinds of validated command the engine side will act on.
// NOLINTNEXTLINE(performance-enum-size)
enum class ClientCommandKind : int {
    ClientConnected,  // a connection reached VERIFIED (logged in)
    LoginUser,        // username string received
    LoginPassword,    // password string received
    ActionInput,      // analog control channel value for the session's entity
    WantUpdates,      // client is ready to receive world updates (0x39)
    Reincarnate,      // respawn request (team/unit/pad selection)
    Disconnected,     // connection closed/dropped
};

// One validated command from a connection to the engine. POD-ish: trivially
// copyable fields only. `session_id` identifies the originating connection so the
// engine side can map it to the owning entity (never trust client-asserted ids).
struct ClientCommand {
    ClientCommandKind kind = ClientCommandKind::Disconnected;
    std::uint64_t session_id = 0;

    // ActionInput payload (validated: channel in range, value clamped to [-1,1]).
    std::int32_t channel = 0;
    float value = 0.0F;

    // Reincarnate payload (validated ranges applied before enqueue).
    std::int32_t team = 0;
    std::int32_t unit_id = 0;
    std::int32_t pad_id = 0;

    // LoginUser / LoginPassword payload (already length/charset validated).
    std::string text;
};

// One outbound message for a specific connection, already serialized to wire bytes
// (the engine/relay side builds these; net threads just send them). `reliable`
// selects TCP vs UDP transport.
struct OutboundMessage {
    std::uint64_t session_id = 0;
    bool reliable = true;
    std::vector<std::uint8_t> bytes;
};

// A simple mutex+condvar FIFO. Correct and obvious over clever; the boundary
// traffic is modest (commands/snapshots per tick), so contention is a non-issue.
template <typename T> class ConcurrentQueue {
public:
    void Push(T item) {
        {
            const std::scoped_lock lock(mutex_);
            items_.push_back(std::move(item));
        }
        cv_.notify_one();
    }

    // Non-blocking pop. nullopt if empty.
    [[nodiscard]] auto TryPop() -> std::optional<T> {
        const std::scoped_lock lock(mutex_);
        if (items_.empty()) {
            return std::nullopt;
        }
        T item = std::move(items_.front());
        items_.pop_front();
        return item;
    }

    // Drain everything currently queued (engine tick drains inbound once per tick).
    [[nodiscard]] auto DrainAll() -> std::vector<T> {
        const std::scoped_lock lock(mutex_);
        std::vector<T> out(std::make_move_iterator(items_.begin()),
                           std::make_move_iterator(items_.end()));
        items_.clear();
        return out;
    }

    [[nodiscard]] auto Empty() const -> bool {
        const std::scoped_lock lock(mutex_);
        return items_.empty();
    }

    [[nodiscard]] auto Size() const -> std::size_t {
        const std::scoped_lock lock(mutex_);
        return items_.size();
    }

private:
    mutable std::mutex mutex_;
    std::condition_variable cv_;
    std::deque<T> items_;
};

using IncomingCmdQueue = ConcurrentQueue<ClientCommand>;
using OutboundStateQueue = ConcurrentQueue<OutboundMessage>;

}  // namespace wfh::server
