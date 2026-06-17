// NOLINTBEGIN(portability-avoid-pragma-once)
// pragma once is the project-wide include-guard convention; intentional.
#pragma once
// NOLINTEND(portability-avoid-pragma-once)

#include "wfh/server/queues.hpp"

#include <array>
#include <cstdint>
#include <functional>
#include <map>
#include <string>
#include <string_view>
#include <vector>

namespace wfh::server {

constexpr std::int32_t kDefaultCargoUnitType = 25;

struct MvpEntitySnapshot {
    std::int32_t net_id = 0;
    std::int32_t unit_type = 0;
    std::int32_t team = 1;
    bool is_manned = true;
    std::array<float, 3> pos{0.0F, 0.0F, 0.0F};
    std::array<float, 3> vel{0.0F, 0.0F, 0.0F};
    std::array<float, 3> rot{0.0F, 0.0F, 0.0F};
    std::array<float, 3> spin{0.0F, 0.0F, 0.0F};
    float health = 1.0F;
    float energy = 1.0F;
    std::int32_t cargo_unit_type = kDefaultCargoUnitType;
};

struct WorldBootstrapConfig {
    std::string map_name = "bpass";
    std::string map_root = "data\\maps";
};

struct TankSpawnSpec {
    std::int32_t sequence = 0;
    std::int32_t net_id = 0;
    std::int32_t unit_type = 0;
    std::int32_t team = 1;
    std::array<float, 3> pos{0.0F, 0.0F, 0.0F};
    std::array<float, 3> rot{0.0F, 0.0F, 0.0F};
};

[[nodiscard]] auto BuildBehavior() -> std::vector<std::uint8_t>;
[[nodiscard]] auto BuildTranslation() -> std::vector<std::uint8_t>;
[[nodiscard]] auto BuildViewUpdateSnapshot(std::int32_t sequence,
                                           const std::vector<MvpEntitySnapshot>& entities,
                                           float local_health, float local_energy)
    -> std::vector<std::uint8_t>;
[[nodiscard]] auto BuildTankSpawn(const TankSpawnSpec& spec) -> std::vector<std::uint8_t>;
[[nodiscard]] auto BuildReincarnateResult(std::uint8_t code, std::string_view message)
    -> std::vector<std::uint8_t>;
[[nodiscard]] auto BuildBirthNotice(std::int32_t player_id) -> std::vector<std::uint8_t>;

// Temporary MVP bridge: tick-owned session/world projection that feeds clients a
// visible tank snapshot while the engine spawn/read wrappers are being pinned. Net
// threads still only push validated commands; this bridge runs from the tick seam.
class MvpOnlineBridge {
public:
    MvpOnlineBridge(IncomingCmdQueue& inbound, OutboundStateQueue& outbound);
    MvpOnlineBridge(IncomingCmdQueue& inbound, OutboundStateQueue& outbound,
                    WorldBootstrapConfig bootstrap);

    void Tick(std::uint32_t sequence);

    // Returns the authoritative world to replicate (the M6.1 engine read). When set,
    // its result REPLACES the MVP placeholder entities (static pads + session tanks)
    // in every VIEW_UPDATE, so clients see the engine's real world. The provider is
    // invoked on the tick thread during snapshot emission.
    using WorldProvider = std::function<std::vector<MvpEntitySnapshot>()>;
    void SetWorldProvider(WorldProvider provider);

    // Spawns a REAL engine entity for a reincarnating player at its pad and returns the engine
    // oid (0 = not hosting / failed). When set (world_host mode), the player's tank becomes part
    // of the authoritative engine world the provider relays, so the TankSpawn id matches a tank
    // that actually appears in snapshots -- otherwise the client spawns a phantom that never shows
    // up, loses sync, and reports a protocol mismatch. Invoked on the tick thread in SpawnOnPad.
    using SpawnHandler = std::function<std::int32_t(
        std::int32_t team, const std::array<float, 3>& pos, const std::array<float, 3>& rot)>;
    void SetSpawnHandler(SpawnHandler handler);

    // Routes a decoded control-channel value to the engine entity that owns it. The bridge maps the
    // originating session to its spawned engine oid (session.entity.net_id) -- the client never
    // asserts which entity it drives. When set (world_host mode), the engine glue records the value
    // for the per-tank drive (M6.4). Invoked on the tick thread from HandleCommand(ActionInput).
    using InputHandler = std::function<void(std::int32_t oid, std::int32_t channel, float value)>;
    void SetInputHandler(InputHandler handler);

private:
    struct SessionState {
        std::uint64_t session_id = 0;
        std::int32_t player_id = 0;
        std::int32_t team = 1;
        std::string name;
        MvpEntitySnapshot entity;
        bool spawned = false;
        bool wants_updates = false;
        // net_ids this session has already been told about (DEFINITION sent once, then POS|ROT).
        std::vector<std::int32_t> introduced;
    };

    void HandleCommand(const ClientCommand& cmd, bool& visibility_changed, std::uint32_t sequence);
    void AddSession(const ClientCommand& cmd, bool& visibility_changed);
    void MarkWantUpdates(std::uint64_t session_id, bool& visibility_changed);
    void RemoveSession(std::uint64_t session_id, bool& visibility_changed);
    void HandleReincarnate(const ClientCommand& cmd, bool& visibility_changed,
                           std::uint32_t sequence);
    void HandleActionInput(const ClientCommand& cmd);
    void HandleTeamSwitch(SessionState& session, std::int32_t team);
    void SpawnOnPad(SessionState& session, const MvpEntitySnapshot& pad, std::uint32_t sequence,
                    bool& visibility_changed);
    void EmitRosterCatchup(const SessionState& joined);
    void LoadMapBootstrap();
    void LoadStateEntities();
    [[nodiscard]] auto ExistingRepairPadTeams() const -> std::array<bool, 3>;
    void EnsureFallbackRepairPads();
    void EmitSnapshots(std::uint32_t sequence);
    [[nodiscard]] auto EntitySnapshots() const -> std::vector<MvpEntitySnapshot>;
    [[nodiscard]] auto ResolveSpawnPad(const SessionState& session, std::int32_t selected_entry_id,
                                       std::int32_t base_id) const -> const MvpEntitySnapshot*;

    IncomingCmdQueue* inbound_;
    OutboundStateQueue* outbound_;
    WorldBootstrapConfig bootstrap_;
    std::map<std::uint64_t, SessionState> sessions_;
    std::vector<MvpEntitySnapshot> static_entities_;
    std::int32_t next_entity_id_ = 1;
    WorldProvider world_provider_;  // when set, supplies the authoritative world (M6.1)
    SpawnHandler spawn_handler_;    // when set (world_host), spawns the player's real engine tank
    InputHandler input_handler_;  // when set (world_host), records decoded input for the tank drive
};

// The process-lifetime MVP bridge (also the M6.1 relay once a world provider is set).
// Exposed so the engine-glue tick can arm its world provider with the live engine read.
[[nodiscard]] auto ProcessMvpBridge() -> MvpOnlineBridge&;
void ProcessMvpOnlineTick(std::uint32_t sequence);

}  // namespace wfh::server
