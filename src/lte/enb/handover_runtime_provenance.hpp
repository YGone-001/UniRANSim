//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

// Phase 18-F-B3: where a running source eNB gets the values a handover needs.
//
// The codecs in src/lte/rrc and src/lte/enb/transparent_container turn typed
// data into octets. This module is the typed data's origin: a cell identity a
// runtime authority owns, a UE history recorded from real serving-cell
// transitions on a monotonic clock, and an immutable snapshot of one source
// session that the container builder consumes. Nothing here invents a value to
// make an encoder succeed: what a runtime cannot supply is reported as missing
// and the builder refuses.
//
// Provenance is the spine. A decoded value is WIRE_UNVERIFIED until a runtime
// authority raises it, and decoding is not an authority. A fixture stays a
// fixture. A runtime observation is only what this module itself recorded.

#pragma once

#include "types.hpp"

#include <lte/rrc/rrc_handover.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <lte/enb/transparent_container.hpp>

namespace lte::enb
{
namespace s1ap
{
struct SourceSession;
}

// --- Cell identity authority ------------------------------------------------

// Who established that this E-UTRAN CGI is the cell it claims to be. A
// physical cell identity alone is not a globally unique E-UTRAN CGI, and
// nothing here infers one from a TAC, a PLMN, a transport address or a TEID.
enum class CellIdentityAuthority : uint8_t
{
    // Read from this eNB's own configuration: it owns the cell.
    LOCAL_CONFIGURATION,
    // An authorized simulator inventory entry that is current.
    SIMULATOR_INVENTORY,
    // Decoded from a peer's bytes or supplied with no verification behind it.
    WIRE_UNVERIFIED
};

const char *ToString(CellIdentityAuthority authority);

struct VerifiedCellIdentity
{
    Plmn plmn;
    uint32_t cellId{};   // the complete 28-bit E-UTRAN cell identity
    uint16_t tac{};
    uint32_t ownerEnbId{};
    // The configuration generation this identity belongs to. A cell identity
    // from an earlier generation is stale and must not be used.
    uint64_t configEpoch{};
    CellIdentityAuthority authority{CellIdentityAuthority::WIRE_UNVERIFIED};
    // Whether this cell is an authorized target for a handover. The real MME
    // selects the target in S1; this flag is the simulator's own statement.
    bool targetCandidate{};

    [[nodiscard]] bool verified() const { return authority != CellIdentityAuthority::WIRE_UNVERIFIED; }
    [[nodiscard]] bool sameCell(const VerifiedCellIdentity &other) const;
};

// The cell this eNB serves, read out of its own configuration. The local cell
// identifier is zero for this one-cell simulator, as the S1AP CGI encoder
// already states.
VerifiedCellIdentity OwnCellIdentity(const EnbConfig &config, uint64_t configEpoch);

// --- Simulator target inventory ---------------------------------------------

// The isolated simulator's authorized target cells. An entry that has gone
// stale must not resolve: publishing a new generation invalidates the old one.
class TargetInventory
{
  public:
    // Publishes a cell as an authorized target under the current generation.
    void Publish(const VerifiedCellIdentity &cell);
    // Advances the generation, invalidating every earlier entry.
    void AdvanceGeneration();
    // Resolves a target by its complete identity. Returns nothing when the
    // cell is unknown, stale or not an authorized target.
    [[nodiscard]] std::optional<VerifiedCellIdentity> Resolve(const Plmn &plmn, uint32_t cellId) const;
    [[nodiscard]] uint64_t generation() const { return m_generation; }

  private:
    struct Entry
    {
        VerifiedCellIdentity cell;
        uint64_t generation{};
        bool stale{};
    };
    uint64_t m_generation{1};
    std::vector<Entry> m_entries;
};

// --- Serving-cell history ---------------------------------------------------

// One observed stay of one EPS session in one cell. The interval is measured on
// a monotonic clock; the wall clock never enters it.
struct ServingCellVisit
{
    VerifiedCellIdentity cell;
    std::chrono::steady_clock::time_point enteredAt{};
    std::chrono::steady_clock::time_point leftAt{};
    // The stay exceeded the 0..4095 range TS 36.413 allows. The value is
    // saturated at 4095 and this flag says so; a saturated duration is not the
    // measured duration.
    bool saturated{};
    s1ap::HistoryProvenance provenance{s1ap::HistoryProvenance::RUNTIME_OBSERVED};

    // Seconds in the cell, saturated to the normative range.
    [[nodiscard]] uint16_t timeStayedInCell() const;
    [[nodiscard]] bool complete() const { return leftAt.time_since_epoch().count() != 0; }
};

// The bounded history of one EPS session. It belongs to that session's
// serving-cell lifecycle and is never shared between UEs.
class ServingCellHistory
{
  public:
    static constexpr size_t MaxEntries = 16;

    // A cell becomes the session's serving cell: an initial Attach completing,
    // an idle reselection arriving at a new cell, or a connected handover
    // arriving at the target.
    void BeginVisit(const VerifiedCellIdentity &cell, std::chrono::steady_clock::time_point now);
    // The session stops being served here without a cell change: an ECM-IDLE
    // access release, a source-context release, a Detach. This completes the
    // current interval and starts no new one.
    void EndCurrentVisit(std::chrono::steady_clock::time_point now);
    // A genuine cell change: the current interval completes and the next cell's
    // begins in the same call, so no event can open a visit twice.
    void ReselectTo(const VerifiedCellIdentity &cell, std::chrono::steady_clock::time_point now);
    // A fresh Attach begins a new EPS session: the old history is closed and a
    // new visit starts, and no earlier cell is invented for the new session.
    void StartNewEpsSession(const VerifiedCellIdentity &cell, std::chrono::steady_clock::time_point now);

    // The visits, most recent last, at most `max` entries. When more happened,
    // the oldest are dropped and the set is marked truncated and its
    // predecessor unknown: the history is valid but shorter than the truth.
    [[nodiscard]] std::vector<ServingCellVisit> Bounded(size_t max = MaxEntries) const;
    [[nodiscard]] bool truncated() const { return m_truncated; }
    [[nodiscard]] bool unknownPredecessor() const { return m_truncated; }
    [[nodiscard]] bool hasCurrentVisit() const { return m_current; }

  private:
    std::vector<ServingCellVisit> m_visits;
    bool m_current{};
    bool m_truncated{};
};

// --- Source runtime snapshot ------------------------------------------------

// An immutable record of the handover-relevant state of one source session. It
// can only be created by BuildSourceHandoverRuntimeSnapshot, so a caller cannot
// assemble one out of fields it chose and then assert that it is verified.
struct SourceHandoverSnapshot
{
    // The source context generation this snapshot belongs to. A snapshot from
    // an earlier generation is stale and may not authorize a new transaction.
    uint64_t sessionGeneration{};
    VerifiedCellIdentity sourceCell;
    uint32_t radioUeId{};
    uint32_t enbUeS1apId{};
    uint32_t mmeUeS1apId{};
    uint32_t accessGeneration{};
    uint64_t associationEpoch{};
    uint8_t defaultEbi{};
    std::vector<uint8_t> dedicatedEbis;
    std::vector<ServingCellVisit> history;
    bool historyTruncated{};
    std::optional<VerifiedCellIdentity> approvedTarget;
    uint64_t targetInventoryGeneration{};

    SourceHandoverSnapshot() = default;

  private:
    friend struct SnapshotBuilderAccess;
};

// Everything the builder needs, and nothing it can invent: every input is a
// live runtime object the caller already owns.
struct SnapshotInputs
{
    const EnbConfig *config{};
    uint64_t configEpoch{};
    // The session as ExtractSourceSession read it out of the live registry.
    const s1ap::SourceSession *session{};
    uint64_t sessionGeneration{};
    const ServingCellHistory *history{};
    const TargetInventory *inventory{};
    // The target the handover is for. It must resolve in the inventory.
    std::optional<Plmn> targetPlmn;
    std::optional<uint32_t> targetCellId;
};

struct SnapshotResult
{
    std::optional<SourceHandoverSnapshot> snapshot;
    std::vector<std::string> missingInputs;

    [[nodiscard]] bool ok() const { return snapshot.has_value() && missingInputs.empty(); }
};

SnapshotResult BuildSourceHandoverRuntimeSnapshot(const SnapshotInputs &inputs);

// --- Runtime handover preparation ------------------------------------------

// One field of the provenance manifest: what the value is and where it came
// from. It is the auditable statement that no fixture reached a live-use
// container.
using ProvenanceManifest = std::vector<std::pair<std::string, std::string>>;

struct PreparationResult
{
    bool ok{};
    std::vector<uint8_t> container;
    std::vector<std::string> missingInputs;
    ProvenanceManifest manifest;
};

// Builds the complete source-to-target transparent container from a verified
// snapshot and the RRC message the source can state. Every mandatory input is
// checked first; a missing one is named and nothing is encoded. It reuses the
// accepted codecs and creates no second encoder.
//
// This produces offline bytes. It authorizes nothing and transmits nothing.
PreparationResult BuildRuntimeHandoverPreparation(const SourceHandoverSnapshot &snapshot,
                                                  const lte::rrc::HandoverPreparation &rrcMessage);

} // namespace lte::enb
