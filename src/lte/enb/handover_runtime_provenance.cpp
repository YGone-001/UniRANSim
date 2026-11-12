//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#include "handover_runtime_provenance.hpp"

#include <algorithm>
#include <utility>

#include "codec.hpp"
#include "handover_admission.hpp"
#include "handover_orchestration.hpp"

namespace lte::enb
{
namespace
{

using Clock = std::chrono::steady_clock;

// TS 36.413 Time-UE-StayedInCell ::= INTEGER (0..4095), in seconds.
constexpr long long kMaxStaySeconds = 4095;

} // namespace

const char *ToString(CellIdentityAuthority authority)
{
    switch (authority)
    {
    case CellIdentityAuthority::LOCAL_CONFIGURATION: return "LOCAL_CONFIGURATION";
    case CellIdentityAuthority::SIMULATOR_INVENTORY: return "SIMULATOR_INVENTORY";
    case CellIdentityAuthority::WIRE_UNVERIFIED: return "WIRE_UNVERIFIED";
    }
    return "UNKNOWN_CELL_IDENTITY_AUTHORITY";
}

bool VerifiedCellIdentity::sameCell(const VerifiedCellIdentity &other) const
{
    return plmn.mcc == other.plmn.mcc && plmn.mnc == other.plmn.mnc && cellId == other.cellId;
}

VerifiedCellIdentity OwnCellIdentity(const EnbConfig &config, uint64_t configEpoch)
{
    // The complete E-UTRAN CGI is the PLMN plus the 20-bit macro eNB
    // identifier and the 8-bit local cell identifier. This simulator serves
    // one cell per eNB, so the local part is zero — the same statement the
    // S1AP EUTRAN-CGI encoder makes.
    VerifiedCellIdentity identity;
    identity.plmn = config.plmn;
    identity.cellId = (config.enbId & 0xFFFFFU) << 8U;
    identity.tac = config.tac;
    identity.ownerEnbId = config.enbId;
    identity.configEpoch = configEpoch;
    identity.authority = CellIdentityAuthority::LOCAL_CONFIGURATION;
    identity.targetCandidate = true;
    return identity;
}

// --- Target inventory -------------------------------------------------------

void TargetInventory::Publish(const VerifiedCellIdentity &cell)
{
    Entry entry;
    entry.cell = cell;
    entry.cell.authority = CellIdentityAuthority::SIMULATOR_INVENTORY;
    entry.cell.targetCandidate = true;
    entry.generation = m_generation;
    entry.stale = false;
    // A re-published cell replaces the earlier entry for the same identity.
    for (auto &existing : m_entries)
    {
        if (existing.cell.sameCell(cell))
        {
            existing = entry;
            return;
        }
    }
    m_entries.push_back(entry);
}

void TargetInventory::AdvanceGeneration()
{
    ++m_generation;
    for (auto &entry : m_entries)
        entry.stale = true;
}

std::optional<VerifiedCellIdentity> TargetInventory::Resolve(const Plmn &plmn, uint32_t cellId) const
{
    for (const auto &entry : m_entries)
    {
        if (entry.stale)
            continue;
        if (!entry.cell.targetCandidate)
            continue;
        if (entry.cell.plmn.mcc != plmn.mcc || entry.cell.plmn.mnc != plmn.mnc)
            continue;
        if (entry.cell.cellId != cellId)
            continue;
        return entry.cell;
    }
    return std::nullopt;
}

// --- Serving-cell history ---------------------------------------------------

uint16_t ServingCellVisit::timeStayedInCell() const
{
    const auto seconds = std::chrono::duration_cast<std::chrono::seconds>(leftAt - enteredAt).count();
    if (seconds > kMaxStaySeconds)
        return static_cast<uint16_t>(kMaxStaySeconds);
    if (seconds <= 0)
        return 0;
    return static_cast<uint16_t>(seconds);
}

void ServingCellHistory::BeginVisit(const VerifiedCellIdentity &cell, Clock::time_point now)
{
    // Re-establishing access in the cell the session is already recorded in is
    // not a new cell visit: the stay was recorded when it happened and a later
    // access does not restate it. Only a genuine change of cell opens a new
    // entry.
    if (!m_visits.empty() && m_visits.back().cell.sameCell(cell))
    {
        m_current = true;
        return;
    }

    ServingCellVisit visit;
    visit.cell = cell;
    visit.enteredAt = now;
    visit.provenance = s1ap::HistoryProvenance::RUNTIME_OBSERVED;
    m_visits.push_back(visit);
    m_current = true;
    while (m_visits.size() > MaxEntries)
    {
        m_visits.erase(m_visits.begin());
        m_truncated = true;
    }
}

void ServingCellHistory::EndCurrentVisit(Clock::time_point now)
{
    if (!m_current || m_visits.empty())
        return;
    auto &visit = m_visits.back();
    if (!visit.complete())
    {
        visit.leftAt = now;
        visit.saturated =
            std::chrono::duration_cast<std::chrono::seconds>(now - visit.enteredAt).count() > kMaxStaySeconds;
    }
    m_current = false;
}

void ServingCellHistory::ReselectTo(const VerifiedCellIdentity &cell, Clock::time_point now)
{
    EndCurrentVisit(now);
    BeginVisit(cell, now);
}

void ServingCellHistory::StartNewEpsSession(const VerifiedCellIdentity &cell, Clock::time_point now)
{
    // A fresh Attach is a new EPS session: the earlier history belongs to the
    // earlier session and nothing from it is carried over, so no earlier cell
    // is invented for the new one.
    EndCurrentVisit(now);
    m_visits.clear();
    m_truncated = false;
    m_current = false;
    BeginVisit(cell, now);
}

std::vector<ServingCellVisit> ServingCellHistory::Bounded(size_t max) const
{
    const size_t keep = std::min(max, MaxEntries);
    if (m_visits.size() <= keep)
        return m_visits;
    return std::vector<ServingCellVisit>(m_visits.end() - static_cast<std::ptrdiff_t>(keep), m_visits.end());
}

// --- Source runtime snapshot ------------------------------------------------

SnapshotResult BuildSourceHandoverRuntimeSnapshot(const SnapshotInputs &inputs)
{
    SnapshotResult result;

    auto missing = [&result](std::string what) { result.missingInputs.push_back(std::move(what)); };

    if (inputs.config == nullptr)
        missing("the source eNB configuration is not available");
    if (inputs.session == nullptr)
        missing("the source session is not available");
    if (inputs.history == nullptr)
        missing("the UE serving-cell history is not available");
    if (inputs.inventory == nullptr)
        missing("the target inventory is not available");
    if (inputs.session != nullptr && inputs.sessionGeneration == 0)
        missing("the source context generation is unknown");
    if (!inputs.targetPlmn.has_value() || !inputs.targetCellId.has_value())
        missing("the intended target cell identity is not named");
    if (!result.missingInputs.empty())
        return result;

    const auto sourceCell = OwnCellIdentity(*inputs.config, inputs.configEpoch);
    const s1ap::SourceSession &session = *inputs.session;

    // The session must be the one this eNB is actually serving on its own cell.
    if (session.sourceCgi.plmn.mcc != sourceCell.plmn.mcc || session.sourceCgi.plmn.mnc != sourceCell.plmn.mnc ||
        session.sourceCgi.cellId != sourceCell.cellId)
    {
        missing("the source session does not belong to this eNB's cell");
        return result;
    }
    if (session.enbUeS1apId == 0 || session.mmeUeS1apId == 0)
    {
        missing("the source session carries no S1AP identity pair");
        return result;
    }

    const auto target = inputs.inventory->Resolve(*inputs.targetPlmn, *inputs.targetCellId);
    if (!target.has_value())
    {
        missing("the intended target cell is not an authorized current inventory entry");
        return result;
    }
    if (target->sameCell(sourceCell))
    {
        missing("the intended target is the source's own cell");
        return result;
    }

    SourceHandoverSnapshot snapshot;
    snapshot.sessionGeneration = inputs.sessionGeneration;
    snapshot.sourceCell = sourceCell;
    snapshot.radioUeId = session.radioUeId;
    snapshot.enbUeS1apId = session.enbUeS1apId;
    snapshot.mmeUeS1apId = session.mmeUeS1apId;
    snapshot.accessGeneration = session.accessGeneration;
    snapshot.associationEpoch = session.associationEpoch;
    snapshot.defaultEbi = session.defaultEbi;
    for (const auto &role : session.roles)
        if (role.role == s1ap::BearerRole::DEDICATED)
            snapshot.dedicatedEbis.push_back(role.erabId);
    snapshot.history = inputs.history->Bounded();
    snapshot.historyTruncated = inputs.history->truncated();
    snapshot.approvedTarget = *target;
    snapshot.targetInventoryGeneration = inputs.inventory->generation();

    result.snapshot = snapshot;
    return result;
}

// --- Runtime handover preparation ------------------------------------------

PreparationResult BuildRuntimeHandoverPreparation(const SourceHandoverSnapshot &snapshot,
                                                  const lte::rrc::HandoverPreparation &rrcMessage)
{
    PreparationResult result;

    if (snapshot.sessionGeneration == 0)
        result.missingInputs.push_back("the snapshot is not bound to a source context generation");
    if (!snapshot.sourceCell.verified())
        result.missingInputs.push_back("the source cell identity is not verified");
    if (snapshot.radioUeId == 0 || snapshot.enbUeS1apId == 0 || snapshot.mmeUeS1apId == 0)
        result.missingInputs.push_back("the snapshot carries no complete UE identity");
    if (!snapshot.approvedTarget.has_value() || !snapshot.approvedTarget->verified())
        result.missingInputs.push_back("the snapshot carries no approved target cell identity");
    if (snapshot.history.empty())
        result.missingInputs.push_back("the snapshot carries no observed serving-cell history");
    if (rrcMessage.ueCapabilities.empty())
        result.missingInputs.push_back("the RRC message carries no UE capability container");
    if (!result.missingInputs.empty())
        return result;

    // The history the container carries is this session's own recorded
    // history, converted at its measured values and marked as observed. A
    // fixture value cannot reach this path: the snapshot can only be built
    // from runtime components.
    s1ap::UeHistoryInformation history;
    history.provenance = snapshot.historyTruncated ? s1ap::HistoryProvenance::UNKNOWN_PREDECESSOR
                                                   : s1ap::HistoryProvenance::RUNTIME_OBSERVED;
    for (const auto &visit : snapshot.history)
    {
        s1ap::LastVisitedEutranCell cell;
        cell.globalCellId.plmn = visit.cell.plmn;
        cell.globalCellId.cellId = visit.cell.cellId;
        cell.globalCellId.provenance = s1ap::EutranCgiProvenance::RUNNING_TARGET_CELL;
        cell.cellSize = 2;
        cell.timeUeStayedInCell = visit.timeStayedInCell();
        cell.provenance = s1ap::HistoryProvenance::RUNTIME_OBSERVED;
        history.visitedCells.push_back(cell);
    }

    s1ap::SourceToTargetContainer container;
    container.targetCellId.plmn = snapshot.approvedTarget->plmn;
    container.targetCellId.cellId = snapshot.approvedTarget->cellId;
    container.targetCellId.provenance = s1ap::EutranCgiProvenance::SIMULATOR_CELL;
    container.ueHistory = history;

    std::vector<uint8_t> rrc;
    const auto encoded = lte::rrc::EncodeHandoverPreparationInformation(rrcMessage, &rrc);
    if (!encoded.ok)
    {
        result.missingInputs.push_back("the RRC message cannot be encoded: " + encoded.detail);
        return result;
    }
    container.rrcPayload = rrc;

    const auto built = s1ap::EncodeSourceToTargetTransparentContainer(container, &result.container);
    if (!built.ok)
    {
        result.missingInputs.push_back("the transparent container cannot be encoded: " + built.detail);
        result.container.clear();
        return result;
    }

    result.manifest = {
        {"sourceCell", std::string(ToString(snapshot.sourceCell.authority))},
        {"targetCell", std::string(ToString(snapshot.approvedTarget->authority))},
        {"ueHistory", std::string(s1ap::ToString(history.provenance))},
        {"ueCapability", "CALLER_SUPPLIED"},
        {"rrcPayload", "lte::rrc::EncodeHandoverPreparationInformation"},
        {"container", "s1ap::EncodeSourceToTargetTransparentContainer"},
    };
    result.ok = true;
    return result;
}

} // namespace lte::enb
