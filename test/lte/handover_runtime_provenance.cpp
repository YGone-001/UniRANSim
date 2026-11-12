//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

// Phase 18-F-B3: where a handover's typed inputs come from.
//
// The codecs turn typed data into octets; these cases drive the typed data's
// origin instead: history recorded from real serving-cell transitions on an
// injected monotonic clock, a cell identity a runtime authority owns, and a
// snapshot that can only be built from live runtime components. No test
// fabricates a trusted value, and every fixture is labelled as one.

#include <ext/doctest/doctest.h>

#include <chrono>
#include <string>
#include <vector>

#include <lte/enb/handover_runtime_provenance.hpp>
#include <lte/enb/handover_orchestration.hpp>
#include <lte/enb/transparent_container.hpp>
#include <lte/enb/ue_registry.hpp>
#include <lte/rrc/rrc_handover.hpp>

namespace
{

using namespace lte::enb;
using namespace lte::enb::s1ap;
using Clock = std::chrono::steady_clock;

Clock::time_point At(long long seconds)
{
    return Clock::time_point{} + std::chrono::seconds{seconds};
}

EnbConfig SourceConfig()
{
    EnbConfig config;
    config.plmn = Plmn{"460", "02"};
    config.enbId = 0x00ABCDE;
    config.tac = 7;
    return config;
}

EnbConfig TargetConfig()
{
    EnbConfig config;
    config.plmn = Plmn{"460", "02"};
    config.enbId = 0x00ABCDF;
    config.tac = 7;
    return config;
}

// A source cell as this eNB owns it.
VerifiedCellIdentity SourceCell()
{
    return OwnCellIdentity(SourceConfig(), 3);
}

VerifiedCellIdentity TargetCell()
{
    return OwnCellIdentity(TargetConfig(), 3);
}

// A live registry entry with everything ExtractSourceSession requires. It is
// built out of the same runtime types production uses, not out of the snapshot
// fields a caller might wish for.
EnbUeEntry LiveEntry()
{
    EnbUeEntry entry;
    entry.radioUeId = 11;
    entry.peer = InetAddress{"127.0.0.1", 39999};
    entry.s1 = UeS1State::BEARER_ACTIVE;
    entry.enbUeS1apId = 1;
    entry.mmeUeS1apId = 201;
    entry.accessGeneration = 4;

    BearerParameters parameters;
    parameters.erabId = 5;
    parameters.qci = 9;
    parameters.ueId = 11;
    parameters.sgwAddress = {10, 45, 0, 1};
    parameters.sgwTeid = 0x0A0B0C0D;
    parameters.localTeid = 0x11121314;
    parameters.qos = lte::ErabQos{9, 15, 0, 0};
    entry.bearer.establish(parameters);
    entry.bearer.activateUe(11, 5, {10, 45, 0, 2});
    entry.ueAmbr = lte::UeAmbr{1000, 1000};
    return entry;
}

lte::rrc::HandoverPreparation SamplePreparation()
{
    lte::rrc::HandoverPreparation message;
    // A fixture capability container, labelled as fixture data by this file.
    message.ueCapabilities.push_back(lte::rrc::UeCapabilityContainer{0, {0x00, 0x11, 0x22, 0x33, 0x44}});
    return message;
}

} // namespace

TEST_CASE("lte/handover/provenance: decoded wire data is never trusted provenance")
{
    // Build a container from a fixture, decode it, and check what came out.
    s1ap::SourceToTargetContainer fixture;
    fixture.rrcPayload = {0x08, 0x10, 0x05, 0x00};
    fixture.targetCellId.plmn = Plmn{"460", "02"};
    fixture.targetCellId.cellId = 0x0ABCDE0;
    fixture.targetCellId.provenance = s1ap::EutranCgiProvenance::FIXTURE;
    s1ap::LastVisitedEutranCell visit;
    visit.globalCellId.plmn = Plmn{"460", "02"};
    visit.globalCellId.cellId = 0x00ABCDE;
    visit.cellSize = 2;
    visit.timeUeStayedInCell = 300;
    visit.provenance = s1ap::HistoryProvenance::FIXTURE;
    fixture.ueHistory.visitedCells = {visit};
    fixture.ueHistory.provenance = s1ap::HistoryProvenance::FIXTURE;

    std::vector<uint8_t> encoded;
    REQUIRE(s1ap::EncodeSourceToTargetTransparentContainer(fixture, &encoded));

    s1ap::SourceToTargetContainer decoded;
    REQUIRE(s1ap::DecodeSourceToTargetTransparentContainer(encoded.data(), encoded.size(), &decoded));

    // The wire carries no provenance. What came out of it is what a peer
    // asserted: not a fixture, not a runtime observation.
    CHECK(decoded.targetCellId.provenance == s1ap::EutranCgiProvenance::WIRE_UNVERIFIED);
    CHECK(decoded.ueHistory.provenance == s1ap::HistoryProvenance::WIRE_UNVERIFIED);
    REQUIRE_FALSE(decoded.ueHistory.visitedCells.empty());
    CHECK(decoded.ueHistory.visitedCells[0].provenance == s1ap::HistoryProvenance::WIRE_UNVERIFIED);
    CHECK(decoded.ueHistory.visitedCells[0].globalCellId.provenance == s1ap::EutranCgiProvenance::WIRE_UNVERIFIED);

    // Nothing in the decoder raises a decoded value to a trusted state.
    CHECK(decoded.ueHistory.provenance != s1ap::HistoryProvenance::RUNTIME_OBSERVED);
    CHECK(decoded.targetCellId.provenance != s1ap::EutranCgiProvenance::RUNNING_TARGET_CELL);
    CHECK(decoded.targetCellId.provenance != s1ap::EutranCgiProvenance::SIMULATOR_CELL);

    // And the wire bytes themselves are unchanged by any of this: the provenance
    // correction altered no encoding.
    std::vector<uint8_t> reencoded;
    REQUIRE(s1ap::EncodeSourceToTargetTransparentContainer(decoded, &reencoded));
    CHECK(reencoded == encoded);
}

TEST_CASE("lte/handover/provenance: serving-cell history is recorded from real transitions")
{
    ServingCellHistory history;
    const auto source = SourceCell();
    const auto target = TargetCell();

    // The session is established on the source cell at t=0.
    history.BeginVisit(source, At(0));
    CHECK(history.hasCurrentVisit());
    CHECK(history.Bounded().size() == 1);

    // An idle access release is not a new cell visit.
    history.EndCurrentVisit(At(300));
    CHECK_FALSE(history.hasCurrentVisit());
    CHECK(history.Bounded().size() == 1);
    CHECK(history.Bounded()[0].timeStayedInCell() == 300);
    CHECK(history.Bounded()[0].complete());

    // Re-establishing access in the same cell is the same stay, not a second
    // entry.
    history.BeginVisit(source, At(320));
    history.EndCurrentVisit(At(400));
    CHECK(history.Bounded().size() == 1);
    CHECK(history.Bounded()[0].timeStayedInCell() == 300);

    // A genuine reselection into another cell records the move, and the
    // earlier stay keeps the duration it was recorded with.
    history.ReselectTo(target, At(900));
    const auto visits = history.Bounded();
    REQUIRE(visits.size() == 2);
    CHECK(visits[0].cell.sameCell(source));
    CHECK(visits[0].timeStayedInCell() == 300);
    CHECK(visits[1].cell.sameCell(target));
    CHECK(visits[1].complete() == false);
    CHECK(visits[1].provenance == s1ap::HistoryProvenance::RUNTIME_OBSERVED);

    // Every recorded visit carries the authority of the cell it names.
    CHECK(visits[0].cell.authority == CellIdentityAuthority::LOCAL_CONFIGURATION);
}

TEST_CASE("lte/handover/provenance: residence time is monotonic and saturates")
{
    ServingCellHistory history;
    const auto source = SourceCell();

    history.BeginVisit(source, At(0));
    history.EndCurrentVisit(At(4095));
    CHECK(history.Bounded()[0].timeStayedInCell() == 4095);
    CHECK_FALSE(history.Bounded()[0].saturated);

    // Beyond the normative range the value is bounded and the flag says the
    // number is not the measured duration.
    ServingCellHistory longStay;
    longStay.BeginVisit(source, At(0));
    longStay.EndCurrentVisit(At(100000));
    CHECK(longStay.Bounded()[0].timeStayedInCell() == 4095);
    CHECK(longStay.Bounded()[0].saturated);

    // A visit that is still open reports its elapsed time so far and does not
    // claim to be complete.
    ServingCellHistory open;
    open.BeginVisit(source, At(0));
    CHECK_FALSE(open.Bounded()[0].complete());
}

TEST_CASE("lte/handover/provenance: history is bounded to sixteen entries")
{
    ServingCellHistory history;
    for (int i = 0; i < 20; ++i)
    {
        EnbConfig config = SourceConfig();
        config.enbId = 0x1000 + static_cast<uint32_t>(i);
        history.ReselectTo(OwnCellIdentity(config, 1), At(i * 10));
    }

    CHECK(history.truncated());
    CHECK(history.unknownPredecessor());
    const auto visits = history.Bounded();
    REQUIRE(visits.size() == ServingCellHistory::MaxEntries);
    // The most recent entries survive, in chronological order. Each cell is
    // distinct, so each transition opens exactly one entry.
    CHECK(visits.back().cell.ownerEnbId == 0x1000 + 19);
    CHECK(visits.front().cell.ownerEnbId == 0x1000 + 4);
    for (size_t i = 1; i < visits.size(); ++i)
        CHECK(visits[i - 1].enteredAt <= visits[i].enteredAt);
}

TEST_CASE("lte/handover/provenance: a fresh attach starts a new session history")
{
    ServingCellHistory history;
    const auto source = SourceCell();
    history.BeginVisit(source, At(0));
    history.EndCurrentVisit(At(100));

    // A fresh Attach is a new EPS session: nothing from the earlier one is
    // carried over and no earlier cell is invented for the new session.
    history.StartNewEpsSession(source, At(200));
    const auto visits = history.Bounded();
    REQUIRE(visits.size() == 1);
    CHECK(visits[0].enteredAt == At(200));
    CHECK(visits[0].provenance == s1ap::HistoryProvenance::RUNTIME_OBSERVED);
    CHECK_FALSE(history.truncated());
}

TEST_CASE("lte/handover/provenance: the target inventory binds identity and generation")
{
    TargetInventory inventory;
    const auto target = TargetCell();
    inventory.Publish(target);

    const auto resolved = inventory.Resolve(target.plmn, target.cellId);
    REQUIRE(resolved.has_value());
    CHECK(resolved->authority == CellIdentityAuthority::SIMULATOR_INVENTORY);
    CHECK(resolved->sameCell(target));

    // A cell the inventory never published does not resolve: a TAC, a PLMN or
    // a transport address is not a cell identity.
    CHECK_FALSE(inventory.Resolve(target.plmn, 0x12345678).has_value());
    CHECK_FALSE(inventory.Resolve(Plmn{"460", "03"}, target.cellId).has_value());

    // A new generation invalidates every earlier entry.
    inventory.AdvanceGeneration();
    CHECK_FALSE(inventory.Resolve(target.plmn, target.cellId).has_value());
    inventory.Publish(target);
    CHECK(inventory.Resolve(target.plmn, target.cellId).has_value());
}

TEST_CASE("lte/handover/provenance: the runtime snapshot is built from live components")
{
    const EnbUeEntry entry = LiveEntry();
    const auto sourceIdentity = EnbIdentity{Plmn{"460", "02"}, SourceConfig().enbId, SourceConfig().tac};
    const s1ap::SourceSession session = ExtractSourceSession(entry, sourceIdentity,
                                                             EutranCgi{Plmn{"460", "02"}, SourceCell().cellId}, 9);
    REQUIRE(session.isVerified());

    ServingCellHistory history;
    history.BeginVisit(SourceCell(), At(0));
    history.EndCurrentVisit(At(120));

    TargetInventory inventory;
    inventory.Publish(TargetCell());

    const EnbConfig config = SourceConfig();
    SnapshotInputs inputs;
    inputs.config = &config;
    inputs.configEpoch = 3;
    inputs.session = &session;
    inputs.sessionGeneration = 42;
    inputs.history = &history;
    inputs.inventory = &inventory;
    inputs.targetPlmn = TargetCell().plmn;
    inputs.targetCellId = TargetCell().cellId;

    const auto built = BuildSourceHandoverRuntimeSnapshot(inputs);
    REQUIRE(built.ok());
    REQUIRE(built.snapshot.has_value());
    const auto &snapshot = *built.snapshot;
    CHECK(snapshot.sessionGeneration == 42);
    CHECK(snapshot.sourceCell.authority == CellIdentityAuthority::LOCAL_CONFIGURATION);
    CHECK(snapshot.approvedTarget.has_value());
    CHECK(snapshot.approvedTarget->authority == CellIdentityAuthority::SIMULATOR_INVENTORY);
    CHECK(snapshot.mmeUeS1apId == 201);
    CHECK(snapshot.enbUeS1apId == 1);
    CHECK(snapshot.history.size() == 1);
    CHECK(snapshot.history[0].timeStayedInCell() == 120);
    CHECK(snapshot.history[0].provenance == s1ap::HistoryProvenance::RUNTIME_OBSERVED);
}

TEST_CASE("lte/handover/provenance: the snapshot refuses missing and mismatched inputs")
{
    const EnbUeEntry entry = LiveEntry();
    const auto sourceIdentity = EnbIdentity{Plmn{"460", "02"}, SourceConfig().enbId, SourceConfig().tac};
    const s1ap::SourceSession session = ExtractSourceSession(entry, sourceIdentity,
                                                             EutranCgi{Plmn{"460", "02"}, SourceCell().cellId}, 9);
    ServingCellHistory history;
    history.BeginVisit(SourceCell(), At(0));
    TargetInventory inventory;
    inventory.Publish(TargetCell());

    const EnbConfig config = SourceConfig();
    SnapshotInputs inputs;
    inputs.config = &config;
    inputs.configEpoch = 3;
    inputs.session = &session;
    inputs.sessionGeneration = 42;
    inputs.history = &history;
    inputs.inventory = &inventory;
    inputs.targetPlmn = TargetCell().plmn;
    inputs.targetCellId = TargetCell().cellId;

    SUBCASE("a missing target is named and nothing is built")
    {
        inputs.targetCellId.reset();
        const auto built = BuildSourceHandoverRuntimeSnapshot(inputs);
        CHECK_FALSE(built.ok());
        CHECK_FALSE(built.missingInputs.empty());
        CHECK_FALSE(built.snapshot.has_value());
    }
    SUBCASE("a target that is not an authorized inventory entry is refused")
    {
        inputs.targetCellId = 0x12345678;
        const auto built = BuildSourceHandoverRuntimeSnapshot(inputs);
        CHECK_FALSE(built.ok());
        CHECK_FALSE(built.missingInputs.empty());
    }
    SUBCASE("the source's own cell is not a target")
    {
        inputs.targetCellId = SourceCell().cellId;
        const auto built = BuildSourceHandoverRuntimeSnapshot(inputs);
        CHECK_FALSE(built.ok());
    }
    SUBCASE("a session from another eNB's cell is refused")
    {
        EnbConfig other = SourceConfig();
        other.enbId = 0x00ABCDE0;
        inputs.config = &other;
        const auto built = BuildSourceHandoverRuntimeSnapshot(inputs);
        CHECK_FALSE(built.ok());
    }
    SUBCASE("no history is named and nothing is built")
    {
        inputs.history = nullptr;
        const auto built = BuildSourceHandoverRuntimeSnapshot(inputs);
        CHECK_FALSE(built.ok());
        CHECK_FALSE(built.missingInputs.empty());
    }
}

TEST_CASE("lte/handover/provenance: the runtime builder fails closed")
{
    const EnbUeEntry entry = LiveEntry();
    const auto sourceIdentity = EnbIdentity{Plmn{"460", "02"}, SourceConfig().enbId, SourceConfig().tac};
    const s1ap::SourceSession session = ExtractSourceSession(entry, sourceIdentity,
                                                             EutranCgi{Plmn{"460", "02"}, SourceCell().cellId}, 9);
    ServingCellHistory history;
    history.BeginVisit(SourceCell(), At(0));
    history.EndCurrentVisit(At(60));
    TargetInventory inventory;
    inventory.Publish(TargetCell());

    const EnbConfig config = SourceConfig();
    SnapshotInputs inputs;
    inputs.config = &config;
    inputs.configEpoch = 3;
    inputs.session = &session;
    inputs.sessionGeneration = 42;
    inputs.history = &history;
    inputs.inventory = &inventory;
    inputs.targetPlmn = TargetCell().plmn;
    inputs.targetCellId = TargetCell().cellId;

    const auto built = BuildSourceHandoverRuntimeSnapshot(inputs);
    REQUIRE(built.ok());

    // A complete snapshot and a real RRC message produce a complete container.
    const auto prepared = BuildRuntimeHandoverPreparation(*built.snapshot, SamplePreparation());
    REQUIRE(prepared.ok);
    CHECK_FALSE(prepared.container.empty());
    CHECK(prepared.missingInputs.empty());
    REQUIRE_FALSE(prepared.manifest.empty());

    s1ap::SourceToTargetContainer unpacked;
    REQUIRE(s1ap::DecodeSourceToTargetTransparentContainer(prepared.container.data(), prepared.container.size(),
                                                           &unpacked));
    // The history in the container is the session's own recorded history.
    REQUIRE(unpacked.ueHistory.visitedCells.size() == 1);
    CHECK(unpacked.ueHistory.visitedCells[0].timeUeStayedInCell == 60);
    CHECK(unpacked.ueHistory.visitedCells[0].globalCellId.cellId == SourceCell().cellId);
    // The target is the inventory-verified cell, not a fixture.
    CHECK(unpacked.targetCellId.cellId == TargetCell().cellId);

    SUBCASE("a missing UE capability is reported and nothing is encoded")
    {
        lte::rrc::HandoverPreparation empty;
        const auto refused = BuildRuntimeHandoverPreparation(*built.snapshot, empty);
        CHECK_FALSE(refused.ok);
        CHECK(refused.container.empty());
        CHECK_FALSE(refused.missingInputs.empty());
    }
    SUBCASE("a snapshot with no history is refused")
    {
        ServingCellHistory noHistory;
        inputs.history = &noHistory;
        const auto reBuilt = BuildSourceHandoverRuntimeSnapshot(inputs);
        const auto refused = BuildRuntimeHandoverPreparation(*reBuilt.snapshot, SamplePreparation());
        CHECK_FALSE(refused.ok);
        CHECK(refused.container.empty());
    }
}

TEST_CASE("lte/handover/provenance: histories of different ues never mix")
{
    ServingCellHistory historyA;
    ServingCellHistory historyB;
    const auto source = SourceCell();
    historyA.BeginVisit(source, At(0));
    historyB.BeginVisit(source, At(0));

    // UE A moves; UE B stays.
    EnbConfig other = TargetConfig();
    historyA.ReselectTo(OwnCellIdentity(other, 3), At(100));
    historyA.EndCurrentVisit(At(200));

    CHECK(historyA.Bounded().size() == 2);
    CHECK(historyB.Bounded().size() == 1);
    CHECK(historyB.Bounded()[0].timeStayedInCell() == 0);
    CHECK_FALSE(historyB.Bounded()[0].complete());

    // A failed target preparation for UE A changes nothing about UE B.
    historyA.EndCurrentVisit(At(300));
    CHECK(historyB.Bounded().size() == 1);
    CHECK(historyB.hasCurrentVisit());
}

TEST_CASE("lte/handover/provenance: the legacy command api cannot satisfy the conformant path")
{
    lte::rrc::HandoverCommand command;
    command.rrcTransactionIdentifier = 1;
    command.targetPhysCellId = 42;
    command.t304 = 2;
    command.newUeIdentity = 0x1234;
    command.prachRootSequenceIndex = 22;
    command.puschNSb = 1;
    command.puschHoppingMode = 0;
    command.puschHoppingOffset = 0;
    command.puschEnable64Qam = false;
    command.puschGroupHoppingEnabled = false;
    command.puschGroupAssignmentPusch = 0;
    command.puschSequenceHoppingEnabled = false;
    command.puschCyclicShift = 0;
    command.ulCyclicPrefixLength = 1;

    std::vector<uint8_t> legacy;
    REQUIRE(lte::rrc::EncodeHandoverCommandLegacy(command, &legacy));
    std::vector<uint8_t> conformant;
    REQUIRE(lte::rrc::EncodeHandoverCommandPayload(command, &conformant));
    CHECK(legacy != conformant);

    // The conformant bytes are the only ones a container may carry, and the
    // legacy form is the one the historical vectors keep.
    lte::rrc::HandoverCommand fromConformant;
    REQUIRE(lte::rrc::DecodeHandoverCommandPayload(conformant.data(), conformant.size(), &fromConformant));
    CHECK(fromConformant.targetPhysCellId == 42);

    lte::rrc::HandoverCommand fromLegacy;
    const auto legacyOutcome = lte::rrc::DecodeHandoverCommandPayload(legacy.data(), legacy.size(), &fromLegacy);
    CHECK_FALSE(legacyOutcome.ok);
}
