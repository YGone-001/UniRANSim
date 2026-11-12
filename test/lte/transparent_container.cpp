//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

// Phase 18-F-B2: the TS 36.413 transparent-container layer.
//
// These cases drive the outer container around the accepted LTE RRC messages:
// the three layers stay separate (RRC UPER, container APER, S1AP APER) and the
// complete nesting is what is asserted. The fixtures are offline values with
// their provenance stated; none of them claims to come from a live target.

#include <ext/doctest/doctest.h>

#include <array>
#include <cstdint>
#include <string>
#include <vector>

#include <lte/enb/codec.hpp>
#include <lte/enb/transparent_container.hpp>
#include <lte/rrc/rrc_handover.hpp>

#include "AccessStratumRelease.h"
#include "BandInfoEUTRA.h"
#include "InterFreqBandInfo.h"
#include "SupportedBandEUTRA.h"
#include "UE-EUTRA-Capability.h"
#include <per_encoder.h>

namespace
{

using namespace lte::enb;
using namespace lte::enb::s1ap;

std::vector<uint8_t> Hex(const std::string &text)
{
    std::vector<uint8_t> out;
    for (size_t i = 0; i + 1 < text.size(); i += 2)
        out.push_back(static_cast<uint8_t>(std::stoul(text.substr(i, 2), nullptr, 16)));
    return out;
}

Plmn TestPlmn()
{
    return Plmn{"460", "02"};
}

EutranCgiValue FixtureCgi(uint32_t cellId)
{
    EutranCgiValue value;
    value.plmn = TestPlmn();
    value.cellId = cellId;
    value.provenance = EutranCgiProvenance::FIXTURE;
    return value;
}

UeHistoryInformation FixtureHistory()
{
    UeHistoryInformation history;
    history.provenance = HistoryProvenance::FIXTURE;

    LastVisitedEutranCell first;
    first.globalCellId = FixtureCgi(0x00ABCDE);
    first.cellSize = 2;      // medium
    first.timeUeStayedInCell = 1200;
    first.provenance = HistoryProvenance::FIXTURE;

    LastVisitedEutranCell second;
    second.globalCellId = FixtureCgi(0x0123456);
    second.cellSize = 1;     // small
    second.timeUeStayedInCell = 4095;
    second.provenance = HistoryProvenance::FIXTURE;

    history.visitedCells = {first, second};
    return history;
}

lte::rrc::HandoverCommand SampleRrcCommand()
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
    return command;
}

// The exact octets the accepted RRC codec produced in Phase 18-F-B1, one per
// direction, so each container carries the RRC message its own direction is
// defined to carry.
std::vector<uint8_t> SamplePreparationRrc()
{
    return Hex("081005001122334400000224a3c616800016400140004048d15a0a080c2347022c461aa058c2825080000108010091a8607150c20200ce40");
}

std::vector<uint8_t> SampleCommandRrc()
{
    return Hex("005a080054848d00002c000008");
}

SourceToTargetContainer SampleSourceContainer()
{
    SourceToTargetContainer container;
    container.rrcPayload = SamplePreparationRrc();
    container.targetCellId = FixtureCgi(0x0ABCDE0);
    container.ueHistory = FixtureHistory();
    container.subscriberProfileIdForRfp = 42;
    return container;
}

TargetToSourceContainer SampleTargetContainer()
{
    TargetToSourceContainer container;
    std::vector<uint8_t> payload;
    const auto outcome = lte::rrc::EncodeHandoverCommandPayload(SampleRrcCommand(), &payload);
    REQUIRE(outcome.ok);
    container.rrcPayload = payload;
    return container;
}

} // namespace

TEST_CASE("lte/rrc-container: a source-to-target container round-trips with its fields intact")
{
    const auto container = SampleSourceContainer();
    std::vector<uint8_t> encoded;
    REQUIRE(EncodeSourceToTargetTransparentContainer(container, &encoded));
    REQUIRE_FALSE(encoded.empty());
    CHECK(encoded.size() <= MaxTransparentContainerSize);

    SourceToTargetContainer decoded;
    REQUIRE(DecodeSourceToTargetTransparentContainer(encoded.data(), encoded.size(), &decoded));
    CHECK(decoded.rrcPayload == container.rrcPayload);
    CHECK(decoded.targetCellId.plmn.mcc == "460");
    CHECK(decoded.targetCellId.plmn.mnc == "02");
    CHECK(decoded.targetCellId.cellId == 0x0ABCDE0);
    CHECK(decoded.targetCellId.provenance == EutranCgiProvenance::WIRE_UNVERIFIED);
    REQUIRE(decoded.subscriberProfileIdForRfp.has_value());
    CHECK(*decoded.subscriberProfileIdForRfp == 42);
    REQUIRE(decoded.ueHistory.visitedCells.size() == 2);
    CHECK(decoded.ueHistory.visitedCells[0].globalCellId.cellId == 0x00ABCDE);
    CHECK(decoded.ueHistory.visitedCells[0].cellSize == 2);
    CHECK(decoded.ueHistory.visitedCells[0].timeUeStayedInCell == 1200);
    CHECK(decoded.ueHistory.visitedCells[1].globalCellId.cellId == 0x0123456);
    CHECK(decoded.ueHistory.visitedCells[1].cellSize == 1);
    CHECK(decoded.ueHistory.visitedCells[1].timeUeStayedInCell == 4095);
}

TEST_CASE("lte/rrc-container: a target-to-source container round-trips with its rrc payload intact")
{
    const auto container = SampleTargetContainer();
    std::vector<uint8_t> encoded;
    REQUIRE(EncodeTargetToSourceTransparentContainer(container, &encoded));
    REQUIRE_FALSE(encoded.empty());

    TargetToSourceContainer decoded;
    REQUIRE(DecodeTargetToSourceTransparentContainer(encoded.data(), encoded.size(), &decoded));
    CHECK(decoded.rrcPayload == container.rrcPayload);
}

TEST_CASE("lte/rrc-container: container encoding is byte-stable across repeated runs")
{
    std::vector<uint8_t> first;
    REQUIRE(EncodeSourceToTargetTransparentContainer(SampleSourceContainer(), &first));
    for (int i = 0; i < 16; ++i)
    {
        std::vector<uint8_t> again;
        REQUIRE(EncodeSourceToTargetTransparentContainer(SampleSourceContainer(), &again));
        CHECK(again == first);
    }

    std::vector<uint8_t> target;
    REQUIRE(EncodeTargetToSourceTransparentContainer(SampleTargetContainer(), &target));
    for (int i = 0; i < 16; ++i)
    {
        std::vector<uint8_t> again;
        REQUIRE(EncodeTargetToSourceTransparentContainer(SampleTargetContainer(), &again));
        CHECK(again == target);
    }
}

// --- The three-layer boundary ----------------------------------------------

TEST_CASE("lte/rrc-container: the complete nesting survives every s1ap handover message")
{
    // Inner layer: the accepted LTE RRC codec, in the form TS 36.331 states
    // for a target-to-source payload (a DL-DCCH-Message inside the command).
    std::vector<uint8_t> rrc;
    REQUIRE(lte::rrc::EncodeHandoverCommandPayload(SampleRrcCommand(), &rrc));

    // Middle layer: the TS 36.413 container around it.
    TargetToSourceContainer targetContainer;
    targetContainer.rrcPayload = rrc;
    std::vector<uint8_t> targetBytes;
    REQUIRE(EncodeTargetToSourceTransparentContainer(targetContainer, &targetBytes));

    SourceToTargetContainer sourceContainer = SampleSourceContainer();
    sourceContainer.rrcPayload = SamplePreparationRrc();
    std::vector<uint8_t> sourceBytes;
    REQUIRE(EncodeSourceToTargetTransparentContainer(sourceContainer, &sourceBytes));

    // Outer layer: the S1AP message, whose IE holds the container as opaque
    // octets and never rewrites them.
    HandoverRequired required;
    required.mmeUeS1apId = 201;
    required.enbUeS1apId = 1;
    required.handoverType = HandoverType::INTRA_LTE;
    required.causeCategory = "radioNetwork";
    required.causeValue = 16;
    required.target = EnbIdentity{TestPlmn(), 0x00ABCDEu, 2};
    required.sourceToTarget = sourceBytes;
    const auto requiredPdu = EncodeHandoverRequired(required);
    const auto decodedRequired = DecodeHandoverRequired(requiredPdu.data(), requiredPdu.size());
    CHECK(decodedRequired.sourceToTarget == sourceBytes);

    HandoverRequest request;
    request.mmeUeS1apId = 201;
    request.handoverType = HandoverType::INTRA_LTE;
    request.causeCategory = "radioNetwork";
    request.causeValue = 16;
    request.ueAmbr.downlink = 1000;
    request.ueAmbr.uplink = 1000;
    ErabToBeSetupItemHoReq bearer;
    bearer.erabId = 5;
    bearer.sgwAddress = {127, 0, 0, 2};
    bearer.sgwTeid = {0, 0, 0, 30};
    bearer.qos.qci = 9;
    bearer.qos.priorityLevel = 15;
    request.erabs = {bearer};
    request.sourceToTarget = sourceBytes;
    request.encryptionAlgorithms = {0x80, 0x00};
    request.integrityAlgorithms = {0x40, 0x00};
    request.securityContext.nextHopChainingCount = 3;
    request.securityContext.nextHopParameter.fill(0xA0);
    const auto requestPdu = EncodeHandoverRequest(request);
    const auto decodedRequest = DecodeHandoverRequest(requestPdu.data(), requestPdu.size());
    CHECK(decodedRequest.sourceToTarget == sourceBytes);

    HandoverRequestAcknowledge acknowledge;
    acknowledge.mmeUeS1apId = 201;
    acknowledge.enbUeS1apId = 1;
    ErabAdmittedItem admitted;
    admitted.erabId = 5;
    admitted.transportLayerAddress = {127, 0, 0, 3};
    admitted.gtpTeid = {0, 0, 0x11, 0x22};
    acknowledge.admitted = {admitted};
    acknowledge.targetToSource = targetBytes;
    const auto acknowledgePdu = EncodeHandoverRequestAcknowledge(acknowledge);
    const auto decodedAcknowledge =
        DecodeHandoverRequestAcknowledge(acknowledgePdu.data(), acknowledgePdu.size());
    CHECK(decodedAcknowledge.targetToSource == targetBytes);

    HandoverCommand command;
    command.mmeUeS1apId = 201;
    command.enbUeS1apId = 1;
    command.handoverType = HandoverType::INTRA_LTE;
    command.targetToSource = targetBytes;
    const auto commandPdu = EncodeHandoverCommand(command);
    const auto decodedCommand = DecodeHandoverCommand(commandPdu.data(), commandPdu.size());
    CHECK(decodedCommand.targetToSource == targetBytes);

    // Now the three layers back out again: S1AP APER, container APER, RRC UPER.
    SourceToTargetContainer unpackedSource;
    REQUIRE(DecodeSourceToTargetTransparentContainer(decodedRequired.sourceToTarget.data(),
                                                      decodedRequired.sourceToTarget.size(), &unpackedSource));
    CHECK(unpackedSource.rrcPayload == sourceContainer.rrcPayload);
    CHECK(unpackedSource.targetCellId.cellId == sourceContainer.targetCellId.cellId);

    TargetToSourceContainer unpackedTarget;
    REQUIRE(DecodeTargetToSourceTransparentContainer(decodedCommand.targetToSource.data(),
                                                      decodedCommand.targetToSource.size(), &unpackedTarget));
    CHECK(unpackedTarget.rrcPayload == rrc);

    lte::rrc::HandoverCommand unpackedRrc;
    REQUIRE(lte::rrc::DecodeHandoverCommandPayload(unpackedTarget.rrcPayload.data(),
                                                   unpackedTarget.rrcPayload.size(), &unpackedRrc));
    CHECK(unpackedRrc.targetPhysCellId == 42);
    CHECK(unpackedRrc.newUeIdentity == 0x1234);
}

// --- Negative and adversarial vectors ---------------------------------------

TEST_CASE("lte/rrc-container: malformed and incomplete containers are refused")
{
    const auto container = SampleSourceContainer();
    std::vector<uint8_t> encoded;
    REQUIRE(EncodeSourceToTargetTransparentContainer(container, &encoded));
    const auto targetBytes = [&] {
        TargetToSourceContainer target = SampleTargetContainer();
        std::vector<uint8_t> bytes;
        REQUIRE(EncodeTargetToSourceTransparentContainer(target, &bytes));
        return bytes;
    }();

    SUBCASE("raw rrc octets are not a complete container")
    {
        SourceToTargetContainer out;
        const auto payload = SampleCommandRrc();
        const auto outcome = DecodeSourceToTargetTransparentContainer(payload.data(), payload.size(), &out);
        CHECK_FALSE(outcome.ok);
    }
    SUBCASE("an empty rRC-Container")
    {
        SourceToTargetContainer empty = container;
        empty.rrcPayload.clear();
        std::vector<uint8_t> bytes;
        const auto outcome = EncodeSourceToTargetTransparentContainer(empty, &bytes);
        CHECK_FALSE(outcome.ok);
        CHECK(outcome.refusal == ContainerRefusal::EMPTY_RRC_PAYLOAD);

        // And on the wire: a container whose length determinant is zero.
        SourceToTargetContainer out;
        const auto decode = DecodeSourceToTargetTransparentContainer(encoded.data(), 2, &out);
        CHECK_FALSE(decode.ok);
    }
    SUBCASE("missing targetCell-ID")
    {
        SourceToTargetContainer missing = container;
        missing.targetCellId = EutranCgiValue{};
        std::vector<uint8_t> bytes;
        const auto outcome = EncodeSourceToTargetTransparentContainer(missing, &bytes);
        CHECK_FALSE(outcome.ok);
        CHECK(outcome.refusal == ContainerRefusal::MISSING_TARGET_CGI);
    }
    SUBCASE("missing UE-HistoryInformation")
    {
        SourceToTargetContainer missing = container;
        missing.ueHistory = UeHistoryInformation{};
        missing.ueHistory.provenance = HistoryProvenance::MISSING;
        std::vector<uint8_t> bytes;
        const auto outcome = EncodeSourceToTargetTransparentContainer(missing, &bytes);
        CHECK_FALSE(outcome.ok);
        CHECK(outcome.refusal == ContainerRefusal::MISSING_UE_HISTORY);
    }
    SUBCASE("an invalid EUTRAN-CGI")
    {
        SourceToTargetContainer bad = container;
        bad.targetCellId.cellId = 0x10000000U;
        std::vector<uint8_t> bytes;
        auto outcome = EncodeSourceToTargetTransparentContainer(bad, &bytes);
        CHECK_FALSE(outcome.ok);
        CHECK(outcome.refusal == ContainerRefusal::INVALID_EUTRAN_CELL_ID);

        bad = container;
        bad.targetCellId.plmn.mcc = "46x";
        outcome = EncodeSourceToTargetTransparentContainer(bad, &bytes);
        CHECK_FALSE(outcome.ok);
        CHECK(outcome.refusal == ContainerRefusal::INVALID_PLMN);
    }
    SUBCASE("an invalid history entry")
    {
        SourceToTargetContainer bad = container;
        bad.ueHistory.visitedCells[0].cellSize = 4;
        std::vector<uint8_t> bytes;
        auto outcome = EncodeSourceToTargetTransparentContainer(bad, &bytes);
        CHECK_FALSE(outcome.ok);
        CHECK(outcome.refusal == ContainerRefusal::INVALID_HISTORY_ENTRY);

        bad = container;
        bad.ueHistory.visitedCells[1].timeUeStayedInCell = 4096;
        outcome = EncodeSourceToTargetTransparentContainer(bad, &bytes);
        CHECK_FALSE(outcome.ok);
        CHECK(outcome.refusal == ContainerRefusal::INVALID_HISTORY_ENTRY);
    }
    SUBCASE("a history longer than the ASN.1 allows")
    {
        SourceToTargetContainer bad = container;
        bad.ueHistory.visitedCells.resize(17, container.ueHistory.visitedCells.front());
        std::vector<uint8_t> bytes;
        const auto outcome = EncodeSourceToTargetTransparentContainer(bad, &bytes);
        CHECK_FALSE(outcome.ok);
        CHECK(outcome.refusal == ContainerRefusal::UE_HISTORY_TOO_LONG);
    }
    SUBCASE("an invalid optional presence bitmap")
    {
        // The iE-Extensions flag is the last prefix bit before the octet
        // boundary; setting it asks for a structure this profile cannot read.
        auto bad = encoded;
        bad[0] = static_cast<uint8_t>(bad[0] | 0x10);
        SourceToTargetContainer out;
        const auto outcome = DecodeSourceToTargetTransparentContainer(bad.data(), bad.size(), &out);
        CHECK_FALSE(outcome.ok);
        CHECK(outcome.refusal == ContainerRefusal::UNSUPPORTED_OPTIONAL_FIELD);
    }
    SUBCASE("unsupported extension additions")
    {
        auto bad = encoded;
        bad[0] = static_cast<uint8_t>(bad[0] | 0x80);
        SourceToTargetContainer out;
        const auto outcome = DecodeSourceToTargetTransparentContainer(bad.data(), bad.size(), &out);
        CHECK_FALSE(outcome.ok);
        CHECK(outcome.refusal == ContainerRefusal::UNSUPPORTED_EXTENSION);
    }
    SUBCASE("a truncated container")
    {
        SourceToTargetContainer out;
        const auto outcome = DecodeSourceToTargetTransparentContainer(encoded.data(), encoded.size() / 2, &out);
        CHECK_FALSE(outcome.ok);
    }
    SUBCASE("an oversized container")
    {
        std::vector<uint8_t> oversized(MaxTransparentContainerSize + 1, 0x00);
        SourceToTargetContainer out;
        const auto outcome = DecodeSourceToTargetTransparentContainer(oversized.data(), oversized.size(), &out);
        CHECK_FALSE(outcome.ok);
        CHECK(outcome.refusal == ContainerRefusal::RRC_PAYLOAD_TOO_LARGE);
    }
    SUBCASE("trailing octets after the container")
    {
        auto padded = encoded;
        padded.push_back(0x00);
        padded.push_back(0x00);
        SourceToTargetContainer out;
        const auto outcome = DecodeSourceToTargetTransparentContainer(padded.data(), padded.size(), &out);
        CHECK_FALSE(outcome.ok);
        CHECK(outcome.refusal == ContainerRefusal::TRAILING_DATA);
    }
    SUBCASE("an invalid nested rrc uper payload")
    {
        SourceToTargetContainer bad = container;
        bad.rrcPayload = {0xFF, 0xFF, 0xFF, 0xFF};
        std::vector<uint8_t> bytes;
        REQUIRE(EncodeSourceToTargetTransparentContainer(bad, &bytes));

        SourceToTargetContainer out;
        REQUIRE(DecodeSourceToTargetTransparentContainer(bytes.data(), bytes.size(), &out));
        lte::rrc::HandoverPreparation rrc;
        const auto rrcOutcome =
            lte::rrc::DecodeHandoverPreparationInformation(out.rrcPayload.data(), out.rrcPayload.size(), &rrc);
        CHECK_FALSE(rrcOutcome.ok);
    }
    SUBCASE("a source container read as a target container")
    {
        TargetToSourceContainer out;
        const auto outcome = DecodeTargetToSourceTransparentContainer(encoded.data(), encoded.size(), &out);
        CHECK_FALSE(outcome.ok);
    }
    SUBCASE("container octets are not an s1ap message")
    {
        CHECK_THROWS_AS(DecodeHandoverRequired(encoded.data(), encoded.size()), CodecError);
        CHECK_THROWS_AS(DecodeHandoverRequestAcknowledge(encoded.data(), encoded.size()), CodecError);
    }
    SUBCASE("a container for one ue changes nothing about another")
    {
        // The container carries no UE identity at all, so it can never bind
        // one; what it does carry is preserved exactly, and a refused decode
        // leaves the caller's object untouched.
        SourceToTargetContainer untouched;
        untouched.targetCellId = FixtureCgi(0x1111111);
        auto bad = encoded;
        bad[0] = static_cast<uint8_t>(bad[0] ^ 0x80);
        const auto outcome = DecodeSourceToTargetTransparentContainer(bad.data(), bad.size(), &untouched);
        CHECK_FALSE(outcome.ok);
        CHECK(untouched.targetCellId.cellId == 0x1111111);
    }
}

TEST_CASE("lte/rrc-container: decoder resource bounds hold for adversarial input")
{
    const auto container = SampleSourceContainer();
    std::vector<uint8_t> encoded;
    REQUIRE(EncodeSourceToTargetTransparentContainer(container, &encoded));

    // Every truncation of a valid container is refused, and none of them
    // touches the caller's object.
    for (size_t length = 1; length < encoded.size(); ++length)
    {
        SourceToTargetContainer out;
        const auto outcome = DecodeSourceToTargetTransparentContainer(encoded.data(), length, &out);
        CHECK_FALSE(outcome.ok);
        const bool refusedCleanly = out.rrcPayload.empty() || outcome.refusal != ContainerRefusal::NONE;
        CHECK(refusedCleanly);
    }

    // Repeated decode and cleanup of malformed input: the decoder allocates
    // and releases on every call, and the sanitizer runs of this case are what
    // prove no leak or use-after-free remains.
    for (int i = 0; i < 2000; ++i)
    {
        SourceToTargetContainer out;
        auto corrupted = encoded;
        corrupted[i % corrupted.size()] = static_cast<uint8_t>(i);
        const auto outcome = DecodeSourceToTargetTransparentContainer(corrupted.data(), corrupted.size(), &out);
        (void)outcome;
        TargetToSourceContainer targetOut;
        const auto targetOutcome = DecodeTargetToSourceTransparentContainer(corrupted.data(), corrupted.size(),
                                                                             &targetOut);
        (void)targetOutcome;
    }

    // A payload that would exceed the container bound is refused before any
    // encoding happens.
    SourceToTargetContainer oversized = container;
    oversized.rrcPayload.assign(MaxTransparentContainerSize, 0x00);
    std::vector<uint8_t> bytes;
    const auto outcome = EncodeSourceToTargetTransparentContainer(oversized, &bytes);
    CHECK_FALSE(outcome.ok);
    CHECK(outcome.refusal == ContainerRefusal::RRC_PAYLOAD_TOO_LARGE);
}

// --- Pinned vectors ---------------------------------------------------------

TEST_CASE("lte/rrc-container: pinned container vectors decode to the fields an independent dissector reports")
{
    // The octets below were dissected with Wireshark's S1AP and LTE RRC
    // dissectors (tshark 4.2.2) while this phase was written. The field values
    // asserted here are the ones it reported.
    const auto sourceBytes = Hex(
        "2038081005001122334400000224a3c616800016400140004048d15a0a080c2347022c461aa058c2825080000108010091"
        "a8607150c20200ce400064f0200abcde0029100064f02000abcde10004b00064f02001234560800fff");
    SourceToTargetContainer source;
    REQUIRE(DecodeSourceToTargetTransparentContainer(sourceBytes.data(), sourceBytes.size(), &source));
    CHECK(source.targetCellId.cellId == 0x0ABCDE0);
    CHECK(source.targetCellId.plmn.mcc == "460");
    CHECK(source.targetCellId.plmn.mnc == "02");
    REQUIRE(source.subscriberProfileIdForRfp.has_value());
    CHECK(*source.subscriberProfileIdForRfp == 42);
    REQUIRE(source.ueHistory.visitedCells.size() == 2);
    CHECK(source.ueHistory.visitedCells[0].globalCellId.cellId == 0x00ABCDE);
    CHECK(source.ueHistory.visitedCells[0].cellSize == 2);
    CHECK(source.ueHistory.visitedCells[0].timeUeStayedInCell == 1200);
    CHECK(source.ueHistory.visitedCells[1].globalCellId.cellId == 0x0123456);
    CHECK(source.ueHistory.visitedCells[1].cellSize == 1);
    CHECK(source.ueHistory.visitedCells[1].timeUeStayedInCell == 4095);
    // The payload is the accepted HandoverPreparationInformation, carried
    // verbatim through the container.
    CHECK(source.rrcPayload ==
          Hex("081005001122334400000224a3c616800016400140004048d15a0a080c2347022c461aa058c2825080000108010091a86071"
              "50c20200ce40"));
    std::vector<uint8_t> reencoded;
    REQUIRE(EncodeSourceToTargetTransparentContainer(source, &reencoded));
    CHECK(reencoded == sourceBytes);

    const auto targetBytes = Hex("000e0061104002a42468000160000040");
    TargetToSourceContainer target;
    REQUIRE(DecodeTargetToSourceTransparentContainer(targetBytes.data(), targetBytes.size(), &target));
    CHECK(target.rrcPayload == Hex("0061104002a42468000160000040"));
    std::vector<uint8_t> reencodedTarget;
    REQUIRE(EncodeTargetToSourceTransparentContainer(target, &reencodedTarget));
    CHECK(reencodedTarget == targetBytes);

    // And the innermost layer: the HandoverCommand payload carries a
    // DL-DCCH-Message whose reconfiguration moves the UE to cell 42.
    lte::rrc::HandoverCommand command;
    REQUIRE(lte::rrc::DecodeHandoverCommandPayload(target.rrcPayload.data(), target.rrcPayload.size(), &command));
    CHECK(command.rrcTransactionIdentifier == 1);
    CHECK(command.targetPhysCellId == 42);
    CHECK(command.t304 == 2);
    CHECK(command.newUeIdentity == 0x1234);
    CHECK(command.prachRootSequenceIndex == 22);
    CHECK(command.ulCyclicPrefixLength == 1);
}

// --- A fully valid nested UE-EUTRA-Capability -------------------------------

namespace
{

// A synthetic but structurally valid UE-EUTRA-Capability, built from the
// asn1c-generated TS 36.331 V15.6.0 types. Every value in it is a deliberately
// chosen standards-valid fixture: it is not a capability captured from a real
// UE and no LTE band support, MIMO capability or feature set in it is claimed
// to be a real measurement.
int AppendBytes(const void *buffer, size_t size, void *key)
{
    auto *out = static_cast<std::vector<uint8_t> *>(key);
    const auto *bytes = static_cast<const uint8_t *>(buffer);
    out->insert(out->end(), bytes, bytes + size);
    return 0;
}

std::vector<uint8_t> SyntheticUeEutraCapability()
{
    UE_EUTRA_Capability_t capability{};
    capability.accessStratumRelease = AccessStratumRelease_rel8;
    capability.ue_Category = 1;
    capability.pdcp_Parameters.supportedROHC_Profiles.profile0x0001_r15 = 1;
    capability.pdcp_Parameters.supportedROHC_Profiles.profile0x0006_r15 = 1;
    capability.phyLayerParameters.ue_TxAntennaSelectionSupported = 0;
    capability.phyLayerParameters.ue_SpecificRefSigsSupported = 0;

    // One supported band: band 1, full duplex.
    auto *band = static_cast<SupportedBandEUTRA_t *>(std::calloc(1, sizeof(SupportedBandEUTRA_t)));
    band->bandEUTRA = 1;
    band->halfDuplex = 0;
    ASN_SEQUENCE_ADD(&capability.rf_Parameters.supportedBandListEUTRA, band);

    // The measurement parameters need one band entry, which needs one
    // inter-frequency band info.
    auto *info = static_cast<InterFreqBandInfo_t *>(std::calloc(1, sizeof(InterFreqBandInfo_t)));
    info->interFreqNeedForGaps = 0;
    InterFreqBandInfo_t **list =
        static_cast<InterFreqBandInfo_t **>(std::calloc(1, sizeof(InterFreqBandInfo_t *)));
    list[0] = info;
    auto *bandInfo = static_cast<BandInfoEUTRA_t *>(std::calloc(1, sizeof(BandInfoEUTRA_t)));
    bandInfo->interFreqBandList.list.array = list;
    bandInfo->interFreqBandList.list.count = 1;
    bandInfo->interFreqBandList.list.size = 1;
    ASN_SEQUENCE_ADD(&capability.measParameters.bandListEUTRA, bandInfo);

    std::vector<uint8_t> encoded;
    const asn_enc_rval_t result =
        uper_encode(&asn_DEF_UE_EUTRA_Capability, nullptr, &capability, AppendBytes, &encoded);
    ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_UE_EUTRA_Capability, &capability);
    if (result.encoded < 0)
        return {};
    return encoded;
}

} // namespace

TEST_CASE("lte/rrc-container: a fully valid nested ue-eutra-capability vector dissects end to end")
{
    const auto capability = SyntheticUeEutraCapability();
    REQUIRE_FALSE(capability.empty());

    // The preparation message carries it as the UE's E-UTRA capability
    // container, exactly where the fixture belongs.
    lte::rrc::HandoverPreparation preparation;
    preparation.ueCapabilities.push_back(lte::rrc::UeCapabilityContainer{0, capability});
    std::vector<uint8_t> rrc;
    REQUIRE(lte::rrc::EncodeHandoverPreparationInformation(preparation, &rrc));

    SourceToTargetContainer container;
    container.rrcPayload = rrc;
    container.targetCellId = FixtureCgi(0x0ABCDE0);
    container.ueHistory = FixtureHistory();
    std::vector<uint8_t> bytes;
    REQUIRE(EncodeSourceToTargetTransparentContainer(container, &bytes));

    // Every layer comes back out.
    SourceToTargetContainer unpacked;
    REQUIRE(DecodeSourceToTargetTransparentContainer(bytes.data(), bytes.size(), &unpacked));
    CHECK(unpacked.rrcPayload == rrc);

    lte::rrc::HandoverPreparation unpackedRrc;
    REQUIRE(lte::rrc::DecodeHandoverPreparationInformation(unpacked.rrcPayload.data(),
                                                           unpacked.rrcPayload.size(), &unpackedRrc));
    REQUIRE(unpackedRrc.ueCapabilities.size() == 1);
    CHECK(unpackedRrc.ueCapabilities[0].container == capability);

    // The complete container travels in a real S1AP Handover Required, whose
    // message layer treats it as the opaque octet string it is.
    HandoverRequired required;
    required.mmeUeS1apId = 201;
    required.enbUeS1apId = 1;
    required.handoverType = HandoverType::INTRA_LTE;
    required.causeCategory = "radioNetwork";
    required.causeValue = 16;
    required.target = EnbIdentity{TestPlmn(), 0x00ABCDEu, 2};
    required.sourceToTarget = bytes;
    const auto pdu = EncodeHandoverRequired(required);
    const auto decoded = DecodeHandoverRequired(pdu.data(), pdu.size());
    CHECK(decoded.sourceToTarget == bytes);
}
