//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

// Phase 18-F-B1: the LTE RRC UPER codec for the two handover containers.
//
// The fixtures are ordinary octets. Their field-level content was checked
// against Wireshark's independent LTE RRC dissector (tshark 4.2.2), not against
// this codec: a vector this codec produced and immediately decoded would prove
// only that it agrees with itself.

#include <ext/doctest/doctest.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <string>
#include <vector>

#include <lte/enb/codec.hpp>
#include <lte/enb/handover_live_ingress.hpp>
#include <lte/rrc/rrc_handover.hpp>

namespace
{

using namespace lte::rrc;

std::vector<uint8_t> Hex(const std::string &text)
{
    std::vector<uint8_t> out;
    for (size_t i = 0; i + 1 < text.size(); i += 2)
        out.push_back(static_cast<uint8_t>(std::stoul(text.substr(i, 2), nullptr, 16)));
    return out;
}

// A complete AS-Config, every mandatory member filled with a value a real
// source cell could hold. Nothing here is a placeholder chosen to make an
// encoder succeed: the values are the ones the test then checks on the way back.
SourceAsConfig SampleSourceConfig()
{
    SourceAsConfig config;
    config.cipheringAlgorithm = 2;      // eea2
    config.integrityProtAlgorithm = 2;  // eia2
    config.sourceUeIdentity = 0x4A3C;
    config.antennaPortsCount = 0;       // an1
    config.sourceDlCarrierFreq = 1650;  // band 3, EARFCN 1650

    config.mib.dlBandwidth = 3;         // n50
    config.mib.phichDuration = 0;       // normal
    config.mib.phichResource = 0;       // oneSixth
    config.mib.systemFrameNumber = 0x5A;
    config.mib.schedulingInfoSib1Br = 0;
    config.mib.systemInfoUnchangedBr = false;
    config.mib.spare = 0;

    config.sib1.plmnIdentity = {0x64, 0x0F, 0x20};  // MCC 460, MNC 02, TS 24.008 order
    config.sib1.cellReservedForOperatorUse = 1;      // notReserved
    config.sib1.trackingAreaCode = 0x0001;
    config.sib1.cellIdentity = 0x0123456;
    config.sib1.cellBarred = 1;                      // notBarred
    config.sib1.intraFreqReselection = 0;            // allowed
    config.sib1.csgIndication = false;
    config.sib1.qRxLevMin = -60;
    config.sib1.freqBandIndicator = 3;
    config.sib1.siPeriodicity = 3;                   // rf64
    config.sib1.sibType = 3;                         // systemInformationBlockType3
    config.sib1.siWindowLength = 2;                  // ms5
    config.sib1.systemInfoValueTag = 7;

    auto &sib2 = config.sib2;
    sib2.radioResourceConfigCommon.numberOfRaPreambles = 8;
    sib2.radioResourceConfigCommon.powerRampingStep = 2;
    sib2.radioResourceConfigCommon.preambleInitialReceivedTargetPower = 12;
    sib2.radioResourceConfigCommon.preambleTransMax = 4;
    sib2.radioResourceConfigCommon.raResponseWindowSize = 3;
    sib2.radioResourceConfigCommon.maxHarqMsg3Tx = 4;
    sib2.radioResourceConfigCommon.bcchModificationPeriodCoeff = 1;
    sib2.radioResourceConfigCommon.pcchDefaultPagingCycle = 1;
    sib2.radioResourceConfigCommon.pcchNb = 2;
    sib2.radioResourceConfigCommon.prachRootSequenceIndex = 22;
    sib2.radioResourceConfigCommon.prachConfigIndex = 12;
    sib2.radioResourceConfigCommon.prachHighSpeedFlag = false;
    sib2.radioResourceConfigCommon.prachZeroCorrelationZoneConfig = 5;
    sib2.radioResourceConfigCommon.prachFreqOffset = 2;
    sib2.radioResourceConfigCommon.pdschReferenceSignalPower = -20;
    sib2.radioResourceConfigCommon.pdschPb = 1;
    sib2.radioResourceConfigCommon.puschNSb = 1;
    sib2.radioResourceConfigCommon.puschHoppingMode = 0;
    sib2.radioResourceConfigCommon.puschHoppingOffset = 0;
    sib2.radioResourceConfigCommon.puschEnable64Qam = false;
    sib2.radioResourceConfigCommon.puschGroupHoppingEnabled = false;
    sib2.radioResourceConfigCommon.puschGroupAssignmentPusch = 0;
    sib2.radioResourceConfigCommon.puschSequenceHoppingEnabled = false;
    sib2.radioResourceConfigCommon.puschCyclicShift = 0;
    sib2.radioResourceConfigCommon.pucchDeltaShift = 1;
    sib2.radioResourceConfigCommon.pucchNrbCqi = 4;
    sib2.radioResourceConfigCommon.pucchNcsAn = 0;
    sib2.radioResourceConfigCommon.pucchN1PucchAn = 32;
    sib2.radioResourceConfigCommon.soundingRsRelease = true;
    sib2.radioResourceConfigCommon.p0NominalPusch = -90;
    sib2.radioResourceConfigCommon.alpha = 3;
    sib2.radioResourceConfigCommon.p0NominalPucch = -117;
    sib2.radioResourceConfigCommon.deltaFPucchFormat1 = 0;
    sib2.radioResourceConfigCommon.deltaFPucchFormat1b = 1;
    sib2.radioResourceConfigCommon.deltaFPucchFormat2 = 2;
    sib2.radioResourceConfigCommon.deltaFPucchFormat2a = 0;
    sib2.radioResourceConfigCommon.deltaFPucchFormat2b = 0;
    sib2.radioResourceConfigCommon.deltaPreambleMsg3 = 2;
    sib2.radioResourceConfigCommon.ulCyclicPrefixLength = 1;
    sib2.t300 = 1;
    sib2.t301 = 2;
    sib2.t310 = 4;
    sib2.n310 = 1;
    sib2.t311 = 4;
    sib2.n311 = 1;
    sib2.additionalSpectrumEmission = 1;
    sib2.timeAlignmentTimerCommon = 4;
    return config;
}

HandoverPreparation SamplePreparation()
{
    HandoverPreparation message;
    // RAT-Type 0 is eutra: the UE's E-UTRA capability container.
    message.ueCapabilities.push_back(UeCapabilityContainer{0, {0x00, 0x11, 0x22, 0x33, 0x44}});
    message.asConfig = SampleSourceConfig();
    return message;
}

HandoverCommand SampleCommand()
{
    HandoverCommand command;
    command.rrcTransactionIdentifier = 1;
    command.targetPhysCellId = 42;
    command.t304 = 2;              // ms150
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

} // namespace

TEST_CASE("lte/rrc: a handover preparation information round-trips through uper")
{
    const HandoverPreparation message = SamplePreparation();
    std::vector<uint8_t> uper;
    REQUIRE(EncodeHandoverPreparationInformation(message, &uper));
    CHECK_FALSE(uper.empty());
    CHECK(uper.size() <= MaxRrcContainerSize);

    HandoverPreparation decoded;
    const RrcOutcome decodeOutcome = DecodeHandoverPreparationInformation(uper.data(), uper.size(), &decoded);
    INFO(decodeOutcome.detail);
    REQUIRE(decodeOutcome.ok);
    REQUIRE(decoded.ueCapabilities.size() == 1);
    CHECK(decoded.ueCapabilities[0].ratType == 0);
    CHECK(decoded.ueCapabilities[0].container == std::vector<uint8_t>({0x00, 0x11, 0x22, 0x33, 0x44}));
    REQUIRE(decoded.asConfig.has_value());
    const auto &config = *decoded.asConfig;
    CHECK(config.cipheringAlgorithm == 2);
    CHECK(config.integrityProtAlgorithm == 2);
    CHECK(config.sourceUeIdentity == 0x4A3C);
    CHECK(config.antennaPortsCount == 0);
    CHECK(config.sourceDlCarrierFreq == 1650);
    CHECK(config.mib.dlBandwidth == 3);
    CHECK(config.mib.systemFrameNumber == 0x5A);
    CHECK(config.sib1.plmnIdentity == std::array<uint8_t, 3>{0x64, 0x0F, 0x20});
    CHECK(config.sib1.trackingAreaCode == 0x0001);
    CHECK(config.sib1.cellIdentity == 0x0123456);
    CHECK(config.sib1.freqBandIndicator == 3);
    CHECK(config.sib1.systemInfoValueTag == 7);
    CHECK(config.sib2.radioResourceConfigCommon.prachRootSequenceIndex == 22);
    CHECK(config.sib2.radioResourceConfigCommon.maxHarqMsg3Tx == 4);
    CHECK(config.sib2.radioResourceConfigCommon.p0NominalPusch == -90);
    CHECK(config.sib2.radioResourceConfigCommon.p0NominalPucch == -117);
    CHECK(config.sib2.t311 == 4);
    CHECK(config.sib2.timeAlignmentTimerCommon == 4);
}

TEST_CASE("lte/rrc: a handover command round-trips through uper")
{
    const HandoverCommand message = SampleCommand();
    std::vector<uint8_t> uper;
    REQUIRE(EncodeHandoverCommand(message, &uper));
    REQUIRE_FALSE(uper.empty());

    HandoverCommand decoded;
    const RrcOutcome commandOutcome = DecodeHandoverCommand(uper.data(), uper.size(), &decoded);
    INFO(commandOutcome.detail);
    REQUIRE(commandOutcome.ok);
    CHECK(decoded.rrcTransactionIdentifier == 1);
    CHECK(decoded.targetPhysCellId == 42);
    CHECK(decoded.t304 == 2);
    CHECK(decoded.newUeIdentity == 0x1234);
    CHECK(decoded.prachRootSequenceIndex == 22);
    CHECK(decoded.puschNSb == 1);
    CHECK(decoded.puschGroupAssignmentPusch == 0);
    CHECK(decoded.ulCyclicPrefixLength == 1);
}

TEST_CASE("lte/rrc: encoding is deterministic across repeated runs")
{
    std::vector<uint8_t> first;
    const RrcOutcome firstOutcome = EncodeHandoverPreparationInformation(SamplePreparation(), &first);
    INFO(firstOutcome.detail);
    REQUIRE(firstOutcome.ok);
    for (int i = 0; i < 16; ++i)
    {
        std::vector<uint8_t> again;
        REQUIRE(EncodeHandoverPreparationInformation(SamplePreparation(), &again));
        CHECK(again == first);
    }

    std::vector<uint8_t> command;
    REQUIRE(EncodeHandoverCommand(SampleCommand(), &command));
    for (int i = 0; i < 16; ++i)
    {
        std::vector<uint8_t> again;
        REQUIRE(EncodeHandoverCommand(SampleCommand(), &again));
        CHECK(again == command);
    }
}

// --- The S1AP transparent-container boundary --------------------------------

TEST_CASE("lte/rrc: the rrc octets survive the s1ap transparent container unchanged")
{
    using namespace lte::enb::s1ap;

    // Source side: the HandoverPreparationInformation travels as the
    // Source-ToTarget container of a Handover Required.
    std::vector<uint8_t> preparation;
    REQUIRE(EncodeHandoverPreparationInformation(SamplePreparation(), &preparation));

    HandoverRequired required;
    required.mmeUeS1apId = 201;
    required.enbUeS1apId = 1;
    required.handoverType = HandoverType::INTRA_LTE;
    required.causeCategory = "radioNetwork";
    required.causeValue = 16;
    required.target = EnbIdentity{lte::enb::Plmn{"460", "02"}, 0x00ABCDEu, 2};
    required.sourceToTarget = preparation;
    const auto requiredPdu = EncodeHandoverRequired(required);

    const auto decodedRequired = DecodeHandoverRequired(requiredPdu.data(), requiredPdu.size());
    // The inner octets are the ones the RRC encoder produced, byte for byte.
    CHECK(decodedRequired.sourceToTarget == preparation);

    lte::rrc::HandoverPreparation unpacked;
    REQUIRE(DecodeHandoverPreparationInformation(decodedRequired.sourceToTarget.data(),
                                                 decodedRequired.sourceToTarget.size(), &unpacked));
    REQUIRE(unpacked.asConfig.has_value());
    CHECK(unpacked.asConfig->sourceUeIdentity == 0x4A3C);
    CHECK(unpacked.asConfig->sib1.cellIdentity == 0x0123456);

    // Target side: the HandoverCommand travels as the Target-ToSource container
    // of a Handover Request Acknowledge.
    std::vector<uint8_t> command;
    REQUIRE(EncodeHandoverCommand(SampleCommand(), &command));

    HandoverRequestAcknowledge acknowledge;
    acknowledge.mmeUeS1apId = 201;
    acknowledge.enbUeS1apId = 1;
    ErabAdmittedItem admitted;
    admitted.erabId = 5;
    admitted.transportLayerAddress = {127, 0, 0, 3};
    admitted.gtpTeid = {0x00, 0x00, 0x11, 0x22};
    acknowledge.admitted = {admitted};
    acknowledge.targetToSource = command;
    const auto acknowledgePdu = EncodeHandoverRequestAcknowledge(acknowledge);
    const auto decodedAcknowledge = DecodeHandoverRequestAcknowledge(acknowledgePdu.data(), acknowledgePdu.size());
    CHECK(decodedAcknowledge.targetToSource == command);

    lte::rrc::HandoverCommand unpackedCommand;
    REQUIRE(DecodeHandoverCommand(decodedAcknowledge.targetToSource.data(), decodedAcknowledge.targetToSource.size(),
                                  &unpackedCommand));
    CHECK(unpackedCommand.targetPhysCellId == 42);
    CHECK(unpackedCommand.newUeIdentity == 0x1234);

    // The layers stay separate: the same octets are an APER S1AP message in one
    // direction and a UPER RRC message in the other, and neither decoder
    // accepts the other's encoding.
    CHECK_THROWS_AS(DecodeHandoverRequest(preparation.data(), preparation.size()), lte::enb::s1ap::CodecError);
    CHECK_THROWS_AS(DecodeHandoverRequired(command.data(), command.size()), lte::enb::s1ap::CodecError);
}

// --- Negative vectors -------------------------------------------------------

TEST_CASE("lte/rrc: malformed and unsupported containers are refused")
{
    std::vector<uint8_t> preparation;
    REQUIRE(EncodeHandoverPreparationInformation(SamplePreparation(), &preparation));
    std::vector<uint8_t> command;
    REQUIRE(EncodeHandoverCommand(SampleCommand(), &command));

    SUBCASE("an empty container")
    {
        lte::rrc::HandoverPreparation out;
        const auto outcome = DecodeHandoverPreparationInformation(nullptr, 0, &out);
        CHECK_FALSE(outcome.ok);
        CHECK(outcome.refusal == RrcRefusal::EMPTY_INPUT);
    }
    SUBCASE("a truncated preparation")
    {
        lte::rrc::HandoverPreparation out;
        const auto outcome =
            DecodeHandoverPreparationInformation(preparation.data(), preparation.size() / 2, &out);
        CHECK_FALSE(outcome.ok);
        CHECK(outcome.refusal == RrcRefusal::TRUNCATED);
    }
    SUBCASE("a preparation with trailing octets")
    {
        auto padded = preparation;
        padded.push_back(0x00);
        lte::rrc::HandoverPreparation out;
        const auto outcome = DecodeHandoverPreparationInformation(padded.data(), padded.size(), &out);
        CHECK_FALSE(outcome.ok);
        CHECK(outcome.refusal == RrcRefusal::TRUNCATED);
    }
    SUBCASE("a container larger than the receiver bound")
    {
        std::vector<uint8_t> oversized(MaxRrcContainerSize + 1, 0x00);
        lte::rrc::HandoverPreparation out;
        const auto outcome = DecodeHandoverPreparationInformation(oversized.data(), oversized.size(), &out);
        CHECK_FALSE(outcome.ok);
        CHECK(outcome.refusal == RrcRefusal::OVERSIZED);
    }
    SUBCASE("the simulator's own container is not rrc")
    {
        const std::vector<uint8_t> simulator{'S', 'I', 'M', '-', 'H', 'O', 'v', '1', 0x00, 0x01};
        lte::rrc::HandoverPreparation out;
        const auto outcome = DecodeHandoverPreparationInformation(simulator.data(), simulator.size(), &out);
        CHECK_FALSE(outcome.ok);
        CHECK(outcome.refusal == RrcRefusal::NOT_HANDOVER_MESSAGE);

        lte::rrc::HandoverCommand commandOut;
        const auto commandOutcome = DecodeHandoverCommand(simulator.data(), simulator.size(), &commandOut);
        CHECK_FALSE(commandOutcome.ok);
        CHECK(commandOutcome.refusal == RrcRefusal::NOT_HANDOVER_MESSAGE);
    }
    SUBCASE("a command container decoded as a preparation")
    {
        lte::rrc::HandoverPreparation out;
        const auto outcome = DecodeHandoverPreparationInformation(command.data(), command.size(), &out);
        CHECK_FALSE(outcome.ok);
    }
    SUBCASE("a preparation container decoded as a command")
    {
        lte::rrc::HandoverCommand out;
        const auto outcome = DecodeHandoverCommand(preparation.data(), preparation.size(), &out);
        CHECK_FALSE(outcome.ok);
    }
    SUBCASE("a single flipped octet in the preparation")
    {
        auto corrupted = preparation;
        corrupted[corrupted.size() / 2] ^= 0xFF;
        lte::rrc::HandoverPreparation out;
        const auto outcome = DecodeHandoverPreparationInformation(corrupted.data(), corrupted.size(), &out);
        // Either the structure no longer parses or it decodes to different
        // values; what it must never do is report the original message.
        if (outcome.ok)
        {
            const bool sameIdentity = out.asConfig->sourceUeIdentity == 0x4A3C;
            const bool sameCell = out.asConfig->sib1.cellIdentity == 0x0123456;
            CHECK((sameIdentity && sameCell) == false);
        }
    }
}

TEST_CASE("lte/rrc: encoding refuses values outside the constraints it declares")
{
    std::vector<uint8_t> out;
    SUBCASE("a physical cell identity beyond 503")
    {
        auto command = SampleCommand();
        command.targetPhysCellId = 504;
        const auto outcome = EncodeHandoverCommand(command, &out);
        CHECK_FALSE(outcome.ok);
        CHECK(outcome.refusal == RrcRefusal::INVALID_CONSTRAINT);
    }
    SUBCASE("a transaction identifier beyond 3")
    {
        auto command = SampleCommand();
        command.rrcTransactionIdentifier = 4;
        const auto outcome = EncodeHandoverCommand(command, &out);
        CHECK_FALSE(outcome.ok);
        CHECK(outcome.refusal == RrcRefusal::INVALID_CONSTRAINT);
    }
    SUBCASE("a preparation with no capability container")
    {
        lte::rrc::HandoverPreparation message;
        message.asConfig = SampleSourceConfig();
        const auto outcome = EncodeHandoverPreparationInformation(message, &out);
        CHECK_FALSE(outcome.ok);
        CHECK(outcome.refusal == RrcRefusal::MISSING_MANDATORY);
    }
    SUBCASE("a capability container with no octets")
    {
        lte::rrc::HandoverPreparation message;
        message.ueCapabilities.push_back(UeCapabilityContainer{0, {}});
        const auto outcome = EncodeHandoverPreparationInformation(message, &out);
        CHECK_FALSE(outcome.ok);
        CHECK(outcome.refusal == RrcRefusal::MISSING_MANDATORY);
    }
}

TEST_CASE("lte/rrc: a valid container does not make a handover executable")
{
    // The codec can now produce and consume both containers. Nothing about
    // that changes what the live ingress may execute: the security, radio and
    // provenance capabilities are still absent, and the assessment says so.
    const lte::enb::s1ap::LiveHandoverReadiness readiness =
        lte::enb::s1ap::AssessLiveHandoverCapabilities();
    CHECK_FALSE(readiness.available(lte::enb::s1ap::HandoverCapability::SOURCE_PROVENANCE_READY));
    CHECK_FALSE(readiness.available(lte::enb::s1ap::HandoverCapability::HANDOVER_SECURITY_READY));
    CHECK_FALSE(readiness.available(lte::enb::s1ap::HandoverCapability::UE_RADIO_EXECUTION_READY));
    CHECK_FALSE(readiness.liveExecutionReady());
}


// --- Pinned vectors ---------------------------------------------------------

TEST_CASE("lte/rrc: pinned uper vectors decode to the values an independent dissector reports")
{
    // The octets below were dissected with Wireshark's LTE RRC / S1AP dissector
    // (tshark 4.2.2) while this phase was written; the field values asserted
    // here are the ones it reported, not the ones this codec happened to write.
    const auto preparation = Hex(
        "081005001122334400000224a3c616800016400140004048d15a0a080c2347022c461aa058c2825080000108010091a8607150c20200ce40");
    lte::rrc::HandoverPreparation decodedPreparation;
    REQUIRE(DecodeHandoverPreparationInformation(preparation.data(), preparation.size(), &decodedPreparation));
    REQUIRE(decodedPreparation.ueCapabilities.size() == 1);
    CHECK(decodedPreparation.ueCapabilities[0].ratType == 0);
    CHECK(decodedPreparation.ueCapabilities[0].container == std::vector<uint8_t>({0x00, 0x11, 0x22, 0x33, 0x44}));
    REQUIRE(decodedPreparation.asConfig.has_value());
    CHECK(decodedPreparation.asConfig->sourceUeIdentity == 0x4A3C);
    CHECK(decodedPreparation.asConfig->sib1.cellIdentity == 0x0123456);

    // Re-encoding the decoded value reproduces the same octets: the codec is
    // deterministic and the vector is not a one-way fixture.
    std::vector<uint8_t> reencoded;
    REQUIRE(EncodeHandoverPreparationInformation(decodedPreparation, &reencoded));
    CHECK(reencoded == preparation);

    const auto command = Hex("005a080054848d00002c000008");
    lte::rrc::HandoverCommand decodedCommand;
    REQUIRE(DecodeHandoverCommand(command.data(), command.size(), &decodedCommand));
    CHECK(decodedCommand.rrcTransactionIdentifier == 1);
    CHECK(decodedCommand.targetPhysCellId == 42);
    CHECK(decodedCommand.t304 == 2);
    CHECK(decodedCommand.newUeIdentity == 0x1234);

    std::vector<uint8_t> reencodedCommand;
    REQUIRE(EncodeHandoverCommand(decodedCommand, &reencodedCommand));
    CHECK(reencodedCommand == command);
}

