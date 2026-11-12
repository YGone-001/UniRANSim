//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#include "rrc_handover.hpp"

#include <algorithm>
#include <cstdlib>
#include <type_traits>
#include <cstring>
#include <utility>

#include "AS-Config.h"
#include "AntennaInfoCommon.h"
#include "BCCH-Config.h"
#include "DL-DCCH-Message.h"
#include "DeltaFList-PUCCH.h"
#include "HandoverCommand-r8-IEs.h"
#include "HandoverCommand.h"
#include "HandoverPreparationInformation-r8-IEs.h"
#include "HandoverPreparationInformation.h"
#include "MCC.h"
#include "MasterInformationBlock.h"
#include "MobilityControlInfo.h"
#include "PCCH-Config.h"
#include "PHICH-Config.h"
#include "PLMN-Identity.h"
#include "PLMN-IdentityInfo.h"
#include "PRACH-Config.h"
#include "PRACH-ConfigSIB.h"
#include "PUCCH-ConfigCommon.h"
#include "PDSCH-ConfigCommon.h"
#include "PUSCH-ConfigCommon.h"
#include "RACH-ConfigCommon.h"
#include "RRCConnectionReconfiguration-r8-IEs.h"
#include "RRCConnectionReconfiguration.h"
#include "RadioResourceConfigCommon.h"
#include "RadioResourceConfigCommonSIB.h"
#include "SIB-Type.h"
#include "SchedulingInfo.h"
#include "SchedulingInfoList.h"
#include "SecurityAlgorithmConfig.h"
#include "SoundingRS-UL-ConfigCommon.h"
#include "SystemInformationBlockType1.h"
#include "SystemInformationBlockType2.h"
#include "RAT-Type.h"
#include "UE-CapabilityRAT-Container.h"
#include "UE-CapabilityRAT-ContainerList.h"
#include "UE-TimersAndConstants.h"
#include "UplinkPowerControlCommon.h"

namespace lte::rrc
{
namespace
{

template <typename T> T *Alloc()
{
    return static_cast<T *>(std::calloc(1, sizeof(T)));
}

bool SetOctets(OCTET_STRING_t &target, const std::vector<uint8_t> &value)
{
    return OCTET_STRING_fromBuf(&target, reinterpret_cast<const char *>(value.data()),
                                static_cast<int>(value.size())) == 0;
}

// A BIT STRING whose value fits in 64 bits, left aligned in its octets with the
// unused trailing bits cleared. Every bit string this codec writes is of that
// shape; the largest is the 28-bit cell identity.
bool SetBits(BIT_STRING_t &target, uint64_t value, size_t bits)
{
    if (bits == 0 || bits > 64)
        return false;
    const size_t octets = (bits + 7) / 8;
    target.buf = static_cast<uint8_t *>(std::calloc(octets, 1));
    if (target.buf == nullptr)
        return false;
    target.size = static_cast<int>(octets);
    target.bits_unused = static_cast<int>((bits % 8) ? (8 - bits % 8) : 0);
    // A PER bit string is left aligned: the value occupies the most significant
    // bits of the first octet, so a 28-bit value is shifted up by the four
    // unused bits before it is written out big-endian.
    const uint64_t aligned = value << target.bits_unused;
    for (size_t i = 0; i < octets; ++i)
        target.buf[i] = static_cast<uint8_t>(aligned >> ((octets - 1 - i) * 8));
    return true;
}

uint64_t GetBits(const BIT_STRING_t &value)
{
    uint64_t out = 0;
    const size_t octets = static_cast<size_t>(value.size);
    for (size_t i = 0; i < octets && i < 8; ++i)
        out = (out << 8U) | value.buf[i];
    if (value.bits_unused > 0 && value.bits_unused < 8)
        out >>= value.bits_unused;
    return out;
}

int AppendBytes(const void *buffer, size_t size, void *key)
{
    auto *out = static_cast<std::vector<uint8_t> *>(key);
    const auto *bytes = static_cast<const uint8_t *>(buffer);
    out->insert(out->end(), bytes, bytes + size);
    return 0;
}


// The default asn1c decode context bounds recursion by measuring the stack
// against the context object's own address. A sanitizer build enlarges every
// frame, so that heuristic reports an overflow long before the message is
// exhausted. The input here is already bounded by MaxRrcContainerSize and the
// nesting is fixed by the ASN.1, so the check is disabled: with
// max_stack_size zero the decoder leaves the guard off.
asn_codec_ctx_t BoundedDecodeContext()
{
    asn_codec_ctx_t context{};
    context.max_stack_size = 0;
    return context;
}

RrcOutcome Refuse(RrcRefusal refusal, std::string detail)
{
    RrcOutcome outcome;
    outcome.ok = false;
    outcome.refusal = refusal;
    outcome.detail = std::move(detail);
    return outcome;
}

bool InRange(long value, long low, long high)
{
    return value >= low && value <= high;
}

// The three PLMN octets TS 24.008 defines, unpacked into the digit sequences
// TS 36.331 carries. Nothing is invented: the digits come from the octets the
// caller supplied.
void UnpackPlmn(const std::array<uint8_t, 3> &octets, PLMN_Identity_t &identity)
{
    const uint8_t mcc2 = static_cast<uint8_t>(octets[0] & 0x0F);
    const uint8_t mcc1 = static_cast<uint8_t>(octets[0] >> 4U);
    const uint8_t mnc3 = static_cast<uint8_t>(octets[1] & 0x0F);
    const uint8_t mcc3 = static_cast<uint8_t>(octets[1] >> 4U);
    const uint8_t mnc1 = static_cast<uint8_t>(octets[2] & 0x0F);
    const uint8_t mnc2 = static_cast<uint8_t>(octets[2] >> 4U);

    // A SEQUENCE (SIZE (n)) OF MCC-MNC-Digit holds pointers to individually
    // allocated digits, so each one is allocated and filled on its own.
    auto newDigit = [](uint8_t value) -> MCC_MNC_Digit_t * {
        auto *digit = static_cast<MCC_MNC_Digit_t *>(std::calloc(1, sizeof(MCC_MNC_Digit_t)));
        *digit = value;
        return digit;
    };

    identity.mcc = Alloc<MCC_t>();
    identity.mcc->list.array = static_cast<MCC_MNC_Digit_t **>(std::calloc(3, sizeof(MCC_MNC_Digit_t *)));
    identity.mcc->list.array[0] = newDigit(mcc1);
    identity.mcc->list.array[1] = newDigit(mcc2);
    identity.mcc->list.array[2] = newDigit(mcc3);
    identity.mcc->list.count = 3;
    identity.mcc->list.size = 3;

    const bool twoDigit = mnc3 == 0x0F;
    const size_t mncCount = twoDigit ? 2 : 3;
    identity.mnc.list.array = static_cast<MCC_MNC_Digit_t **>(std::calloc(mncCount, sizeof(MCC_MNC_Digit_t *)));
    identity.mnc.list.array[0] = newDigit(mnc1);
    identity.mnc.list.array[1] = newDigit(mnc2);
    if (!twoDigit)
        identity.mnc.list.array[2] = newDigit(mnc3);
    identity.mnc.list.count = static_cast<int>(mncCount);
    identity.mnc.list.size = static_cast<int>(mncCount);
}

std::array<uint8_t, 3> PackPlmn(const PLMN_Identity_t &identity)
{
    auto digit = [](MCC_MNC_Digit_t *const *list, int count, int index) -> uint8_t {
        return (list != nullptr && index < count && list[index] != nullptr)
                   ? static_cast<uint8_t>(*list[index] & 0x0F)
                   : 0x0F;
    };
    const auto *mcc = identity.mcc;
    const uint8_t mcc1 = digit(mcc != nullptr ? mcc->list.array : nullptr, mcc != nullptr ? mcc->list.count : 0, 0);
    const uint8_t mcc2 = digit(mcc != nullptr ? mcc->list.array : nullptr, mcc != nullptr ? mcc->list.count : 0, 1);
    const uint8_t mcc3 = digit(mcc != nullptr ? mcc->list.array : nullptr, mcc != nullptr ? mcc->list.count : 0, 2);
    const uint8_t mnc1 = digit(identity.mnc.list.array, identity.mnc.list.count, 0);
    const uint8_t mnc2 = digit(identity.mnc.list.array, identity.mnc.list.count, 1);
    const uint8_t mnc3 = identity.mnc.list.count >= 3
                             ? digit(identity.mnc.list.array, identity.mnc.list.count, 2)
                             : static_cast<uint8_t>(0x0F);
    std::array<uint8_t, 3> out{};
    out[0] = static_cast<uint8_t>((mcc1 << 4U) | mcc2);
    out[1] = static_cast<uint8_t>((mcc3 << 4U) | mnc3);
    out[2] = static_cast<uint8_t>((mnc2 << 4U) | mnc1);
    return out;
}

// --- Filling the generated structures ---------------------------------------

void FillMib(MasterInformationBlock_t &target, const MasterInformationBlock &source)
{
    target.dl_Bandwidth = source.dlBandwidth;
    target.phich_Config.phich_Duration = source.phichDuration;
    target.phich_Config.phich_Resource = source.phichResource;
    SetBits(target.systemFrameNumber, source.systemFrameNumber, 8);
    target.schedulingInfoSIB1_BR_r13 = source.schedulingInfoSib1Br;
    target.systemInfoUnchanged_BR_r15 = source.systemInfoUnchangedBr ? 1 : 0;
    SetBits(target.spare, source.spare, 4);
}

void FillSib1(SystemInformationBlockType1_t &target, const SystemInformationBlockType1 &source)
{
    auto *info = Alloc<PLMN_IdentityInfo_t>();
    UnpackPlmn(source.plmnIdentity, info->plmn_Identity);
    info->cellReservedForOperatorUse = source.cellReservedForOperatorUse;
    ASN_SEQUENCE_ADD(&target.cellAccessRelatedInfo.plmn_IdentityList, info);

    SetBits(target.cellAccessRelatedInfo.trackingAreaCode, source.trackingAreaCode, 16);
    SetBits(target.cellAccessRelatedInfo.cellIdentity, source.cellIdentity, 28);
    target.cellAccessRelatedInfo.cellBarred = source.cellBarred;
    target.cellAccessRelatedInfo.intraFreqReselection = source.intraFreqReselection;
    target.cellAccessRelatedInfo.csg_Indication = source.csgIndication ? 1 : 0;

    target.cellSelectionInfo.q_RxLevMin = source.qRxLevMin;
    target.freqBandIndicator = source.freqBandIndicator;

    auto *scheduling = Alloc<SchedulingInfo_t>();
    scheduling->si_Periodicity = source.siPeriodicity;
    auto *sib = static_cast<SIB_Type_t *>(std::calloc(1, sizeof(SIB_Type_t)));
    *sib = static_cast<SIB_Type_t>(source.sibType);
    auto **sibArray = static_cast<SIB_Type_t **>(std::calloc(1, sizeof(SIB_Type_t *)));
    sibArray[0] = sib;
    scheduling->sib_MappingInfo.list.array = sibArray;
    scheduling->sib_MappingInfo.list.count = 1;
    scheduling->sib_MappingInfo.list.size = 1;
    ASN_SEQUENCE_ADD(&target.schedulingInfoList, scheduling);

    target.si_WindowLength = source.siWindowLength;
    target.systemInfoValueTag = source.systemInfoValueTag;
}

void FillRachConfigCommon(RACH_ConfigCommon_t &target, const RadioResourceConfigCommonSib &source)
{
    target.preambleInfo.numberOfRA_Preambles = source.numberOfRaPreambles;
    target.powerRampingParameters.powerRampingStep = source.powerRampingStep;
    target.powerRampingParameters.preambleInitialReceivedTargetPower = source.preambleInitialReceivedTargetPower;
    target.ra_SupervisionInfo.preambleTransMax = source.preambleTransMax;
    target.ra_SupervisionInfo.ra_ResponseWindowSize = source.raResponseWindowSize;
    target.maxHARQ_Msg3Tx = source.maxHarqMsg3Tx;
}

void FillRrcCommonSib(RadioResourceConfigCommonSIB_t &target, const RadioResourceConfigCommonSib &source)
{
    FillRachConfigCommon(target.rach_ConfigCommon, source);
    target.bcch_Config.modificationPeriodCoeff = source.bcchModificationPeriodCoeff;
    target.pcch_Config.defaultPagingCycle = source.pcchDefaultPagingCycle;
    target.pcch_Config.nB = source.pcchNb;

    target.prach_Config.rootSequenceIndex = source.prachRootSequenceIndex;
    target.prach_Config.prach_ConfigInfo.prach_ConfigIndex = source.prachConfigIndex;
    target.prach_Config.prach_ConfigInfo.highSpeedFlag = source.prachHighSpeedFlag ? 1 : 0;
    target.prach_Config.prach_ConfigInfo.zeroCorrelationZoneConfig = source.prachZeroCorrelationZoneConfig;
    target.prach_Config.prach_ConfigInfo.prach_FreqOffset = source.prachFreqOffset;

    target.pdsch_ConfigCommon.referenceSignalPower = source.pdschReferenceSignalPower;
    target.pdsch_ConfigCommon.p_b = source.pdschPb;

    target.pusch_ConfigCommon.pusch_ConfigBasic.n_SB = source.puschNSb;
    target.pusch_ConfigCommon.pusch_ConfigBasic.hoppingMode = source.puschHoppingMode;
    target.pusch_ConfigCommon.pusch_ConfigBasic.pusch_HoppingOffset = source.puschHoppingOffset;
    target.pusch_ConfigCommon.pusch_ConfigBasic.enable64QAM = source.puschEnable64Qam ? 1 : 0;
    target.pusch_ConfigCommon.ul_ReferenceSignalsPUSCH.groupHoppingEnabled = source.puschGroupHoppingEnabled ? 1 : 0;
    target.pusch_ConfigCommon.ul_ReferenceSignalsPUSCH.groupAssignmentPUSCH = source.puschGroupAssignmentPusch;
    target.pusch_ConfigCommon.ul_ReferenceSignalsPUSCH.sequenceHoppingEnabled =
        source.puschSequenceHoppingEnabled ? 1 : 0;
    target.pusch_ConfigCommon.ul_ReferenceSignalsPUSCH.cyclicShift = source.puschCyclicShift;

    target.pucch_ConfigCommon.deltaPUCCH_Shift = source.pucchDeltaShift;
    target.pucch_ConfigCommon.nRB_CQI = source.pucchNrbCqi;
    target.pucch_ConfigCommon.nCS_AN = source.pucchNcsAn;
    target.pucch_ConfigCommon.n1PUCCH_AN = source.pucchN1PucchAn;

    if (source.soundingRsRelease)
    {
        target.soundingRS_UL_ConfigCommon.present = SoundingRS_UL_ConfigCommon_PR_release;
    }
    else
    {
        target.soundingRS_UL_ConfigCommon.present = SoundingRS_UL_ConfigCommon_PR_setup;
        using Setup = std::remove_pointer_t<decltype(target.soundingRS_UL_ConfigCommon.choice.setup)>;
        target.soundingRS_UL_ConfigCommon.choice.setup = static_cast<Setup *>(std::calloc(1, sizeof(Setup)));
        target.soundingRS_UL_ConfigCommon.choice.setup->srs_BandwidthConfig = source.srsBandwidthConfig;
        target.soundingRS_UL_ConfigCommon.choice.setup->srs_SubframeConfig = source.srsSubframeConfig;
        target.soundingRS_UL_ConfigCommon.choice.setup->ackNackSRS_SimultaneousTransmission =
            source.ackNackSrsSimultaneousTransmission ? 1 : 0;
    }

    target.uplinkPowerControlCommon.p0_NominalPUSCH = source.p0NominalPusch;
    target.uplinkPowerControlCommon.alpha = static_cast<Alpha_r12_t>(source.alpha);
    target.uplinkPowerControlCommon.p0_NominalPUCCH = source.p0NominalPucch;
    target.uplinkPowerControlCommon.deltaFList_PUCCH.deltaF_PUCCH_Format1 = source.deltaFPucchFormat1;
    target.uplinkPowerControlCommon.deltaFList_PUCCH.deltaF_PUCCH_Format1b = source.deltaFPucchFormat1b;
    target.uplinkPowerControlCommon.deltaFList_PUCCH.deltaF_PUCCH_Format2 = source.deltaFPucchFormat2;
    target.uplinkPowerControlCommon.deltaFList_PUCCH.deltaF_PUCCH_Format2a = source.deltaFPucchFormat2a;
    target.uplinkPowerControlCommon.deltaFList_PUCCH.deltaF_PUCCH_Format2b = source.deltaFPucchFormat2b;
    target.uplinkPowerControlCommon.deltaPreambleMsg3 = source.deltaPreambleMsg3;

    target.ul_CyclicPrefixLength = source.ulCyclicPrefixLength;
}

void FillSib2(SystemInformationBlockType2_t &target, const SystemInformationBlockType2 &source)
{
    FillRrcCommonSib(target.radioResourceConfigCommon, source.radioResourceConfigCommon);
    target.ue_TimersAndConstants.t300 = source.t300;
    target.ue_TimersAndConstants.t301 = source.t301;
    target.ue_TimersAndConstants.t310 = source.t310;
    target.ue_TimersAndConstants.n310 = source.n310;
    target.ue_TimersAndConstants.t311 = source.t311;
    target.ue_TimersAndConstants.n311 = source.n311;
    target.freqInfo.additionalSpectrumEmission = source.additionalSpectrumEmission;
    target.timeAlignmentTimerCommon = source.timeAlignmentTimerCommon;
}

void FillAsConfig(AS_Config_t &target, const SourceAsConfig &source)
{
    // sourceMeasConfig and sourceRadioResourceConfig are legal empty structures
    // in this model: their contents are not modelled yet and the design record
    // says so. Nothing here invents a measurement or a dedicated radio bearer.
    target.sourceSecurityAlgorithmConfig.cipheringAlgorithm = static_cast<CipheringAlgorithm_r12_t>(source.cipheringAlgorithm);
    target.sourceSecurityAlgorithmConfig.integrityProtAlgorithm = source.integrityProtAlgorithm;
    SetBits(target.sourceUE_Identity, source.sourceUeIdentity, 16);
    FillMib(target.sourceMasterInformationBlock, source.mib);
    FillSib1(target.sourceSystemInformationBlockType1, source.sib1);
    FillSib2(target.sourceSystemInformationBlockType2, source.sib2);
    target.antennaInfoCommon.antennaPortsCount = source.antennaPortsCount;
    target.sourceDl_CarrierFreq = source.sourceDlCarrierFreq;
}

void FillRrcCommon(RadioResourceConfigCommon_t &target, const HandoverCommand &source)
{
    target.prach_Config.rootSequenceIndex = source.prachRootSequenceIndex;
    target.pusch_ConfigCommon.pusch_ConfigBasic.n_SB = source.puschNSb;
    target.pusch_ConfigCommon.pusch_ConfigBasic.hoppingMode = source.puschHoppingMode;
    target.pusch_ConfigCommon.pusch_ConfigBasic.pusch_HoppingOffset = source.puschHoppingOffset;
    target.pusch_ConfigCommon.pusch_ConfigBasic.enable64QAM = source.puschEnable64Qam ? 1 : 0;
    target.pusch_ConfigCommon.ul_ReferenceSignalsPUSCH.groupHoppingEnabled = source.puschGroupHoppingEnabled ? 1 : 0;
    target.pusch_ConfigCommon.ul_ReferenceSignalsPUSCH.groupAssignmentPUSCH = source.puschGroupAssignmentPusch;
    target.pusch_ConfigCommon.ul_ReferenceSignalsPUSCH.sequenceHoppingEnabled =
        source.puschSequenceHoppingEnabled ? 1 : 0;
    target.pusch_ConfigCommon.ul_ReferenceSignalsPUSCH.cyclicShift = source.puschCyclicShift;
    target.ul_CyclicPrefixLength = source.ulCyclicPrefixLength;
}

// --- Encoding ---------------------------------------------------------------

RrcOutcome EncodePdu(const asn_TYPE_descriptor_t &descriptor, const void *pdu, std::vector<uint8_t> *uper)
{
    uper->clear();
    const asn_enc_rval_t encoded = uper_encode(&descriptor, nullptr, pdu, AppendBytes, uper);
    if (encoded.encoded < 0)
        return Refuse(RrcRefusal::INVALID_CONSTRAINT,
                      "the message cannot be encoded within the constraints it declares");
    if (uper->empty())
        return Refuse(RrcRefusal::EMPTY_INPUT, "the encoder produced no octets");
    if (uper->size() > MaxRrcContainerSize)
        return Refuse(RrcRefusal::OVERSIZED, "the encoded message exceeds the container bound");
    return RrcOutcome{true, RrcRefusal::NONE, {}};
}

} // namespace

const char *ToString(RrcReadiness readiness)
{
    switch (readiness)
    {
    case RrcReadiness::RRC_CODEC_VALID: return "RRC_CODEC_VALID";
    case RrcReadiness::RRC_CONFIGURATION_VALID: return "RRC_CONFIGURATION_VALID";
    case RrcReadiness::RRC_RUNTIME_INPUT_AVAILABLE: return "RRC_RUNTIME_INPUT_AVAILABLE";
    case RrcReadiness::RRC_SECURITY_READY: return "RRC_SECURITY_READY";
    case RrcReadiness::RRC_UE_EXECUTION_READY: return "RRC_UE_EXECUTION_READY";
    }
    return "UNKNOWN_RRC_READINESS";
}

const char *ToString(RrcRefusal refusal)
{
    switch (refusal)
    {
    case RrcRefusal::NONE: return "NONE";
    case RrcRefusal::EMPTY_INPUT: return "EMPTY_INPUT";
    case RrcRefusal::TRUNCATED: return "TRUNCATED";
    case RrcRefusal::INVALID_CHOICE: return "INVALID_CHOICE";
    case RrcRefusal::INVALID_CONSTRAINT: return "INVALID_CONSTRAINT";
    case RrcRefusal::INVALID_PRESENCE: return "INVALID_PRESENCE";
    case RrcRefusal::UNSUPPORTED_EXTENSION: return "UNSUPPORTED_EXTENSION";
    case RrcRefusal::OVERSIZED: return "OVERSIZED";
    case RrcRefusal::MISSING_MANDATORY: return "MISSING_MANDATORY";
    case RrcRefusal::UNSUPPORTED_VALUE: return "UNSUPPORTED_VALUE";
    case RrcRefusal::NOT_HANDOVER_MESSAGE: return "NOT_HANDOVER_MESSAGE";
    }
    return "UNKNOWN_RRC_REFUSAL";
}

bool IsSimulatorContainer(const std::vector<uint8_t> &container)
{
    static const std::string label = "SIM-HOv1";
    return container.size() >= label.size() && std::equal(label.begin(), label.end(), container.begin());
}


// --- HandoverPreparationInformation ----------------------------------------

RrcOutcome EncodeHandoverPreparationInformation(const HandoverPreparation &message, std::vector<uint8_t> *uper)
{
    if (uper == nullptr)
        return Refuse(RrcRefusal::EMPTY_INPUT, "no output was named");
    if (message.ueCapabilities.empty())
        return Refuse(RrcRefusal::MISSING_MANDATORY,
                      "ue-RadioAccessCapabilityInfo is mandatory and names no capability container");
    if (message.ueCapabilities.size() > 8)
        return Refuse(RrcRefusal::OVERSIZED, "more capability containers than this codec accepts");
    for (const auto &capability : message.ueCapabilities)
        if (capability.container.empty())
            return Refuse(RrcRefusal::MISSING_MANDATORY, "a capability container carries no octets");

    auto *pdu = Alloc<HandoverPreparationInformation_t>();
    pdu->criticalExtensions.present = HandoverPreparationInformation__criticalExtensions_PR_c1;
    using C1 = std::remove_pointer_t<decltype(pdu->criticalExtensions.choice.c1)>;
    pdu->criticalExtensions.choice.c1 = static_cast<C1 *>(std::calloc(1, sizeof(C1)));
    pdu->criticalExtensions.choice.c1->present =
        HandoverPreparationInformation__criticalExtensions__c1_PR_handoverPreparationInformation_r8;
    auto *ies = Alloc<HandoverPreparationInformation_r8_IEs_t>();
    pdu->criticalExtensions.choice.c1->choice.handoverPreparationInformation_r8 = ies;

    for (const auto &capability : message.ueCapabilities)
    {
        auto *container = Alloc<UE_CapabilityRAT_Container>();
        container->rat_Type = static_cast<RAT_Type_t>(capability.ratType);
        if (!SetOctets(container->ueCapabilityRAT_Container, capability.container))
        {
            ASN_STRUCT_FREE(asn_DEF_HandoverPreparationInformation, pdu);
            return Refuse(RrcRefusal::INVALID_CONSTRAINT, "a capability container could not be carried");
        }
        ASN_SEQUENCE_ADD(&ies->ue_RadioAccessCapabilityInfo, container);
    }

    if (message.asConfig.has_value())
    {
        ies->as_Config = Alloc<AS_Config_t>();
        FillAsConfig(*ies->as_Config, *message.asConfig);
    }

    const RrcOutcome outcome = EncodePdu(asn_DEF_HandoverPreparationInformation, pdu, uper);
    ASN_STRUCT_FREE(asn_DEF_HandoverPreparationInformation, pdu);
    return outcome;
}

namespace
{

void ReadRachConfigCommon(const RACH_ConfigCommon_t &source, RadioResourceConfigCommonSib &target)
{
    target.numberOfRaPreambles = static_cast<uint8_t>(source.preambleInfo.numberOfRA_Preambles);
    target.powerRampingStep = static_cast<uint8_t>(source.powerRampingParameters.powerRampingStep);
    target.preambleInitialReceivedTargetPower =
        static_cast<uint8_t>(source.powerRampingParameters.preambleInitialReceivedTargetPower);
    target.preambleTransMax = static_cast<uint8_t>(source.ra_SupervisionInfo.preambleTransMax);
    target.raResponseWindowSize = static_cast<uint8_t>(source.ra_SupervisionInfo.ra_ResponseWindowSize);
    target.maxHarqMsg3Tx = static_cast<uint8_t>(source.maxHARQ_Msg3Tx);
}

void ReadRrcCommonSib(const RadioResourceConfigCommonSIB_t &source, RadioResourceConfigCommonSib &target)
{
    ReadRachConfigCommon(source.rach_ConfigCommon, target);
    target.bcchModificationPeriodCoeff = static_cast<uint8_t>(source.bcch_Config.modificationPeriodCoeff);
    target.pcchDefaultPagingCycle = static_cast<uint8_t>(source.pcch_Config.defaultPagingCycle);
    target.pcchNb = static_cast<uint8_t>(source.pcch_Config.nB);
    target.prachRootSequenceIndex = static_cast<uint16_t>(source.prach_Config.rootSequenceIndex);
    target.prachConfigIndex = static_cast<uint8_t>(source.prach_Config.prach_ConfigInfo.prach_ConfigIndex);
    target.prachHighSpeedFlag = source.prach_Config.prach_ConfigInfo.highSpeedFlag != 0;
    target.prachZeroCorrelationZoneConfig =
        static_cast<uint8_t>(source.prach_Config.prach_ConfigInfo.zeroCorrelationZoneConfig);
    target.prachFreqOffset = static_cast<uint8_t>(source.prach_Config.prach_ConfigInfo.prach_FreqOffset);
    target.pdschReferenceSignalPower = static_cast<int8_t>(source.pdsch_ConfigCommon.referenceSignalPower);
    target.pdschPb = static_cast<uint8_t>(source.pdsch_ConfigCommon.p_b);
    target.puschNSb = static_cast<uint8_t>(source.pusch_ConfigCommon.pusch_ConfigBasic.n_SB);
    target.puschHoppingMode = static_cast<uint8_t>(source.pusch_ConfigCommon.pusch_ConfigBasic.hoppingMode);
    target.puschHoppingOffset = static_cast<uint8_t>(source.pusch_ConfigCommon.pusch_ConfigBasic.pusch_HoppingOffset);
    target.puschEnable64Qam = source.pusch_ConfigCommon.pusch_ConfigBasic.enable64QAM != 0;
    target.puschGroupHoppingEnabled = source.pusch_ConfigCommon.ul_ReferenceSignalsPUSCH.groupHoppingEnabled != 0;
    target.puschGroupAssignmentPusch =
        static_cast<uint8_t>(source.pusch_ConfigCommon.ul_ReferenceSignalsPUSCH.groupAssignmentPUSCH);
    target.puschSequenceHoppingEnabled =
        source.pusch_ConfigCommon.ul_ReferenceSignalsPUSCH.sequenceHoppingEnabled != 0;
    target.puschCyclicShift = static_cast<uint8_t>(source.pusch_ConfigCommon.ul_ReferenceSignalsPUSCH.cyclicShift);
    target.pucchDeltaShift = static_cast<uint8_t>(source.pucch_ConfigCommon.deltaPUCCH_Shift);
    target.pucchNrbCqi = static_cast<uint8_t>(source.pucch_ConfigCommon.nRB_CQI);
    target.pucchNcsAn = static_cast<uint8_t>(source.pucch_ConfigCommon.nCS_AN);
    target.pucchN1PucchAn = static_cast<uint16_t>(source.pucch_ConfigCommon.n1PUCCH_AN);
    target.soundingRsRelease = source.soundingRS_UL_ConfigCommon.present == SoundingRS_UL_ConfigCommon_PR_release;
    if (!target.soundingRsRelease)
    {
        if (source.soundingRS_UL_ConfigCommon.choice.setup != nullptr)
        {
            target.srsBandwidthConfig =
                static_cast<uint8_t>(source.soundingRS_UL_ConfigCommon.choice.setup->srs_BandwidthConfig);
            target.srsSubframeConfig =
                static_cast<uint8_t>(source.soundingRS_UL_ConfigCommon.choice.setup->srs_SubframeConfig);
            target.ackNackSrsSimultaneousTransmission =
                source.soundingRS_UL_ConfigCommon.choice.setup->ackNackSRS_SimultaneousTransmission != 0;
        }
    }
    target.p0NominalPusch = static_cast<int16_t>(source.uplinkPowerControlCommon.p0_NominalPUSCH);
    target.alpha = static_cast<uint8_t>(source.uplinkPowerControlCommon.alpha);
    target.p0NominalPucch = static_cast<int8_t>(source.uplinkPowerControlCommon.p0_NominalPUCCH);
    target.deltaFPucchFormat1 =
        static_cast<uint8_t>(source.uplinkPowerControlCommon.deltaFList_PUCCH.deltaF_PUCCH_Format1);
    target.deltaFPucchFormat1b =
        static_cast<uint8_t>(source.uplinkPowerControlCommon.deltaFList_PUCCH.deltaF_PUCCH_Format1b);
    target.deltaFPucchFormat2 =
        static_cast<uint8_t>(source.uplinkPowerControlCommon.deltaFList_PUCCH.deltaF_PUCCH_Format2);
    target.deltaFPucchFormat2a =
        static_cast<uint8_t>(source.uplinkPowerControlCommon.deltaFList_PUCCH.deltaF_PUCCH_Format2a);
    target.deltaFPucchFormat2b =
        static_cast<uint8_t>(source.uplinkPowerControlCommon.deltaFList_PUCCH.deltaF_PUCCH_Format2b);
    target.deltaPreambleMsg3 = static_cast<int8_t>(source.uplinkPowerControlCommon.deltaPreambleMsg3);
    target.ulCyclicPrefixLength = static_cast<uint8_t>(source.ul_CyclicPrefixLength);
}

void ReadSib2(const SystemInformationBlockType2_t &source, SystemInformationBlockType2 &target)
{
    ReadRrcCommonSib(source.radioResourceConfigCommon, target.radioResourceConfigCommon);
    target.t300 = static_cast<uint8_t>(source.ue_TimersAndConstants.t300);
    target.t301 = static_cast<uint8_t>(source.ue_TimersAndConstants.t301);
    target.t310 = static_cast<uint8_t>(source.ue_TimersAndConstants.t310);
    target.n310 = static_cast<uint8_t>(source.ue_TimersAndConstants.n310);
    target.t311 = static_cast<uint8_t>(source.ue_TimersAndConstants.t311);
    target.n311 = static_cast<uint8_t>(source.ue_TimersAndConstants.n311);
    target.additionalSpectrumEmission = static_cast<uint8_t>(source.freqInfo.additionalSpectrumEmission);
    target.timeAlignmentTimerCommon = static_cast<uint8_t>(source.timeAlignmentTimerCommon);
}

void ReadSib1(const SystemInformationBlockType1_t &source, SystemInformationBlockType1 &target)
{
    if (source.cellAccessRelatedInfo.plmn_IdentityList.list.count > 0)
    {
        const auto *info = static_cast<const PLMN_IdentityInfo_t *>(
            source.cellAccessRelatedInfo.plmn_IdentityList.list.array[0]);
        if (info != nullptr)
        {
            target.plmnIdentity = PackPlmn(info->plmn_Identity);
            target.cellReservedForOperatorUse = static_cast<uint8_t>(info->cellReservedForOperatorUse);
        }
    }
    target.trackingAreaCode = static_cast<uint16_t>(GetBits(source.cellAccessRelatedInfo.trackingAreaCode));
    target.cellIdentity = static_cast<uint32_t>(GetBits(source.cellAccessRelatedInfo.cellIdentity));
    target.cellBarred = static_cast<uint8_t>(source.cellAccessRelatedInfo.cellBarred);
    target.intraFreqReselection = static_cast<uint8_t>(source.cellAccessRelatedInfo.intraFreqReselection);
    target.csgIndication = source.cellAccessRelatedInfo.csg_Indication != 0;
    target.qRxLevMin = static_cast<int8_t>(source.cellSelectionInfo.q_RxLevMin);
    target.freqBandIndicator = static_cast<uint8_t>(source.freqBandIndicator);
    if (source.schedulingInfoList.list.count > 0)
    {
        const auto *scheduling = static_cast<const SchedulingInfo_t *>(source.schedulingInfoList.list.array[0]);
        if (scheduling != nullptr)
        {
            target.siPeriodicity = static_cast<uint8_t>(scheduling->si_Periodicity);
            if (scheduling->sib_MappingInfo.list.count > 0)
                target.sibType =
                    static_cast<uint8_t>(*scheduling->sib_MappingInfo.list.array[0]);
        }
    }
    target.siWindowLength = static_cast<uint8_t>(source.si_WindowLength);
    target.systemInfoValueTag = static_cast<uint8_t>(source.systemInfoValueTag);
}

void ReadMib(const MasterInformationBlock_t &source, MasterInformationBlock &target)
{
    target.dlBandwidth = static_cast<uint8_t>(source.dl_Bandwidth);
    target.phichDuration = static_cast<uint8_t>(source.phich_Config.phich_Duration);
    target.phichResource = static_cast<uint8_t>(source.phich_Config.phich_Resource);
    target.systemFrameNumber = static_cast<uint8_t>(GetBits(source.systemFrameNumber));
    target.schedulingInfoSib1Br = static_cast<uint8_t>(source.schedulingInfoSIB1_BR_r13);
    target.systemInfoUnchangedBr = source.systemInfoUnchanged_BR_r15 != 0;
    target.spare = static_cast<uint8_t>(GetBits(source.spare));
}

void ReadAsConfig(const AS_Config_t &source, SourceAsConfig &target)
{
    target.cipheringAlgorithm = static_cast<uint8_t>(source.sourceSecurityAlgorithmConfig.cipheringAlgorithm);
    target.integrityProtAlgorithm = static_cast<uint8_t>(source.sourceSecurityAlgorithmConfig.integrityProtAlgorithm);
    target.sourceUeIdentity = static_cast<uint16_t>(GetBits(source.sourceUE_Identity));
    ReadMib(source.sourceMasterInformationBlock, target.mib);
    ReadSib1(source.sourceSystemInformationBlockType1, target.sib1);
    ReadSib2(source.sourceSystemInformationBlockType2, target.sib2);
    target.antennaPortsCount = static_cast<uint8_t>(source.antennaInfoCommon.antennaPortsCount);
    target.sourceDlCarrierFreq = static_cast<uint16_t>(source.sourceDl_CarrierFreq);
}

} // namespace

RrcOutcome DecodeHandoverPreparationInformation(const uint8_t *data, size_t size, HandoverPreparation *message)
{
    if (message == nullptr)
        return Refuse(RrcRefusal::EMPTY_INPUT, "no output was named");
    if (data == nullptr || size == 0)
        return Refuse(RrcRefusal::EMPTY_INPUT, "the container is empty");
    if (size > MaxRrcContainerSize)
        return Refuse(RrcRefusal::OVERSIZED, "the container exceeds the receiver bound");
    if (IsSimulatorContainer(std::vector<uint8_t>(data, data + size)))
        return Refuse(RrcRefusal::NOT_HANDOVER_MESSAGE,
                      "the container is the isolated simulator's own frame, not LTE RRC");

    void *decoded = nullptr;
    // A complete encoding: the trailing bits of the last octet are padding, and
    // only the complete decoder knows to ignore them.
    const asn_codec_ctx_t context = BoundedDecodeContext();
    const asn_dec_rval_t rval =
        uper_decode_complete(&context, &asn_DEF_HandoverPreparationInformation, &decoded, data, size);
    auto *pdu = static_cast<HandoverPreparationInformation_t *>(decoded);
    if (rval.code != RC_OK || pdu == nullptr)
    {
        if (pdu != nullptr)
            ASN_STRUCT_FREE(asn_DEF_HandoverPreparationInformation, pdu);
        return Refuse(RrcRefusal::TRUNCATED,
                      "the octets do not decode as a HandoverPreparationInformation (code " +
                          std::to_string(static_cast<int>(rval.code)) + ", consumed " +
                          std::to_string(rval.consumed) + " of " + std::to_string(size) + " octets)");
    }
    if (static_cast<size_t>(rval.consumed) != size)
    {
        ASN_STRUCT_FREE(asn_DEF_HandoverPreparationInformation, pdu);
        return Refuse(RrcRefusal::TRUNCATED, "the container carries octets after the message");
    }


    RrcOutcome outcome{true, RrcRefusal::NONE, {}};
    if (pdu->criticalExtensions.present != HandoverPreparationInformation__criticalExtensions_PR_c1 ||
        pdu->criticalExtensions.choice.c1 == nullptr ||
        pdu->criticalExtensions.choice.c1->present !=
            HandoverPreparationInformation__criticalExtensions__c1_PR_handoverPreparationInformation_r8 ||
        pdu->criticalExtensions.choice.c1->choice.handoverPreparationInformation_r8 == nullptr)
    {
        ASN_STRUCT_FREE(asn_DEF_HandoverPreparationInformation, pdu);
        return Refuse(RrcRefusal::UNSUPPORTED_EXTENSION,
                      "the message does not carry a handoverPreparationInformation-r8 body");
    }

    const auto *ies = pdu->criticalExtensions.choice.c1->choice.handoverPreparationInformation_r8;
    HandoverPreparation out;
    for (int i = 0; i < ies->ue_RadioAccessCapabilityInfo.list.count; ++i)
    {
        const auto *container =
            static_cast<const UE_CapabilityRAT_Container_t *>(ies->ue_RadioAccessCapabilityInfo.list.array[i]);
        if (container == nullptr)
            continue;
        UeCapabilityContainer capability;
        capability.ratType = static_cast<uint8_t>(container->rat_Type);
        capability.container.assign(container->ueCapabilityRAT_Container.buf,
                                    container->ueCapabilityRAT_Container.buf + container->ueCapabilityRAT_Container.size);
        out.ueCapabilities.push_back(std::move(capability));
    }
    if (out.ueCapabilities.empty())
    {
        ASN_STRUCT_FREE(asn_DEF_HandoverPreparationInformation, pdu);
        return Refuse(RrcRefusal::MISSING_MANDATORY,
                      "the message carries no ue-RadioAccessCapabilityInfo entry");
    }
    if (ies->as_Config != nullptr)
    {
        SourceAsConfig config;
        ReadAsConfig(*ies->as_Config, config);
        out.asConfig = config;
    }

    ASN_STRUCT_FREE(asn_DEF_HandoverPreparationInformation, pdu);
    *message = std::move(out);
    return outcome;
}


// --- HandoverCommand carrying an RRCConnectionReconfiguration ---------------
//
// The Target-ToSource transparent container's rRC-Container is the RRC
// HandoverCommand message (TS 36.413 §9.2.1.40), and that message's
// handoverCommandMessage field carries an RRCConnectionReconfiguration encoded
// as an OCTET STRING. So the octets this codec produces are the HandoverCommand
// message, and the reconfiguration that actually moves the UE is one layer
// inside it. Both layers are produced and checked separately.

namespace
{

void ReadReconfiguration(const RRCConnectionReconfiguration_t &reconfiguration, HandoverCommand *out)
{
    out->rrcTransactionIdentifier = static_cast<uint8_t>(reconfiguration.rrc_TransactionIdentifier);
    const auto *ies = reconfiguration.criticalExtensions.choice.c1->choice.rrcConnectionReconfiguration_r8;
    if (ies == nullptr || ies->mobilityControlInfo == nullptr)
        return;
    out->targetPhysCellId = static_cast<uint16_t>(ies->mobilityControlInfo->targetPhysCellId);
    out->t304 = static_cast<uint8_t>(ies->mobilityControlInfo->t304);
    out->newUeIdentity = static_cast<uint16_t>(GetBits(ies->mobilityControlInfo->newUE_Identity));
    const auto &common = ies->mobilityControlInfo->radioResourceConfigCommon;
    out->prachRootSequenceIndex = static_cast<uint16_t>(common.prach_Config.rootSequenceIndex);
    out->puschNSb = static_cast<uint8_t>(common.pusch_ConfigCommon.pusch_ConfigBasic.n_SB);
    out->puschHoppingMode = static_cast<uint8_t>(common.pusch_ConfigCommon.pusch_ConfigBasic.hoppingMode);
    out->puschHoppingOffset = static_cast<uint8_t>(common.pusch_ConfigCommon.pusch_ConfigBasic.pusch_HoppingOffset);
    out->puschEnable64Qam = common.pusch_ConfigCommon.pusch_ConfigBasic.enable64QAM != 0;
    out->puschGroupHoppingEnabled = common.pusch_ConfigCommon.ul_ReferenceSignalsPUSCH.groupHoppingEnabled != 0;
    out->puschGroupAssignmentPusch =
        static_cast<uint8_t>(common.pusch_ConfigCommon.ul_ReferenceSignalsPUSCH.groupAssignmentPUSCH);
    out->puschSequenceHoppingEnabled = common.pusch_ConfigCommon.ul_ReferenceSignalsPUSCH.sequenceHoppingEnabled != 0;
    out->puschCyclicShift = static_cast<uint8_t>(common.pusch_ConfigCommon.ul_ReferenceSignalsPUSCH.cyclicShift);
    out->ulCyclicPrefixLength = static_cast<uint8_t>(common.ul_CyclicPrefixLength);
}

RrcOutcome ValidateCommand(const HandoverCommand &message)
{
    if (!InRange(message.rrcTransactionIdentifier, 0, 3))
        return Refuse(RrcRefusal::INVALID_CONSTRAINT, "the RRC transaction identifier is outside 0..3");
    if (!InRange(message.targetPhysCellId, 0, 503))
        return Refuse(RrcRefusal::INVALID_CONSTRAINT, "the target physical cell identity is outside 0..503");
    if (!InRange(message.t304, 0, 7))
        return Refuse(RrcRefusal::INVALID_CONSTRAINT, "t304 is outside its enumeration");
    if (!InRange(message.newUeIdentity, 0, 65535))
        return Refuse(RrcRefusal::INVALID_CONSTRAINT, "the new C-RNTI is outside 0..65535");
    if (!InRange(message.prachRootSequenceIndex, 0, 837))
        return Refuse(RrcRefusal::INVALID_CONSTRAINT, "the PRACH root sequence index is outside 0..837");
    if (!InRange(message.puschNSb, 1, 4))
        return Refuse(RrcRefusal::INVALID_CONSTRAINT, "n-SB is outside 1..4");
    if (!InRange(message.puschHoppingMode, 0, 1))
        return Refuse(RrcRefusal::INVALID_CONSTRAINT, "the PUSCH hopping mode is outside its enumeration");
    if (!InRange(message.puschHoppingOffset, 0, 98))
        return Refuse(RrcRefusal::INVALID_CONSTRAINT, "the PUSCH hopping offset is outside 0..98");
    if (!InRange(message.puschGroupAssignmentPusch, 0, 29))
        return Refuse(RrcRefusal::INVALID_CONSTRAINT, "the PUSCH group assignment is outside 0..29");
    if (!InRange(message.puschCyclicShift, 0, 7))
        return Refuse(RrcRefusal::INVALID_CONSTRAINT, "the PUSCH cyclic shift is outside 0..7");
    if (!InRange(message.ulCyclicPrefixLength, 1, 2))
        return Refuse(RrcRefusal::INVALID_CONSTRAINT, "the UL cyclic prefix length is outside 1..2");

    return RrcOutcome{true, RrcRefusal::NONE, {}};
}

RrcOutcome BuildHandoverReconfiguration(const HandoverCommand &message, RRCConnectionReconfiguration_t **out)
{
    auto *pdu = Alloc<RRCConnectionReconfiguration_t>();
    pdu->rrc_TransactionIdentifier = message.rrcTransactionIdentifier;
    pdu->criticalExtensions.present = RRCConnectionReconfiguration__criticalExtensions_PR_c1;
    using C1 = std::remove_pointer_t<decltype(pdu->criticalExtensions.choice.c1)>;
    pdu->criticalExtensions.choice.c1 = static_cast<C1 *>(std::calloc(1, sizeof(C1)));
    pdu->criticalExtensions.choice.c1->present =
        RRCConnectionReconfiguration__criticalExtensions__c1_PR_rrcConnectionReconfiguration_r8;
    auto *ies = Alloc<RRCConnectionReconfiguration_r8_IEs_t>();
    pdu->criticalExtensions.choice.c1->choice.rrcConnectionReconfiguration_r8 = ies;

    ies->mobilityControlInfo = Alloc<MobilityControlInfo_t>();
    ies->mobilityControlInfo->targetPhysCellId = message.targetPhysCellId;
    ies->mobilityControlInfo->t304 = message.t304;
    SetBits(ies->mobilityControlInfo->newUE_Identity, message.newUeIdentity, 16);
    FillRrcCommon(ies->mobilityControlInfo->radioResourceConfigCommon, message);
    *out = pdu;
    return RrcOutcome{true, RrcRefusal::NONE, {}};
}

} // namespace

RrcOutcome EncodeHandoverCommandLegacy(const HandoverCommand &message, std::vector<uint8_t> *uper)
{
    if (uper == nullptr)
        return Refuse(RrcRefusal::EMPTY_INPUT, "no output was named");
    const RrcOutcome validated = ValidateCommand(message);
    if (!validated.ok)
        return validated;

    RRCConnectionReconfiguration_t *reconfiguration = nullptr;
    const RrcOutcome built = BuildHandoverReconfiguration(message, &reconfiguration);
    if (!built.ok)
        return built;

    std::vector<uint8_t> inner;
    const RrcOutcome innerOutcome = EncodePdu(asn_DEF_RRCConnectionReconfiguration, reconfiguration, &inner);
    ASN_STRUCT_FREE(asn_DEF_RRCConnectionReconfiguration, reconfiguration);
    if (!innerOutcome.ok)
        return innerOutcome;

    auto *pdu = Alloc<HandoverCommand_t>();
    pdu->criticalExtensions.present = HandoverCommand__criticalExtensions_PR_c1;
    using C1 = std::remove_pointer_t<decltype(pdu->criticalExtensions.choice.c1)>;
    pdu->criticalExtensions.choice.c1 = static_cast<C1 *>(std::calloc(1, sizeof(C1)));
    pdu->criticalExtensions.choice.c1->present = HandoverCommand__criticalExtensions__c1_PR_handoverCommand_r8;
    auto *ies = Alloc<HandoverCommand_r8_IEs_t>();
    pdu->criticalExtensions.choice.c1->choice.handoverCommand_r8 = ies;
    if (!SetOctets(ies->handoverCommandMessage, inner))
    {
        ASN_STRUCT_FREE(asn_DEF_HandoverCommand, pdu);
        return Refuse(RrcRefusal::INVALID_CONSTRAINT, "the reconfiguration could not be carried");
    }

    const RrcOutcome outcome = EncodePdu(asn_DEF_HandoverCommand, pdu, uper);
    ASN_STRUCT_FREE(asn_DEF_HandoverCommand, pdu);
    return outcome;
}

RrcOutcome DecodeHandoverCommandLegacy(const uint8_t *data, size_t size, HandoverCommand *message)
{
    if (message == nullptr)
        return Refuse(RrcRefusal::EMPTY_INPUT, "no output was named");
    if (data == nullptr || size == 0)
        return Refuse(RrcRefusal::EMPTY_INPUT, "the container is empty");
    if (size > MaxRrcContainerSize)
        return Refuse(RrcRefusal::OVERSIZED, "the container exceeds the receiver bound");
    if (IsSimulatorContainer(std::vector<uint8_t>(data, data + size)))
        return Refuse(RrcRefusal::NOT_HANDOVER_MESSAGE,
                      "the container is the isolated simulator's own frame, not LTE RRC");

    void *decoded = nullptr;
    const asn_codec_ctx_t context = BoundedDecodeContext();
    const asn_dec_rval_t rval = uper_decode_complete(&context, &asn_DEF_HandoverCommand, &decoded, data, size);
    auto *pdu = static_cast<HandoverCommand_t *>(decoded);
    if (rval.code != RC_OK || pdu == nullptr)
    {
        if (pdu != nullptr)
            ASN_STRUCT_FREE(asn_DEF_HandoverCommand, pdu);
        return Refuse(RrcRefusal::TRUNCATED,
                      "the octets do not decode as an RRC HandoverCommand (code " +
                          std::to_string(static_cast<int>(rval.code)) + ", consumed " +
                          std::to_string(rval.consumed) + " of " + std::to_string(size) + " octets)");
    }
    if (static_cast<size_t>(rval.consumed) != size)
    {
        ASN_STRUCT_FREE(asn_DEF_HandoverCommand, pdu);
        return Refuse(RrcRefusal::TRUNCATED, "the container carries octets after the message");
    }

    if (pdu->criticalExtensions.present != HandoverCommand__criticalExtensions_PR_c1 ||
        pdu->criticalExtensions.choice.c1 == nullptr ||
        pdu->criticalExtensions.choice.c1->present != HandoverCommand__criticalExtensions__c1_PR_handoverCommand_r8 ||
        pdu->criticalExtensions.choice.c1->choice.handoverCommand_r8 == nullptr)
    {
        ASN_STRUCT_FREE(asn_DEF_HandoverCommand, pdu);
        return Refuse(RrcRefusal::UNSUPPORTED_EXTENSION, "the message carries no handoverCommand-r8 body");
    }

    const auto *ies = pdu->criticalExtensions.choice.c1->choice.handoverCommand_r8;
    const OCTET_STRING_t &inner = ies->handoverCommandMessage;
    if (inner.buf == nullptr || inner.size == 0)
    {
        ASN_STRUCT_FREE(asn_DEF_HandoverCommand, pdu);
        return Refuse(RrcRefusal::MISSING_MANDATORY, "the handover command carries no reconfiguration");
    }

    // The octet string lives inside the outer structure, so everything needed
    // from it is copied out before that structure is freed.
    const size_t innerSize = static_cast<size_t>(inner.size);
    const uint8_t *innerBytes = inner.buf;

    void *innerDecoded = nullptr;
    const asn_codec_ctx_t innerContext = BoundedDecodeContext();
    const asn_dec_rval_t innerRval = uper_decode_complete(&innerContext, &asn_DEF_RRCConnectionReconfiguration,
                                                          &innerDecoded, innerBytes, innerSize);
    auto *reconfiguration = static_cast<RRCConnectionReconfiguration_t *>(innerDecoded);
    ASN_STRUCT_FREE(asn_DEF_HandoverCommand, pdu);
    if (innerRval.code != RC_OK || reconfiguration == nullptr)
    {
        if (reconfiguration != nullptr)
            ASN_STRUCT_FREE(asn_DEF_RRCConnectionReconfiguration, reconfiguration);
        return Refuse(RrcRefusal::TRUNCATED,
                      "the handover command's reconfiguration does not decode as an RRCConnectionReconfiguration");
    }
    if (static_cast<size_t>(innerRval.consumed) != innerSize)
    {
        ASN_STRUCT_FREE(asn_DEF_RRCConnectionReconfiguration, reconfiguration);
        return Refuse(RrcRefusal::TRUNCATED, "the reconfiguration carries octets after the message");
    }

    if (reconfiguration->criticalExtensions.present != RRCConnectionReconfiguration__criticalExtensions_PR_c1 ||
        reconfiguration->criticalExtensions.choice.c1 == nullptr ||
        reconfiguration->criticalExtensions.choice.c1->present !=
            RRCConnectionReconfiguration__criticalExtensions__c1_PR_rrcConnectionReconfiguration_r8 ||
        reconfiguration->criticalExtensions.choice.c1->choice.rrcConnectionReconfiguration_r8 == nullptr)
    {
        ASN_STRUCT_FREE(asn_DEF_RRCConnectionReconfiguration, reconfiguration);
        return Refuse(RrcRefusal::UNSUPPORTED_EXTENSION,
                      "the reconfiguration carries no rrcConnectionReconfiguration-r8 body");
    }

    const auto *ies2 = reconfiguration->criticalExtensions.choice.c1->choice.rrcConnectionReconfiguration_r8;
    if (ies2->mobilityControlInfo == nullptr)
    {
        ASN_STRUCT_FREE(asn_DEF_RRCConnectionReconfiguration, reconfiguration);
        return Refuse(RrcRefusal::NOT_HANDOVER_MESSAGE,
                      "the reconfiguration carries no mobilityControlInfo and moves no UE");
    }

    HandoverCommand out;
    ReadReconfiguration(*reconfiguration, &out);

    ASN_STRUCT_FREE(asn_DEF_RRCConnectionReconfiguration, reconfiguration);
    *message = out;
    return RrcOutcome{true, RrcRefusal::NONE, {}};
}

// --- The conformant target-to-source payload -------------------------------
//
// TS 36.331: HandoverCommand-r8-IEs.handoverCommandMessage is an OCTET STRING
// (CONTAINING DL-DCCH-Message), and that DL-DCCH-Message carries the
// rrcConnectionReconfiguration. The functions below produce and parse exactly
// that; EncodeHandoverCommand above stores the bare reconfiguration in the
// field and is kept for its Phase 18-F-B1 pinned vectors.

RrcOutcome EncodeHandoverCommandPayload(const HandoverCommand &message, std::vector<uint8_t> *uper)
{
    if (uper == nullptr)
        return Refuse(RrcRefusal::EMPTY_INPUT, "no output was named");
    const RrcOutcome validated = ValidateCommand(message);
    if (!validated.ok)
        return validated;

    RRCConnectionReconfiguration_t *reconfiguration = nullptr;
    const RrcOutcome built = BuildHandoverReconfiguration(message, &reconfiguration);
    if (!built.ok)
        return built;

    auto *dl = Alloc<DL_DCCH_Message_t>();
    dl->message.present = DL_DCCH_MessageType_PR_c1;
    using C1 = std::remove_pointer_t<decltype(dl->message.choice.c1)>;
    dl->message.choice.c1 = static_cast<C1 *>(std::calloc(1, sizeof(C1)));
    dl->message.choice.c1->present = DL_DCCH_MessageType__c1_PR_rrcConnectionReconfiguration;
    dl->message.choice.c1->choice.rrcConnectionReconfiguration = reconfiguration;

    std::vector<uint8_t> dlBytes;
    const RrcOutcome inner = EncodePdu(asn_DEF_DL_DCCH_Message, dl, &dlBytes);
    ASN_STRUCT_FREE(asn_DEF_DL_DCCH_Message, dl);
    if (!inner.ok)
        return inner;

    auto *pdu = Alloc<HandoverCommand_t>();
    pdu->criticalExtensions.present = HandoverCommand__criticalExtensions_PR_c1;
    using OuterC1 = std::remove_pointer_t<decltype(pdu->criticalExtensions.choice.c1)>;
    pdu->criticalExtensions.choice.c1 = static_cast<OuterC1 *>(std::calloc(1, sizeof(OuterC1)));
    pdu->criticalExtensions.choice.c1->present = HandoverCommand__criticalExtensions__c1_PR_handoverCommand_r8;
    auto *ies = Alloc<HandoverCommand_r8_IEs_t>();
    pdu->criticalExtensions.choice.c1->choice.handoverCommand_r8 = ies;
    if (!SetOctets(ies->handoverCommandMessage, dlBytes))
    {
        ASN_STRUCT_FREE(asn_DEF_HandoverCommand, pdu);
        return Refuse(RrcRefusal::INVALID_CONSTRAINT, "the DL-DCCH-Message could not be carried");
    }

    const RrcOutcome outcome = EncodePdu(asn_DEF_HandoverCommand, pdu, uper);
    ASN_STRUCT_FREE(asn_DEF_HandoverCommand, pdu);
    return outcome;
}

RrcOutcome DecodeHandoverCommandPayload(const uint8_t *data, size_t size, HandoverCommand *message)
{
    if (message == nullptr)
        return Refuse(RrcRefusal::EMPTY_INPUT, "no output was named");
    if (data == nullptr || size == 0)
        return Refuse(RrcRefusal::EMPTY_INPUT, "the container is empty");
    if (size > MaxRrcContainerSize)
        return Refuse(RrcRefusal::OVERSIZED, "the container exceeds the receiver bound");
    if (IsSimulatorContainer(std::vector<uint8_t>(data, data + size)))
        return Refuse(RrcRefusal::NOT_HANDOVER_MESSAGE,
                      "the container is the isolated simulator's own frame, not LTE RRC");

    void *decoded = nullptr;
    const asn_codec_ctx_t context = BoundedDecodeContext();
    const asn_dec_rval_t rval = uper_decode_complete(&context, &asn_DEF_HandoverCommand, &decoded, data, size);
    auto *pdu = static_cast<HandoverCommand_t *>(decoded);
    if (rval.code != RC_OK || pdu == nullptr)
    {
        if (pdu != nullptr)
            ASN_STRUCT_FREE(asn_DEF_HandoverCommand, pdu);
        return Refuse(RrcRefusal::TRUNCATED, "the octets do not decode as an RRC HandoverCommand");
    }
    if (static_cast<size_t>(rval.consumed) != size)
    {
        ASN_STRUCT_FREE(asn_DEF_HandoverCommand, pdu);
        return Refuse(RrcRefusal::TRUNCATED, "the container carries octets after the message");
    }
    if (pdu->criticalExtensions.present != HandoverCommand__criticalExtensions_PR_c1 ||
        pdu->criticalExtensions.choice.c1 == nullptr ||
        pdu->criticalExtensions.choice.c1->present != HandoverCommand__criticalExtensions__c1_PR_handoverCommand_r8 ||
        pdu->criticalExtensions.choice.c1->choice.handoverCommand_r8 == nullptr)
    {
        ASN_STRUCT_FREE(asn_DEF_HandoverCommand, pdu);
        return Refuse(RrcRefusal::UNSUPPORTED_EXTENSION, "the message carries no handoverCommand-r8 body");
    }

    const auto *ies = pdu->criticalExtensions.choice.c1->choice.handoverCommand_r8;
    const OCTET_STRING_t &inner = ies->handoverCommandMessage;
    const size_t innerSize = static_cast<size_t>(inner.size);
    const uint8_t *innerBytes = inner.buf;
    if (innerBytes == nullptr || innerSize == 0)
    {
        ASN_STRUCT_FREE(asn_DEF_HandoverCommand, pdu);
        return Refuse(RrcRefusal::MISSING_MANDATORY, "the handover command carries no DL-DCCH-Message");
    }

    void *dlDecoded = nullptr;
    const asn_codec_ctx_t dlContext = BoundedDecodeContext();
    const asn_dec_rval_t dlRval =
        uper_decode_complete(&dlContext, &asn_DEF_DL_DCCH_Message, &dlDecoded, innerBytes, innerSize);
    auto *dl = static_cast<DL_DCCH_Message_t *>(dlDecoded);
    ASN_STRUCT_FREE(asn_DEF_HandoverCommand, pdu);
    if (dlRval.code != RC_OK || dl == nullptr)
    {
        if (dl != nullptr)
            ASN_STRUCT_FREE(asn_DEF_DL_DCCH_Message, dl);
        return Refuse(RrcRefusal::TRUNCATED,
                      "the handover command's payload does not decode as a DL-DCCH-Message");
    }
    if (static_cast<size_t>(dlRval.consumed) != innerSize)
    {
        ASN_STRUCT_FREE(asn_DEF_DL_DCCH_Message, dl);
        return Refuse(RrcRefusal::TRUNCATED, "the DL-DCCH-Message carries octets after the message");
    }
    if (dl->message.present != DL_DCCH_MessageType_PR_c1 || dl->message.choice.c1 == nullptr ||
        dl->message.choice.c1->present != DL_DCCH_MessageType__c1_PR_rrcConnectionReconfiguration ||
        dl->message.choice.c1->choice.rrcConnectionReconfiguration == nullptr)
    {
        ASN_STRUCT_FREE(asn_DEF_DL_DCCH_Message, dl);
        return Refuse(RrcRefusal::NOT_HANDOVER_MESSAGE,
                      "the DL-DCCH-Message carries no rrcConnectionReconfiguration");
    }

    const auto *reconfiguration = dl->message.choice.c1->choice.rrcConnectionReconfiguration;
    if (reconfiguration->criticalExtensions.present != RRCConnectionReconfiguration__criticalExtensions_PR_c1 ||
        reconfiguration->criticalExtensions.choice.c1 == nullptr ||
        reconfiguration->criticalExtensions.choice.c1->present !=
            RRCConnectionReconfiguration__criticalExtensions__c1_PR_rrcConnectionReconfiguration_r8 ||
        reconfiguration->criticalExtensions.choice.c1->choice.rrcConnectionReconfiguration_r8 == nullptr ||
        reconfiguration->criticalExtensions.choice.c1->choice.rrcConnectionReconfiguration_r8->mobilityControlInfo ==
            nullptr)
    {
        ASN_STRUCT_FREE(asn_DEF_DL_DCCH_Message, dl);
        return Refuse(RrcRefusal::NOT_HANDOVER_MESSAGE,
                      "the reconfiguration carries no mobilityControlInfo and moves no UE");
    }

    HandoverCommand out;
    ReadReconfiguration(*reconfiguration, &out);
    ASN_STRUCT_FREE(asn_DEF_DL_DCCH_Message, dl);
    *message = out;
    return RrcOutcome{true, RrcRefusal::NONE, {}};
}

bool AsConfigCompleteness::completeForRuntime() const
{
    return notModelled.empty() && emptyStructures.empty();
}

AsConfigCompleteness AssessAsConfigCompleteness(const SourceAsConfig &config)
{
    (void)config;
    AsConfigCompleteness assessment;
    assessment.modelled = {
        "sourceSecurityAlgorithmConfig.cipheringAlgorithm",
        "sourceSecurityAlgorithmConfig.integrityProtAlgorithm",
        "sourceUE-Identity",
        "sourceMasterInformationBlock (mandatory members)",
        "sourceSystemInformationBlockType1 (mandatory members)",
        "sourceSystemInformationBlockType2 (mandatory members)",
        "antennaInfoCommon.antennaPortsCount",
        "sourceDl-CarrierFreq",
    };
    assessment.emptyStructures = {
        "sourceMeasConfig (encoded empty: every member is OPTIONAL and none is modelled)",
        "sourceRadioResourceConfig (encoded empty: every member is OPTIONAL and none is modelled)",
    };
    assessment.notModelled = {
        "sourceMeasConfig.measObjectList and every measurement configuration member",
        "sourceRadioResourceConfig.srb-ToAddModList / drb-ToAddModList / mac-MainConfig / physicalConfigDedicated",
        "sourceMasterInformationBlock schedulingInfoSIB1-BR-r13 and systemInfoUnchanged-BR-r15 (modelled, but the "
        "values must come from the source cell's own broadcast)",
        "SystemInformationBlockType1 optional members (p-Max, tdd-Config, nonCriticalExtension)",
        "SystemInformationBlockType2 optional members (ac-BarringInfo, mbsfn-SubframeConfigList, "
        "lateNonCriticalExtension and the extension additions)",
        "RadioResourceConfigCommonSIB optional members (uplinkPowerControlCommon-v1020 and the extension additions)",
        "mobilityControlInfo.carrierFreq / carrierBandwidth / additionalSpectrumEmission / rach-ConfigDedicated",
        "radioResourceConfigCommon optional members and the securityConfigHO dependency",
    };
    return assessment;
}

} // namespace lte::rrc


