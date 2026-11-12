//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

// Phase 18-F-B1: LTE RRC (TS 36.331) handover messages, encoded with UPER.
//
// The two containers an S1 handover carries are opaque to S1AP and to the MME.
// Their contents are LTE RRC, encoded with Unaligned Packed Encoding Rules.
// This module is that codec: it builds and parses the two messages a handover
// needs, and it keeps the distinction between "these octets are valid UPER" and
// "this UE can execute the handover" explicit in its result types.
//
// The typed structures below model the subset this project can populate from
// real state. A field that is not modelled is not silently zeroed: the
// specification marks it OPTIONAL and the encoder omits it, or the API has no
// way to express it and the limitation is named in the design record.

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace lte::rrc
{

// How far a decoded message has been taken. A message can be valid UPER and
// still be unexecutable, and the five levels keep that apart.
enum class RrcReadiness : uint8_t
{
    // The octets decode as the specified message.
    RRC_CODEC_VALID,
    // The decoded configuration is complete for the handover profile.
    RRC_CONFIGURATION_VALID,
    // Every value in it was supplied by live runtime state rather than a fixture.
    RRC_RUNTIME_INPUT_AVAILABLE,
    // The AS keys the message assumes exist do exist.
    RRC_SECURITY_READY,
    // The UE can execute the reconfiguration on its radio.
    RRC_UE_EXECUTION_READY
};

const char *ToString(RrcReadiness readiness);

// Why a message was refused. Each value is decided before any structure is
// handed to a caller.
enum class RrcRefusal : uint8_t
{
    NONE,
    EMPTY_INPUT,
    TRUNCATED,
    INVALID_CHOICE,
    INVALID_CONSTRAINT,
    INVALID_PRESENCE,
    UNSUPPORTED_EXTENSION,
    OVERSIZED,
    MISSING_MANDATORY,
    UNSUPPORTED_VALUE,
    NOT_HANDOVER_MESSAGE
};

const char *ToString(RrcRefusal refusal);

struct RrcOutcome
{
    bool ok{};
    RrcRefusal refusal{RrcRefusal::NONE};
    std::string detail;

    [[nodiscard]] explicit operator bool() const { return ok; }
};

// The S1AP transparent container bound. It is the same receiver bound the S1AP
// codec applies, so a container cannot be acceptable to one layer and not the
// other.
constexpr size_t MaxRrcContainerSize = 4096;

// --- Typed protocol data ---------------------------------------------------

// UE-CapabilityRAT-Container ::= SEQUENCE { rat-Type, ueCapabilityRAT-Container }
struct UeCapabilityContainer
{
    // RAT-Type enumerator (0 eutra, 1 utra, ...). The value is carried as the
    // specification states it; this codec does not validate the container body,
    // which belongs to the RAT it names.
    uint8_t ratType{};
    std::vector<uint8_t> container;
};

struct MasterInformationBlock
{
    uint8_t dlBandwidth{};            // ENUMERATED n6..n100 (0..5)
    uint8_t phichDuration{};          // ENUMERATED normal/extended (0..1)
    uint8_t phichResource{};          // ENUMERATED oneSixth..two (0..3)
    uint8_t systemFrameNumber{};      // BIT STRING (SIZE (8))
    uint8_t schedulingInfoSib1Br{};   // INTEGER (0..31)
    bool systemInfoUnchangedBr{};     // BOOLEAN
    uint8_t spare{};                  // BIT STRING (SIZE (4))
};

struct SystemInformationBlockType1
{
    std::array<uint8_t, 3> plmnIdentity{};   // PLMN-Identity, three octets
    uint8_t cellReservedForOperatorUse{};    // ENUMERATED (0..1)
    uint16_t trackingAreaCode{};             // BIT STRING (SIZE (16)) as an integer
    uint32_t cellIdentity{};                 // BIT STRING (SIZE (28)) as an integer
    uint8_t cellBarred{};                    // ENUMERATED barred/notBarred (0..1)
    uint8_t intraFreqReselection{};          // ENUMERATED allowed/notAllowed (0..1)
    bool csgIndication{};                    // BOOLEAN
    int8_t qRxLevMin{};                      // INTEGER (-70..-22)
    uint8_t freqBandIndicator{};             // INTEGER (1..64)
    uint8_t siPeriodicity{};                 // ENUMERATED rf8..rf512 (0..6)
    uint8_t sibType{};                       // SIB-Type (0..31)
    uint8_t siWindowLength{};                // ENUMERATED ms1..ms40 (0..6)
    uint8_t systemInfoValueTag{};            // INTEGER (0..31)
};

// The mandatory members of RadioResourceConfigCommonSIB. The optional members
// of the specification are not modelled; the encoder omits them.
struct RadioResourceConfigCommonSib
{
    uint8_t numberOfRaPreambles{};                 // ENUMERATED n4..n64 (0..15)
    uint8_t powerRampingStep{};                    // ENUMERATED dB0..dB6 (0..3)
    uint8_t preambleInitialReceivedTargetPower{};  // ENUMERATED dBm-120..dBm-90 (0..15)
    uint8_t preambleTransMax{};                    // ENUMERATED n3..n200 (0..7)
    uint8_t raResponseWindowSize{};                // ENUMERATED sf2..sf10 (0..7)
    uint8_t maxHarqMsg3Tx{};                       // INTEGER (1..8)
    uint8_t bcchModificationPeriodCoeff{};         // ENUMERATED n2..n16 (0..3)
    uint8_t pcchDefaultPagingCycle{};              // ENUMERATED rf32..rf256 (0..3)
    uint8_t pcchNb{};                              // ENUMERATED fourT..oneThirtySecondT (0..7)
    uint16_t prachRootSequenceIndex{};             // INTEGER (0..837)
    uint8_t prachConfigIndex{};                    // INTEGER (0..63)
    bool prachHighSpeedFlag{};                     // BOOLEAN
    uint8_t prachZeroCorrelationZoneConfig{};      // INTEGER (0..15)
    uint8_t prachFreqOffset{};                     // INTEGER (0..94)
    int8_t pdschReferenceSignalPower{};            // INTEGER (-60..50)
    uint8_t pdschPb{};                             // INTEGER (0..3)
    uint8_t puschNSb{};                            // INTEGER (1..4)
    uint8_t puschHoppingMode{};                    // ENUMERATED (0..1)
    uint8_t puschHoppingOffset{};                  // INTEGER (0..98)
    bool puschEnable64Qam{};                       // BOOLEAN
    bool puschGroupHoppingEnabled{};               // BOOLEAN
    uint8_t puschGroupAssignmentPusch{};           // INTEGER (0..29)
    bool puschSequenceHoppingEnabled{};            // BOOLEAN
    uint8_t puschCyclicShift{};                    // INTEGER (0..7)
    uint8_t pucchDeltaShift{};                     // ENUMERATED ds1..ds3 (0..2)
    uint8_t pucchNrbCqi{};                         // INTEGER (0..98)
    uint8_t pucchNcsAn{};                          // INTEGER (0..7)
    uint16_t pucchN1PucchAn{};                     // INTEGER (0..2047)
    bool soundingRsRelease{};                      // CHOICE release (true) / setup (false)
    uint8_t srsBandwidthConfig{};                  // ENUMERATED bw0..bw7 (0..7)
    uint8_t srsSubframeConfig{};                   // ENUMERATED sc0..sc15 (0..15)
    bool ackNackSrsSimultaneousTransmission{};     // BOOLEAN
    int16_t p0NominalPusch{};                      // INTEGER (-126..24)
    uint8_t alpha{};                               // Alpha-r12 (0..7)
    int8_t p0NominalPucch{};                       // INTEGER (-127..-96)
    uint8_t deltaFPucchFormat1{};                  // ENUMERATED (0..2)
    uint8_t deltaFPucchFormat1b{};                 // ENUMERATED (0..2)
    uint8_t deltaFPucchFormat2{};                  // ENUMERATED (0..3)
    uint8_t deltaFPucchFormat2a{};                 // ENUMERATED (0..2)
    uint8_t deltaFPucchFormat2b{};                 // ENUMERATED (0..2)
    int8_t deltaPreambleMsg3{};                    // INTEGER (-1..6)
    uint8_t ulCyclicPrefixLength{};                // INTEGER (1..2)
};

struct SystemInformationBlockType2
{
    RadioResourceConfigCommonSib radioResourceConfigCommon;
    uint8_t t300{};                         // ENUMERATED ms100..ms2000 (0..7)
    uint8_t t301{};
    uint8_t t310{};                         // ENUMERATED ms0..ms2000 (0..6)
    uint8_t n310{};                         // ENUMERATED n1..n20 (0..7)
    uint8_t t311{};                         // ENUMERATED ms1000..ms30000 (0..6)
    uint8_t n311{};                         // ENUMERATED n1..n10 (0..7)
    uint8_t additionalSpectrumEmission{};   // INTEGER (0..31)
    uint8_t timeAlignmentTimerCommon{};     // ENUMERATED sf500..infinity (0..7)
};

// AS-Config, reduced to the members this project can populate from a source
// cell's own state. sourceMeasConfig and sourceRadioResourceConfig are legal
// empty structures here: this phase does not model their contents and the
// design record states so, rather than filling them with invented values.
struct SourceAsConfig
{
    uint8_t cipheringAlgorithm{};      // CipheringAlgorithm-r12 (0..3 in the root)
    uint8_t integrityProtAlgorithm{};  // eia0-v920..spare1 (0..7)
    uint16_t sourceUeIdentity{};       // C-RNTI (0..65535)
    uint8_t antennaPortsCount{};       // ENUMERATED an1/an2/an4/spare1 (0..3)
    uint16_t sourceDlCarrierFreq{};    // ARFCN-ValueEUTRA (0..65535)
    MasterInformationBlock mib;
    SystemInformationBlockType1 sib1;
    SystemInformationBlockType2 sib2;
};

// HandoverPreparationInformation as this project can produce it. as-Config is
// OPTIONAL in the specification and conditionally present for a handover, so
// both forms are representable.
struct HandoverPreparation
{
    std::vector<UeCapabilityContainer> ueCapabilities;  // 1..8 entries
    std::optional<SourceAsConfig> asConfig;
};

// RRCConnectionReconfiguration carrying mobilityControlInfo: the message that
// directs a UE to the target cell.
struct HandoverCommand
{
    uint8_t rrcTransactionIdentifier{};  // RRC-TransactionIdentifier (0..3)
    uint16_t targetPhysCellId{};         // PhysCellId (0..503)
    uint8_t t304{};                      // ENUMERATED ms50..ms10000-v1310 (0..7)
    uint16_t newUeIdentity{};            // C-RNTI (0..65535)
    // The mandatory members of RadioResourceConfigCommon.
    uint16_t prachRootSequenceIndex{};   // INTEGER (0..837)
    uint8_t puschNSb{};                  // INTEGER (1..4)
    uint8_t puschHoppingMode{};          // ENUMERATED (0..1)
    uint8_t puschHoppingOffset{};        // INTEGER (0..98)
    bool puschEnable64Qam{};             // BOOLEAN
    bool puschGroupHoppingEnabled{};     // BOOLEAN
    uint8_t puschGroupAssignmentPusch{}; // INTEGER (0..29)
    bool puschSequenceHoppingEnabled{};  // BOOLEAN
    uint8_t puschCyclicShift{};          // INTEGER (0..7)
    uint8_t ulCyclicPrefixLength{};      // INTEGER (1..2)
};

// --- Codec -----------------------------------------------------------------

// Encodes the message with UPER. On success `uper` holds the message octets,
// exactly as they belong inside an S1AP transparent container.
RrcOutcome EncodeHandoverPreparationInformation(const HandoverPreparation &message, std::vector<uint8_t> *uper);

// Decodes UPER octets into the typed model. A message that decodes but carries
// something this model cannot represent is refused rather than truncated.
RrcOutcome DecodeHandoverPreparationInformation(const uint8_t *data, size_t size, HandoverPreparation *message);

RrcOutcome EncodeHandoverCommand(const HandoverCommand &message, std::vector<uint8_t> *uper);
RrcOutcome DecodeHandoverCommand(const uint8_t *data, size_t size, HandoverCommand *message);

// Whether a container is the isolated simulator's own frame rather than LTE
// RRC. It is the boundary the S1AP side already enforces; this is the RRC
// side's copy of it, so a simulator container can never be decoded as RRC.
bool IsSimulatorContainer(const std::vector<uint8_t> &container);

} // namespace lte::rrc
