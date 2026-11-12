//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

// Phase 18-F-B2: the TS 36.413 transparent-container SEQUENCEs.
//
// An S1 handover carries its LTE RRC inside a transparent container, and the
// container is not the RRC message: TS 36.413 defines a SEQUENCE around it.
// This module is that SEQUENCE, encoded and decoded with the same aligned-PER
// primitives the S1AP message codec uses, so the three layers stay distinct:
//
//   TS 36.331 RRC message            UPER
//   TS 36.413 container SEQUENCE     APER   <- here
//   TS 36.413 S1AP message           APER   <- src/lte/enb/codec.cpp
//
// The RRC payload is carried as an opaque OCTET STRING and is never parsed,
// rewritten or inferred here. What this module does own is the container's own
// fields: the target cell identity and the UE's visited-cell history, both
// with an explicit statement of where their values came from.

#pragma once

#include "codec.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace lte::enb::s1ap
{

// Where a target-cell identity came from. A decoded E-UTRAN-CGI is not proof
// that the cell exists, and a fixture value is not proof of a live target
// association; the provenance says which of those the value is.
enum class EutranCgiProvenance : uint8_t
{
    // Supplied by a deterministic offline fixture.
    FIXTURE,
    // Read out of a verified simulator cell identity.
    SIMULATOR_CELL,
    // Read out of a real running target cell's configuration.
    RUNNING_TARGET_CELL,
    // Supplied by a caller with no verification behind it.
    CALLER_UNVERIFIED
};

const char *ToString(EutranCgiProvenance provenance);

// Where a UE history entry came from. A handover container must carry history
// the responsible runtime actually recorded; a timestamp difference is not a
// history.
enum class HistoryProvenance : uint8_t
{
    // Recorded by the runtime that watched the UE occupy the cell.
    RUNTIME_OBSERVED,
    // Supplied by a deterministic offline fixture.
    FIXTURE,
    // No history is known.
    MISSING,
    // The history is known but older than its validity window.
    STALE,
    // Cells before this entry are unknown.
    UNKNOWN_PREDECESSOR
};

const char *ToString(HistoryProvenance provenance);

// EUTRAN-CGI ::= SEQUENCE { pLMNidentity, cell-ID BIT STRING (SIZE (28)),
//                           iE-Extensions OPTIONAL, ... }
struct EutranCgiValue
{
    Plmn plmn;
    uint32_t cellId{};  // the 28-bit E-UTRAN cell identifier
    EutranCgiProvenance provenance{EutranCgiProvenance::CALLER_UNVERIFIED};
};

// LastVisitedEUTRANCellInformation ::= SEQUENCE { global-Cell-ID, cellType,
//                                                  time-UE-StayedInCell, ... }
// with CellType ::= SEQUENCE { cell-Size Cell-Size, ... }.
struct LastVisitedEutranCell
{
    EutranCgiValue globalCellId;
    uint8_t cellSize{};              // Cell-Size: verysmall..large (0..3)
    uint16_t timeUeStayedInCell{};   // INTEGER (0..4095)
    HistoryProvenance provenance{HistoryProvenance::FIXTURE};
};

// UE-HistoryInformation ::= SEQUENCE (SIZE (1..16)) OF LastVisitedCell-Item,
// of which this profile supports only the e-UTRAN-Cell alternative.
struct UeHistoryInformation
{
    std::vector<LastVisitedEutranCell> visitedCells;
    HistoryProvenance provenance{HistoryProvenance::FIXTURE};
};

// SourceeNB-ToTargeteNB-TransparentContainer, reduced to the fields this
// profile supports. The two fields the module cannot encode are named rather
// than dropped: supplying either one is refused.
struct SourceToTargetContainer
{
    std::vector<uint8_t> rrcPayload;
    EutranCgiValue targetCellId;
    UeHistoryInformation ueHistory;
    std::optional<uint16_t> subscriberProfileIdForRfp;  // INTEGER (1..256)
    // e-RABInformationList and iE-Extensions are not supported in this profile.
    bool carriesERabInformationList{};
    bool carriesIeExtensions{};
};

// TargeteNB-ToSourceeNB-TransparentContainer ::= SEQUENCE { rRC-Container,
//                                                    iE-Extensions OPTIONAL, ... }
struct TargetToSourceContainer
{
    std::vector<uint8_t> rrcPayload;
    bool carriesIeExtensions{};
};

enum class ContainerRefusal : uint8_t
{
    NONE,
    EMPTY_RRC_PAYLOAD,
    RRC_PAYLOAD_TOO_LARGE,
    MISSING_TARGET_CGI,
    INVALID_PLMN,
    INVALID_EUTRAN_CELL_ID,
    MISSING_UE_HISTORY,
    EMPTY_UE_HISTORY,
    UE_HISTORY_TOO_LONG,
    INVALID_HISTORY_ENTRY,
    UNSUPPORTED_HISTORY_ALTERNATIVE,
    UNSUPPORTED_OPTIONAL_FIELD,
    INVALID_SUBSCRIBER_PROFILE,
    TRUNCATED,
    TRAILING_DATA,
    MALFORMED,
    UNSUPPORTED_EXTENSION
};

const char *ToString(ContainerRefusal refusal);

struct ContainerOutcome
{
    bool ok{};
    ContainerRefusal refusal{ContainerRefusal::NONE};
    std::string detail;

    [[nodiscard]] explicit operator bool() const { return ok; }
};

// --- The two containers ----------------------------------------------------

// Builds the complete SourceeNB-ToTargeteNB-TransparentContainer octets. The
// RRC payload is carried verbatim; nothing in it is parsed here.
ContainerOutcome EncodeSourceToTargetTransparentContainer(const SourceToTargetContainer &container,
                                                          std::vector<uint8_t> *out);

// Decodes the container and returns its fields with their provenance intact.
// The payload is the exact octets the container carried.
ContainerOutcome DecodeSourceToTargetTransparentContainer(const uint8_t *data, size_t size,
                                                          SourceToTargetContainer *container);

ContainerOutcome EncodeTargetToSourceTransparentContainer(const TargetToSourceContainer &container,
                                                          std::vector<uint8_t> *out);
ContainerOutcome DecodeTargetToSourceTransparentContainer(const uint8_t *data, size_t size,
                                                          TargetToSourceContainer *container);

} // namespace lte::enb::s1ap
