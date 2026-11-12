//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#include "transparent_container.hpp"

#include <utility>

#include "aper_bits.hpp"

namespace lte::enb::s1ap
{
namespace
{

ContainerOutcome Refuse(ContainerRefusal refusal, std::string detail)
{
    ContainerOutcome outcome;
    outcome.ok = false;
    outcome.refusal = refusal;
    outcome.detail = std::move(detail);
    return outcome;
}

ContainerOutcome Accept()
{
    ContainerOutcome outcome;
    outcome.ok = true;
    return outcome;
}

// EUTRAN-CGI, written exactly as the S1AP message codec writes it: the
// extension marker, the absent iE-Extensions, the three PLMN octets and the
// 28-bit cell identifier. Nothing is padded in the middle; the caller's own
// writer aligns where the encoding rules require it.
void WriteEutranCgi(BitWriter &writer, const Plmn &plmn, uint32_t cellId)
{
    writer.writeBit(false);  // extension marker
    writer.writeBit(false);  // iE-Extensions absent
    const auto encoded = EncodePlmn(plmn);
    WriteFixedOctets(writer, encoded.data(), encoded.size());
    writer.writeBits(cellId, 28);
}

void ReadEutranCgi(BitReader &reader, Plmn *plmn, uint32_t *cellId)
{
    if (reader.readBit())
        throw CodecError("EUTRAN-CGI carries unsupported extension additions");
    if (reader.readBit())
        throw CodecError("EUTRAN-CGI carries unsupported iE-Extensions");
    const auto octets = ReadFixedOctets(reader, 3);
    *plmn = DecodePlmn(octets.data(), octets.size());
    *cellId = static_cast<uint32_t>(reader.readBits(28));
}

// CellType ::= SEQUENCE { cell-Size Cell-Size, iE-Extensions OPTIONAL, ... }
// Cell-Size ::= ENUMERATED { verysmall, small, medium, large, ... }
void WriteCellType(BitWriter &writer, uint8_t cellSize)
{
    writer.writeBit(false);  // extension marker
    writer.writeBit(false);  // iE-Extensions absent
    writer.writeBit(false);  // Cell-Size: not an extension value
    writer.writeBits(cellSize, 2);
}

void ReadCellType(BitReader &reader, uint8_t *cellSize)
{
    if (reader.readBit())
        throw CodecError("CellType carries unsupported extension additions");
    if (reader.readBit())
        throw CodecError("CellType carries unsupported iE-Extensions");
    if (reader.readBit())
        throw CodecError("Cell-Size is an unsupported extension value");
    *cellSize = static_cast<uint8_t>(reader.readBits(2));
}

// LastVisitedEUTRANCellInformation ::= SEQUENCE {
//     global-Cell-ID EUTRAN-CGI,
//     cellType       CellType,
//     time-UE-StayedInCell Time-UE-StayedInCell,
//     iE-Extensions OPTIONAL, ... }
void WriteVisitedCell(BitWriter &writer, const LastVisitedEutranCell &cell)
{
    // LastVisitedCell-Item is an extensible CHOICE with three root
    // alternatives; this profile supports only e-UTRAN-Cell.
    writer.writeBit(false);  // CHOICE: not an extension value
    writer.writeBits(0, 2);  // e-UTRAN-Cell

    writer.writeBit(false);  // extension marker
    writer.writeBit(false);  // iE-Extensions absent
    WriteEutranCgi(writer, cell.globalCellId.plmn, cell.globalCellId.cellId);
    WriteCellType(writer, cell.cellSize);
    WriteConstrained(writer, cell.timeUeStayedInCell, 0, 4095, true);
}

void ReadVisitedCell(BitReader &reader, LastVisitedEutranCell *cell)
{
    if (reader.readBit())
        throw CodecError("LastVisitedCell-Item is an unsupported extension alternative");
    const auto alternative = static_cast<uint8_t>(reader.readBits(2));
    if (alternative != 0)
        throw CodecError("LastVisitedCell-Item is not an e-UTRAN cell");
    if (reader.readBit())
        throw CodecError("LastVisitedEUTRANCellInformation carries unsupported extension additions");
    if (reader.readBit())
        throw CodecError("LastVisitedEUTRANCellInformation carries unsupported iE-Extensions");
    ReadEutranCgi(reader, &cell->globalCellId.plmn, &cell->globalCellId.cellId);
    ReadCellType(reader, &cell->cellSize);
    cell->timeUeStayedInCell = static_cast<uint16_t>(ReadConstrained(reader, 0, 4095, true));
}

// The RRC payload is an OCTET STRING: an octet-aligned length determinant
// followed by the octets themselves, carried verbatim.
void WriteRrcPayload(BitWriter &writer, const std::vector<uint8_t> &payload)
{
    writer.writeLength(payload.size());
    writer.writeBytes(payload);
}

ContainerOutcome ValidatePayload(const std::vector<uint8_t> &payload)
{
    if (payload.empty())
        return Refuse(ContainerRefusal::EMPTY_RRC_PAYLOAD, "the rRC-Container carries no RRC message");
    if (payload.size() > MaxTransparentContainerSize)
        return Refuse(ContainerRefusal::RRC_PAYLOAD_TOO_LARGE,
                      "the RRC message exceeds the transparent-container bound");
    return Accept();
}

ContainerOutcome ValidateTargetCgi(const EutranCgiValue &cgi)
{
    if (cgi.plmn.mcc.empty() && cgi.plmn.mnc.empty())
        return Refuse(ContainerRefusal::MISSING_TARGET_CGI, "no target cell identity was supplied");
    if (cgi.plmn.mcc.empty() || cgi.plmn.mnc.empty())
        return Refuse(ContainerRefusal::INVALID_PLMN, "the target cell identity carries no PLMN");
    if (cgi.plmn.mcc.size() != 3 || (cgi.plmn.mnc.size() != 2 && cgi.plmn.mnc.size() != 3))
        return Refuse(ContainerRefusal::INVALID_PLMN, "the target cell identity carries a malformed PLMN");
    for (const char digit : cgi.plmn.mcc + cgi.plmn.mnc)
        if (digit < '0' || digit > '9')
            return Refuse(ContainerRefusal::INVALID_PLMN, "the target cell identity carries a non-decimal PLMN digit");
    if (cgi.cellId > 0x0FFFFFFFU)
        return Refuse(ContainerRefusal::INVALID_EUTRAN_CELL_ID,
                      "the E-UTRAN cell identifier does not fit in its 28 bits");
    return Accept();
}

ContainerOutcome ValidateHistory(const UeHistoryInformation &history)
{
    if (history.provenance == HistoryProvenance::MISSING)
        return Refuse(ContainerRefusal::MISSING_UE_HISTORY,
                      "a source container must carry the UE history the runtime recorded");
    if (history.visitedCells.empty())
        return Refuse(ContainerRefusal::EMPTY_UE_HISTORY, "UE-HistoryInformation must hold at least one cell");
    if (history.visitedCells.size() > 16)
        return Refuse(ContainerRefusal::UE_HISTORY_TOO_LONG,
                      "UE-HistoryInformation holds at most 16 visited cells");
    for (const auto &cell : history.visitedCells)
    {
        if (cell.cellSize > 3)
            return Refuse(ContainerRefusal::INVALID_HISTORY_ENTRY, "a visited cell size is outside its enumeration");
        if (cell.timeUeStayedInCell > 4095)
            return Refuse(ContainerRefusal::INVALID_HISTORY_ENTRY,
                          "a visited-cell stay is outside the 0..4095 range");
        const auto cgi = ValidateTargetCgi(cell.globalCellId);
        if (!cgi.ok)
            return cgi;
    }
    return Accept();
}

// The trailing octets of a container are not part of any message. Zero bits of
// octet alignment are the encoding's own padding and are accepted; anything
// else left over is trailing data and is refused.
bool HasTrailingData(const BitReader &reader)
{
    return reader.remainingBits() >= 8;
}

} // namespace

const char *ToString(EutranCgiProvenance provenance)
{
    switch (provenance)
    {
    case EutranCgiProvenance::FIXTURE: return "FIXTURE";
    case EutranCgiProvenance::SIMULATOR_CELL: return "SIMULATOR_CELL";
    case EutranCgiProvenance::RUNNING_TARGET_CELL: return "RUNNING_TARGET_CELL";
    case EutranCgiProvenance::CALLER_UNVERIFIED: return "CALLER_UNVERIFIED";
    case EutranCgiProvenance::WIRE_UNVERIFIED: return "WIRE_UNVERIFIED";
    }
    return "UNKNOWN_CGI_PROVENANCE";
}

const char *ToString(HistoryProvenance provenance)
{
    switch (provenance)
    {
    case HistoryProvenance::RUNTIME_OBSERVED: return "RUNTIME_OBSERVED";
    case HistoryProvenance::FIXTURE: return "FIXTURE";
    case HistoryProvenance::MISSING: return "MISSING";
    case HistoryProvenance::STALE: return "STALE";
    case HistoryProvenance::UNKNOWN_PREDECESSOR: return "UNKNOWN_PREDECESSOR";
    case HistoryProvenance::WIRE_UNVERIFIED: return "WIRE_UNVERIFIED";
    }
    return "UNKNOWN_HISTORY_PROVENANCE";
}

const char *ToString(ContainerRefusal refusal)
{
    switch (refusal)
    {
    case ContainerRefusal::NONE: return "NONE";
    case ContainerRefusal::EMPTY_RRC_PAYLOAD: return "EMPTY_RRC_PAYLOAD";
    case ContainerRefusal::RRC_PAYLOAD_TOO_LARGE: return "RRC_PAYLOAD_TOO_LARGE";
    case ContainerRefusal::MISSING_TARGET_CGI: return "MISSING_TARGET_CGI";
    case ContainerRefusal::INVALID_PLMN: return "INVALID_PLMN";
    case ContainerRefusal::INVALID_EUTRAN_CELL_ID: return "INVALID_EUTRAN_CELL_ID";
    case ContainerRefusal::MISSING_UE_HISTORY: return "MISSING_UE_HISTORY";
    case ContainerRefusal::EMPTY_UE_HISTORY: return "EMPTY_UE_HISTORY";
    case ContainerRefusal::UE_HISTORY_TOO_LONG: return "UE_HISTORY_TOO_LONG";
    case ContainerRefusal::INVALID_HISTORY_ENTRY: return "INVALID_HISTORY_ENTRY";
    case ContainerRefusal::UNSUPPORTED_HISTORY_ALTERNATIVE: return "UNSUPPORTED_HISTORY_ALTERNATIVE";
    case ContainerRefusal::UNSUPPORTED_OPTIONAL_FIELD: return "UNSUPPORTED_OPTIONAL_FIELD";
    case ContainerRefusal::INVALID_SUBSCRIBER_PROFILE: return "INVALID_SUBSCRIBER_PROFILE";
    case ContainerRefusal::TRUNCATED: return "TRUNCATED";
    case ContainerRefusal::TRAILING_DATA: return "TRAILING_DATA";
    case ContainerRefusal::MALFORMED: return "MALFORMED";
    case ContainerRefusal::UNSUPPORTED_EXTENSION: return "UNSUPPORTED_EXTENSION";
    }
    return "UNKNOWN_CONTAINER_REFUSAL";
}

// --- Source-to-target ------------------------------------------------------

ContainerOutcome EncodeSourceToTargetTransparentContainer(const SourceToTargetContainer &container,
                                                          std::vector<uint8_t> *out)
{
    if (out == nullptr)
        return Refuse(ContainerRefusal::MALFORMED, "no output was named");
    const auto payload = ValidatePayload(container.rrcPayload);
    if (!payload.ok)
        return payload;
    if (container.carriesERabInformationList)
        return Refuse(ContainerRefusal::UNSUPPORTED_OPTIONAL_FIELD,
                      "e-RABInformationList is not supported in this profile and cannot be carried");
    if (container.carriesIeExtensions)
        return Refuse(ContainerRefusal::UNSUPPORTED_OPTIONAL_FIELD,
                      "iE-Extensions is not supported in this profile and cannot be carried");
    const auto cgi = ValidateTargetCgi(container.targetCellId);
    if (!cgi.ok)
        return cgi;
    const auto history = ValidateHistory(container.ueHistory);
    if (!history.ok)
        return history;
    if (container.subscriberProfileIdForRfp.has_value() &&
        (*container.subscriberProfileIdForRfp < 1 || *container.subscriberProfileIdForRfp > 256))
        return Refuse(ContainerRefusal::INVALID_SUBSCRIBER_PROFILE,
                      "the subscriber profile identity is outside the 1..256 range");

    try
    {
        BitWriter writer;
        writer.writeBit(false);  // extension marker: no extension additions
        writer.writeBit(false);  // e-RABInformationList absent
        writer.writeBit(container.subscriberProfileIdForRfp.has_value());
        writer.writeBit(false);  // iE-Extensions absent

        WriteRrcPayload(writer, container.rrcPayload);
        WriteEutranCgi(writer, container.targetCellId.plmn, container.targetCellId.cellId);
        if (container.subscriberProfileIdForRfp.has_value())
            WriteConstrained(writer, *container.subscriberProfileIdForRfp, 1, 256, true);

        // UE-HistoryInformation ::= SEQUENCE (SIZE (1..16)) OF
        // LastVisitedCell-Item, so the count is a constrained whole number in
        // the same 1..16 range the ASN.1 states.
        WriteConstrained(writer, container.ueHistory.visitedCells.size(), 1, 16, false);
        for (const auto &cell : container.ueHistory.visitedCells)
            WriteVisitedCell(writer, cell);

        *out = writer.take();
    }
    catch (const CodecError &error)
    {
        return Refuse(ContainerRefusal::MALFORMED, error.what());
    }

    if (out->size() > MaxTransparentContainerSize)
        return Refuse(ContainerRefusal::RRC_PAYLOAD_TOO_LARGE,
                      "the complete container exceeds the transparent-container bound");
    return Accept();
}

ContainerOutcome DecodeSourceToTargetTransparentContainer(const uint8_t *data, size_t size,
                                                          SourceToTargetContainer *container)
{
    if (container == nullptr)
        return Refuse(ContainerRefusal::MALFORMED, "no output was named");
    if (data == nullptr || size == 0)
        return Refuse(ContainerRefusal::TRUNCATED, "the transparent container is empty");
    if (size > MaxTransparentContainerSize)
        return Refuse(ContainerRefusal::RRC_PAYLOAD_TOO_LARGE,
                      "the container exceeds the transparent-container bound");

    SourceToTargetContainer out;
    try
    {
        BitReader reader(data, size);
        if (reader.readBit())
            return Refuse(ContainerRefusal::UNSUPPORTED_EXTENSION,
                          "the source container carries extension additions this profile cannot read");
        if (reader.readBit())
            return Refuse(ContainerRefusal::UNSUPPORTED_OPTIONAL_FIELD,
                          "the source container carries an e-RABInformationList this profile cannot read");
        const bool hasProfile = reader.readBit();
        if (reader.readBit())
            return Refuse(ContainerRefusal::UNSUPPORTED_OPTIONAL_FIELD,
                          "the source container carries iE-Extensions this profile cannot read");

        const auto payloadSize = reader.readLength();
        if (payloadSize == 0)
            return Refuse(ContainerRefusal::EMPTY_RRC_PAYLOAD, "the rRC-Container carries no RRC message");
        out.rrcPayload = reader.readBytes(payloadSize);

        ReadEutranCgi(reader, &out.targetCellId.plmn, &out.targetCellId.cellId);
        // Decoding is not verification. The wire carries no provenance, so
        // what came out of it is asserted by a peer and stays that way until a
        // runtime authority says otherwise.
        out.targetCellId.provenance = EutranCgiProvenance::WIRE_UNVERIFIED;

        if (hasProfile)
        {
            const auto profile = static_cast<uint16_t>(ReadConstrained(reader, 1, 256, true));
            out.subscriberProfileIdForRfp = profile;
        }

        const auto historyCount = static_cast<size_t>(ReadConstrained(reader, 1, 16, false));
        if (historyCount == 0 || historyCount > 16)
            return Refuse(ContainerRefusal::UE_HISTORY_TOO_LONG,
                          "UE-HistoryInformation holds between one and sixteen visited cells");
        for (size_t i = 0; i < historyCount; ++i)
        {
            LastVisitedEutranCell cell;
            try
            {
                ReadVisitedCell(reader, &cell);
            }
            catch (const CodecError &error)
            {
                const std::string detail = error.what();
                if (detail.find("extension alternative") != std::string::npos ||
                    detail.find("not an e-UTRAN cell") != std::string::npos)
                    return Refuse(ContainerRefusal::UNSUPPORTED_HISTORY_ALTERNATIVE, detail);
                return Refuse(ContainerRefusal::INVALID_HISTORY_ENTRY, detail);
            }
            out.ueHistory.visitedCells.push_back(cell);
        }
        out.ueHistory.provenance = HistoryProvenance::WIRE_UNVERIFIED;
        for (auto &cell : out.ueHistory.visitedCells)
        {
            cell.provenance = HistoryProvenance::WIRE_UNVERIFIED;
            cell.globalCellId.provenance = EutranCgiProvenance::WIRE_UNVERIFIED;
        }

        if (HasTrailingData(reader))
            return Refuse(ContainerRefusal::TRAILING_DATA,
                          "the transparent container carries octets after its message");
    }
    catch (const CodecError &error)
    {
        return Refuse(ContainerRefusal::MALFORMED, error.what());
    }

    *container = std::move(out);
    return Accept();
}

// --- Target-to-source ------------------------------------------------------

ContainerOutcome EncodeTargetToSourceTransparentContainer(const TargetToSourceContainer &container,
                                                          std::vector<uint8_t> *out)
{
    if (out == nullptr)
        return Refuse(ContainerRefusal::MALFORMED, "no output was named");
    const auto payload = ValidatePayload(container.rrcPayload);
    if (!payload.ok)
        return payload;
    if (container.carriesIeExtensions)
        return Refuse(ContainerRefusal::UNSUPPORTED_OPTIONAL_FIELD,
                      "iE-Extensions is not supported in this profile and cannot be carried");

    try
    {
        BitWriter writer;
        writer.writeBit(false);  // extension marker: no extension additions
        writer.writeBit(false);  // iE-Extensions absent
        WriteRrcPayload(writer, container.rrcPayload);
        *out = writer.take();
    }
    catch (const CodecError &error)
    {
        return Refuse(ContainerRefusal::MALFORMED, error.what());
    }

    if (out->size() > MaxTransparentContainerSize)
        return Refuse(ContainerRefusal::RRC_PAYLOAD_TOO_LARGE,
                      "the complete container exceeds the transparent-container bound");
    return Accept();
}

ContainerOutcome DecodeTargetToSourceTransparentContainer(const uint8_t *data, size_t size,
                                                          TargetToSourceContainer *container)
{
    if (container == nullptr)
        return Refuse(ContainerRefusal::MALFORMED, "no output was named");
    if (data == nullptr || size == 0)
        return Refuse(ContainerRefusal::TRUNCATED, "the transparent container is empty");
    if (size > MaxTransparentContainerSize)
        return Refuse(ContainerRefusal::RRC_PAYLOAD_TOO_LARGE,
                      "the container exceeds the transparent-container bound");

    TargetToSourceContainer out;
    try
    {
        BitReader reader(data, size);
        if (reader.readBit())
            return Refuse(ContainerRefusal::UNSUPPORTED_EXTENSION,
                          "the target container carries extension additions this profile cannot read");
        if (reader.readBit())
            return Refuse(ContainerRefusal::UNSUPPORTED_OPTIONAL_FIELD,
                          "the target container carries iE-Extensions this profile cannot read");

        const auto payloadSize = reader.readLength();
        if (payloadSize == 0)
            return Refuse(ContainerRefusal::EMPTY_RRC_PAYLOAD, "the rRC-Container carries no RRC message");
        out.rrcPayload = reader.readBytes(payloadSize);
        if (HasTrailingData(reader))
            return Refuse(ContainerRefusal::TRAILING_DATA,
                          "the transparent container carries octets after its message");
    }
    catch (const CodecError &error)
    {
        return Refuse(ContainerRefusal::MALFORMED, error.what());
    }

    *container = std::move(out);
    return Accept();
}

} // namespace lte::enb::s1ap
