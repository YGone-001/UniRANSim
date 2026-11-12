//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#include "codec.hpp"

#include <algorithm>
#include <array>
#include <limits>
#include <set>
#include <sstream>

namespace lte::enb::s1ap
{

namespace
{

constexpr uint16_t PROCEDURE_INITIAL_CONTEXT_SETUP = 9;
constexpr uint16_t PROCEDURE_PAGING = 10;
constexpr uint16_t PROCEDURE_S1_SETUP = 17;
constexpr uint16_t PROCEDURE_DOWNLINK_NAS_TRANSPORT = 11;
constexpr uint16_t PROCEDURE_INITIAL_UE_MESSAGE = 12;
constexpr uint16_t PROCEDURE_UPLINK_NAS_TRANSPORT = 13;
constexpr uint16_t PROCEDURE_UE_CONTEXT_RELEASE_REQUEST = 18;
constexpr uint16_t PROCEDURE_UE_CONTEXT_RELEASE = 23;
constexpr uint16_t IE_CAUSE = 2;
constexpr uint16_t IE_MME_UE_S1AP_ID = 0;
constexpr uint16_t IE_ENB_UE_S1AP_ID = 8;
constexpr uint16_t IE_E_RAB_TO_BE_SETUP_LIST_CTXT_SU_REQ = 24;
constexpr uint16_t IE_NAS_PDU = 26;
constexpr uint16_t IE_E_RAB_SETUP_ITEM_CTXT_SU_RES = 50;
constexpr uint16_t IE_E_RAB_SETUP_LIST_CTXT_SU_RES = 51;
constexpr uint16_t IE_E_RAB_FAILED_TO_SETUP_LIST_CTXT_SU_RES = 48;
constexpr uint16_t IE_E_RAB_TO_BE_SETUP_ITEM_CTXT_SU_REQ = 52;
constexpr uint16_t IE_UE_AGGREGATE_MAXIMUM_BITRATE = 66;
constexpr uint16_t IE_SECURITY_KEY = 73;
constexpr uint16_t IE_UE_S1AP_IDS = 99;
constexpr uint16_t IE_UE_SECURITY_CAPABILITIES = 107;
constexpr uint16_t IE_GLOBAL_ENB_ID = 59;
constexpr uint16_t IE_ENB_NAME = 60;
constexpr uint16_t IE_MME_NAME = 61;
constexpr uint16_t IE_SUPPORTED_TAS = 64;
constexpr uint16_t IE_TIME_TO_WAIT = 65;
constexpr uint16_t IE_RELATIVE_MME_CAPACITY = 87;
constexpr uint16_t IE_SERVED_GUMMEIS = 105;
constexpr uint16_t IE_DEFAULT_PAGING_DRX = 137;
constexpr uint16_t IE_CRITICALITY_DIAGNOSTICS = 58;
constexpr uint16_t IE_TAI = 67;
constexpr uint16_t PROCEDURE_E_RAB_SETUP = 5;
constexpr uint16_t PROCEDURE_E_RAB_RELEASE = 7;
constexpr uint16_t IE_E_RAB_TO_BE_SETUP_LIST_BEARER_SU_REQ = 16;
constexpr uint16_t IE_E_RAB_TO_BE_SETUP_ITEM_BEARER_SU_REQ = 17;
constexpr uint16_t IE_E_RAB_SETUP_LIST_BEARER_SU_RES = 28;
constexpr uint16_t IE_E_RAB_FAILED_TO_SETUP_LIST_BEARER_SU_RES = 29;
constexpr uint16_t IE_E_RAB_TO_BE_RELEASED_LIST = 33;
constexpr uint16_t IE_E_RAB_ITEM = 35;
constexpr uint16_t IE_E_RAB_RELEASE_ITEM = 38;
constexpr uint16_t IE_E_RAB_SETUP_ITEM_BEARER_SU_RES = 39;
constexpr uint16_t IE_E_RAB_RELEASED_LIST = 110;
constexpr uint16_t IE_EUTRAN_CGI = 100;
constexpr uint16_t IE_RRC_ESTABLISHMENT_CAUSE = 134;
constexpr uint16_t IE_S_TMSI = 96;
// TS 36.413 §9.1.3.1 S1-based connected-mode handover elementary procedures.
// id-PathSwitchRequest (3) is the X2-based bearer path update and is
// deliberately absent: it is not an S1-based handover message.
constexpr uint16_t PROCEDURE_HANDOVER_PREPARATION = 0;
constexpr uint16_t PROCEDURE_HANDOVER_RESOURCE_ALLOCATION = 1;
constexpr uint16_t PROCEDURE_HANDOVER_NOTIFICATION = 2;
// TS 36.413 handover information element identifiers. Every value below was
// read out of the reference ASN.1 module 36413-g40.asn (TS 36.413 V16.4.0).
// id-SourceID (3) is declared there but referenced by no handover IE set, so it
// is deliberately not defined here and never appears on the wire.
constexpr uint16_t IE_HANDOVER_TYPE = 1;
constexpr uint16_t IE_TARGET_ID = 4;
constexpr uint16_t IE_E_RAB_SUBJECT_TO_DATA_FORWARDING_LIST = 12;
constexpr uint16_t IE_E_RAB_TO_RELEASE_LIST_HO_CMD = 13;
constexpr uint16_t IE_E_RAB_DATA_FORWARDING_ITEM = 14;
constexpr uint16_t IE_E_RAB_ADMITTED_LIST = 18;
constexpr uint16_t IE_E_RAB_FAILED_TO_SETUP_LIST_HO_REQ_ACK = 19;
constexpr uint16_t IE_E_RAB_ADMITTED_ITEM = 20;
constexpr uint16_t IE_E_RAB_FAILED_TO_SETUP_ITEM_HO_REQ_ACK = 21;
constexpr uint16_t IE_E_RAB_TO_BE_SETUP_ITEM_HO_REQ = 27;
constexpr uint16_t IE_SECURITY_CONTEXT = 40;
constexpr uint16_t IE_E_RAB_TO_BE_SETUP_LIST_HO_REQ = 53;
constexpr uint16_t IE_DIRECT_FORWARDING_PATH_AVAILABILITY = 79;
constexpr uint16_t IE_SOURCE_TO_TARGET_TRANSPARENT_CONTAINER = 104;
constexpr uint16_t IE_TARGET_TO_SOURCE_TRANSPARENT_CONTAINER = 123;
constexpr uint16_t IE_SOURCE_TO_TARGET_TRANSPARENT_CONTAINER_SECONDARY = 138;
constexpr uint16_t IE_TARGET_TO_SOURCE_TRANSPARENT_CONTAINER_SECONDARY = 139;
// TS 36.413 Paging information elements. Paging is a non-UE-associated
// procedure, so none of these carry an eNB-UE-S1AP-ID or an MME-UE-S1AP-ID.
// The identifiers were verified against a live Open5GS 2.8 MME Paging PDU with
// the reference ASN.1 decoder: UEIdentityIndexValue=80, UEPagingID=43,
// CNDomain=109, TAIList=46 and TAIItem=47.
constexpr uint16_t IE_CN_DOMAIN = 109;
constexpr uint16_t IE_TAI_LIST = 46;
constexpr uint16_t IE_TAI_ITEM = 47;
constexpr uint16_t IE_UE_IDENTITY_INDEX_VALUE = 80;
constexpr uint16_t IE_UE_PAGING_IDENTITY = 43;
// TS 36.413 reuses IE id 137 for the optional PagingDRX of Paging and the
// DefaultPagingDRX of S1 Setup; IE_DEFAULT_PAGING_DRX therefore serves both.

enum class Criticality : uint8_t
{
    REJECT = 0,
    IGNORE = 1,
    NOTIFY = 2
};

class BitWriter;
void WriteCause(BitWriter &, const std::string &, int);

class BitWriter
{
  public:
    void writeBit(bool value)
    {
        writeBits(value ? 1 : 0, 1);
    }

    void writeBits(uint64_t value, size_t count)
    {
        if (count > 64)
            throw CodecError("Attempt to encode more than 64 bits at once");
        for (size_t i = 0; i < count; ++i)
        {
            size_t shift = count - i - 1;
            if ((m_bitCount % 8) == 0)
                m_data.push_back(0);
            if (((value >> shift) & 1U) != 0)
                m_data.back() |= static_cast<uint8_t>(1U << (7U - (m_bitCount % 8)));
            ++m_bitCount;
        }
    }

    void align()
    {
        m_bitCount = (m_bitCount + 7U) / 8U * 8U;
    }

    void writeBytes(const uint8_t *data, size_t length)
    {
        align();
        m_data.insert(m_data.end(), data, data + length);
        m_bitCount += length * 8U;
    }

    void writeBytes(const std::vector<uint8_t> &data)
    {
        writeBytes(data.data(), data.size());
    }

    void writeLength(size_t length)
    {
        align();
        if (length < 128)
            writeBits(length, 8);
        else if (length < 16384)
            writeBits(0x8000U | length, 16);
        else
            throw CodecError("S1AP open type is too large");
    }

    [[nodiscard]] std::vector<uint8_t> take()
    {
        align();
        return std::move(m_data);
    }

  private:
    std::vector<uint8_t> m_data;
    size_t m_bitCount{};
};

class BitReader
{
  public:
    BitReader(const uint8_t *data, size_t length) : m_data(data), m_length(length)
    {
    }
    explicit BitReader(const std::vector<uint8_t> &data) : BitReader(data.data(), data.size())
    {
    }

    uint64_t readBits(size_t count)
    {
        if (count > 64 || count > remainingBits())
            throw CodecError("Truncated S1AP APER value");
        uint64_t result = 0;
        for (size_t i = 0; i < count; ++i)
        {
            result <<= 1U;
            size_t byteIndex = m_bitOffset / 8U;
            size_t bitIndex = 7U - (m_bitOffset % 8U);
            result |= (m_data[byteIndex] >> bitIndex) & 1U;
            ++m_bitOffset;
        }
        return result;
    }

    bool readBit()
    {
        return readBits(1) != 0;
    }

    void align()
    {
        size_t aligned = (m_bitOffset + 7U) / 8U * 8U;
        while (m_bitOffset < aligned)
        {
            if (readBit())
                throw CodecError("Non-zero APER alignment padding");
        }
    }

    std::vector<uint8_t> readBytes(size_t length)
    {
        align();
        if (length > remainingBits() / 8U)
            throw CodecError("Truncated S1AP octet string");
        size_t byteOffset = m_bitOffset / 8U;
        std::vector<uint8_t> result(m_data + byteOffset, m_data + byteOffset + length);
        m_bitOffset += length * 8U;
        return result;
    }

    size_t readLength()
    {
        align();
        uint8_t first = static_cast<uint8_t>(readBits(8));
        if ((first & 0x80U) == 0)
            return first;
        if ((first & 0xC0U) == 0x80U)
            return (static_cast<size_t>(first & 0x3FU) << 8U) | readBits(8);
        throw CodecError("Fragmented APER length is not supported for S1 Setup");
    }

    std::vector<uint8_t> readOpenType()
    {
        return readBytes(readLength());
    }

    [[nodiscard]] size_t remainingBits() const
    {
        return m_length * 8U - m_bitOffset;
    }

    void requireFinished()
    {
        while (remainingBits() != 0)
        {
            if (readBit())
                throw CodecError("Unexpected trailing bits in S1AP value");
        }
    }

  private:
    const uint8_t *m_data;
    size_t m_length;
    size_t m_bitOffset{};
};

size_t BitsForRange(size_t range)
{
    size_t bits = 0;
    size_t values = 1;
    while (values < range)
    {
        values <<= 1U;
        ++bits;
    }
    return bits;
}

void WriteConstrained(BitWriter &writer, size_t value, size_t lower, size_t upper, bool aligned)
{
    if (value < lower || value > upper)
        throw CodecError("APER constrained value is out of range");
    size_t range = upper - lower + 1U;
    size_t bits = BitsForRange(range);
    size_t encoded = value - lower;
    if (aligned && range >= 256 && range <= 65536)
    {
        writer.align();
        size_t octets = (bits + 7U) / 8U;
        writer.writeBits(encoded, octets * 8U);
        writer.align();
    }
    else if (aligned && range > 65536)
    {
        const size_t maximumOctets = (bits + 7U) / 8U;
        size_t octets = 1;
        while (octets < maximumOctets && encoded >= (uint64_t{1} << (octets * 8U)))
            ++octets;
        WriteConstrained(writer, octets, 1, maximumOctets, false);
        writer.align();
        writer.writeBits(encoded, octets * 8U);
        writer.align();
    }
    else
        writer.writeBits(encoded, bits);
}

size_t ReadConstrained(BitReader &reader, size_t lower, size_t upper, bool aligned)
{
    size_t range = upper - lower + 1U;
    size_t bits = BitsForRange(range);
    uint64_t encoded;
    if (aligned && range >= 256 && range <= 65536)
    {
        reader.align();
        encoded = reader.readBits(((bits + 7U) / 8U) * 8U);
        reader.align();
    }
    else if (aligned && range > 65536)
    {
        const size_t maximumOctets = (bits + 7U) / 8U;
        const size_t octets = ReadConstrained(reader, 1, maximumOctets, false);
        reader.align();
        encoded = reader.readBits(octets * 8U);
        reader.align();
    }
    else
        encoded = reader.readBits(bits);
    if (encoded >= range)
        throw CodecError("Invalid APER constrained value");
    return static_cast<size_t>(encoded) + lower;
}

void WriteFixedOctets(BitWriter &writer, const uint8_t *data, size_t length)
{
    if (length > 2)
        writer.align();
    for (size_t i = 0; i < length; ++i)
        writer.writeBits(data[i], 8);
}

std::vector<uint8_t> ReadFixedOctets(BitReader &reader, size_t length)
{
    if (length > 2)
        reader.align();
    std::vector<uint8_t> result;
    result.reserve(length);
    for (size_t i = 0; i < length; ++i)
        result.push_back(static_cast<uint8_t>(reader.readBits(8)));
    return result;
}

std::vector<uint8_t> EncodePrintable(const std::string &value)
{
    if (value.empty() || value.size() > 150)
        throw CodecError("S1AP PrintableString length must be 1..150");
    if (!std::all_of(value.begin(), value.end(), [](unsigned char c) { return c >= 0x20 && c <= 0x7e; }))
        throw CodecError("S1AP name contains a non-printable character");
    BitWriter writer;
    writer.writeBit(false);
    WriteConstrained(writer, value.size(), 1, 150, true);
    writer.align();
    writer.writeBytes(reinterpret_cast<const uint8_t *>(value.data()), value.size());
    return writer.take();
}

std::string DecodePrintable(const std::vector<uint8_t> &data)
{
    BitReader reader(data);
    if (reader.readBit())
        throw CodecError("Extended S1AP PrintableString is not supported");
    size_t length = ReadConstrained(reader, 1, 150, true);
    auto bytes = reader.readBytes(length);
    reader.requireFinished();
    if (!std::all_of(bytes.begin(), bytes.end(), [](uint8_t c) { return c >= 0x20 && c <= 0x7e; }))
        throw CodecError("S1AP name contains a non-printable character");
    return std::string(bytes.begin(), bytes.end());
}

std::vector<uint8_t> EncodeGlobalEnbId(const EnbConfig &config)
{
    BitWriter writer;
    writer.writeBit(false); // SEQUENCE extension marker
    writer.writeBit(false); // iE-Extensions absent
    auto plmn = EncodePlmn(config.plmn);
    WriteFixedOctets(writer, plmn.data(), plmn.size());
    writer.writeBit(false); // ENB-ID CHOICE extension marker
    writer.writeBit(false); // macroENB-ID
    writer.align();
    writer.writeBits(config.enbId, 20);
    return writer.take();
}

std::vector<uint8_t> EncodeSupportedTas(const EnbConfig &config)
{
    BitWriter writer;
    WriteConstrained(writer, 1, 1, 256, true);
    writer.writeBit(false); // item extension marker
    writer.writeBit(false); // item iE-Extensions absent
    writer.writeBits(config.tac, 16);
    WriteConstrained(writer, 1, 1, 6, true);
    auto plmn = EncodePlmn(config.plmn);
    WriteFixedOctets(writer, plmn.data(), plmn.size());
    return writer.take();
}

std::vector<uint8_t> EncodePagingDrx(int value)
{
    int index = value == 32 ? 0 : value == 64 ? 1 : value == 128 ? 2 : value == 256 ? 3 : -1;
    if (index < 0)
        throw CodecError("Invalid DefaultPagingDRX value");
    BitWriter writer;
    writer.writeBit(false);
    writer.writeBits(static_cast<uint64_t>(index), 2);
    return writer.take();
}

void WriteIe(BitWriter &writer, uint16_t id, Criticality criticality, const std::vector<uint8_t> &value)
{
    WriteConstrained(writer, id, 0, 65535, true);
    writer.writeBits(static_cast<uint8_t>(criticality), 2);
    writer.align();
    writer.writeLength(value.size());
    writer.writeBytes(value);
}

struct Envelope
{
    uint8_t choice{};
    std::vector<uint8_t> value;
};

Envelope DecodeEnvelope(const uint8_t *data, size_t length, uint16_t expectedProcedure, int expectedCriticality)
{
    if (data == nullptr || length == 0)
        throw CodecError("Empty S1AP PDU");
    BitReader reader(data, length);
    if (reader.readBit())
        throw CodecError("Extended S1AP PDU choice is not supported");
    uint8_t choice = static_cast<uint8_t>(reader.readBits(2));
    if (choice > 2)
        throw CodecError("Invalid S1AP PDU choice");
    reader.align();
    auto procedure = ReadConstrained(reader, 0, 255, true);
    if (procedure != expectedProcedure)
        throw CodecError("Unexpected S1AP procedure code " + std::to_string(procedure) + " (expected " +
                         std::to_string(expectedProcedure) + ")");
    auto criticality = reader.readBits(2);
    if (criticality > static_cast<uint8_t>(Criticality::NOTIFY))
        throw CodecError("Invalid S1AP procedure criticality");
    if (expectedCriticality >= 0 && criticality != static_cast<uint8_t>(expectedCriticality))
        throw CodecError("Unexpected S1AP procedure criticality");
    reader.align();
    auto value = reader.readOpenType();
    reader.requireFinished();
    return Envelope{choice, std::move(value)};
}

std::vector<uint8_t> EncodeTai(const EnbConfig &config)
{
    BitWriter writer;
    writer.writeBit(false); // extension marker
    writer.writeBit(false); // iE-Extensions absent
    auto plmn = EncodePlmn(config.plmn);
    WriteFixedOctets(writer, plmn.data(), plmn.size());
    writer.writeBits(config.tac, 16);
    return writer.take();
}

std::vector<uint8_t> EncodeEutranCgi(const EnbConfig &config)
{
    BitWriter writer;
    writer.writeBit(false); // extension marker
    writer.writeBit(false); // iE-Extensions absent
    auto plmn = EncodePlmn(config.plmn);
    WriteFixedOctets(writer, plmn.data(), plmn.size());
    // E-UTRAN Cell Identifier contains the 20-bit macro eNB identifier followed
    // by the 8-bit local cell identifier (zero for this one-cell simulator).
    writer.writeBits((config.enbId & 0xFFFFFU) << 8U, 28);
    return writer.take();
}

std::vector<uint8_t> EncodeUeId(uint32_t value, uint32_t maximum)
{
    BitWriter writer;
    WriteConstrained(writer, value, 0, maximum, true);
    return writer.take();
}

uint32_t DecodeUeId(const std::vector<uint8_t> &value, uint32_t maximum)
{
    BitReader reader(value);
    auto result = static_cast<uint32_t>(ReadConstrained(reader, 0, maximum, true));
    reader.requireFinished();
    return result;
}

std::vector<uint8_t> EncodeNasPdu(const std::vector<uint8_t> &nas)
{
    if (nas.empty() || nas.size() > 4096)
        throw CodecError("Invalid NAS-PDU length");
    BitWriter writer;
    writer.writeLength(nas.size());
    writer.writeBytes(nas);
    return writer.take();
}

std::vector<uint8_t> DecodeNasPdu(const std::vector<uint8_t> &value)
{
    BitReader reader(value);
    auto nas = reader.readBytes(reader.readLength());
    reader.requireFinished();
    if (nas.empty() || nas.size() > 4096)
        throw CodecError("Invalid NAS-PDU length");
    return nas;
}

std::vector<uint8_t> EncodeRrcEstablishmentCause()
{
    BitWriter writer;
    writer.writeBit(false); // root enumeration
    writer.writeBits(3, 3); // mo-Signalling
    return writer.take();
}

std::vector<uint8_t> EncodeUeMessage(uint16_t procedure, Criticality pduCriticality,
                                     const std::vector<std::pair<std::pair<uint16_t, Criticality>, std::vector<uint8_t>>> &ies)
{
    BitWriter message;
    message.writeBit(false); // SEQUENCE extension marker
    WriteConstrained(message, ies.size(), 0, 65535, true);
    for (const auto &ie : ies)
        WriteIe(message, ie.first.first, ie.first.second, ie.second);
    auto body = message.take();
    BitWriter pdu;
    pdu.writeBit(false); // S1AP-PDU CHOICE extension marker
    pdu.writeBits(0, 2); // initiatingMessage
    pdu.align();
    WriteConstrained(pdu, procedure, 0, 255, true);
    pdu.writeBits(static_cast<uint8_t>(pduCriticality), 2);
    pdu.align();
    pdu.writeLength(body.size());
    pdu.writeBytes(body);
    return pdu.take();
}

struct Ie
{
    uint16_t id{};
    Criticality criticality{};
    std::vector<uint8_t> value;
};

std::vector<Ie> DecodeIeContainer(const std::vector<uint8_t> &data)
{
    BitReader reader(data);
    if (reader.readBit())
        throw CodecError("Extended S1 Setup message is not supported");
    size_t count = ReadConstrained(reader, 0, 65535, true);
    std::vector<Ie> result;
    result.reserve(count);
    std::set<uint16_t> seen;
    for (size_t i = 0; i < count; ++i)
    {
        auto id = static_cast<uint16_t>(ReadConstrained(reader, 0, 65535, true));
        auto criticalityValue = reader.readBits(2);
        if (criticalityValue > 2)
            throw CodecError("Invalid S1AP IE criticality");
        reader.align();
        auto value = reader.readOpenType();
        if (!seen.insert(id).second)
            throw CodecError("Duplicate S1AP information element");
        result.push_back(Ie{id, static_cast<Criticality>(criticalityValue), std::move(value)});
    }
    reader.requireFinished();
    return result;
}

DecodedSetupRequest DecodeRequestIes(const std::vector<Ie> &ies)
{
    DecodedSetupRequest result{};
    bool globalPresent = false;
    bool tasPresent = false;
    bool drxPresent = false;
    for (const auto &ie : ies)
    {
        if (ie.id == IE_GLOBAL_ENB_ID)
        {
            if (ie.criticality != Criticality::REJECT)
                throw CodecError("Global-ENB-ID has invalid criticality");
            BitReader reader(ie.value);
            if (reader.readBit() || reader.readBit())
                throw CodecError("Unsupported Global-ENB-ID extension");
            auto plmn = ReadFixedOctets(reader, 3);
            result.plmn = DecodePlmn(plmn.data(), plmn.size());
            if (reader.readBit() || reader.readBit())
                throw CodecError("Only macroENB-ID is supported");
            reader.align();
            result.enbId = static_cast<uint32_t>(reader.readBits(20));
            reader.requireFinished();
            globalPresent = true;
        }
        else if (ie.id == IE_ENB_NAME)
        {
            if (ie.criticality != Criticality::IGNORE)
                throw CodecError("ENBname has invalid criticality");
            result.enbName = DecodePrintable(ie.value);
        }
        else if (ie.id == IE_SUPPORTED_TAS)
        {
            if (ie.criticality != Criticality::REJECT)
                throw CodecError("SupportedTAs has invalid criticality");
            BitReader reader(ie.value);
            size_t taCount = ReadConstrained(reader, 1, 256, true);
            if (taCount != 1)
                throw CodecError("This LTE eNB expects exactly one supported TA");
            if (reader.readBit() || reader.readBit())
                throw CodecError("Unsupported SupportedTAs extension");
            result.tac = static_cast<uint16_t>(reader.readBits(16));
            size_t plmnCount = ReadConstrained(reader, 1, 6, true);
            for (size_t i = 0; i < plmnCount; ++i)
            {
                auto bytes = ReadFixedOctets(reader, 3);
                result.broadcastPlmns.push_back(DecodePlmn(bytes.data(), bytes.size()));
            }
            reader.requireFinished();
            tasPresent = true;
        }
        else if (ie.id == IE_DEFAULT_PAGING_DRX)
        {
            if (ie.criticality != Criticality::IGNORE)
                throw CodecError("DefaultPagingDRX has invalid criticality");
            BitReader reader(ie.value);
            if (reader.readBit())
                throw CodecError("Extended PagingDRX is not supported");
            int index = static_cast<int>(reader.readBits(2));
            result.pagingDrx = std::array<int, 4>{32, 64, 128, 256}[index];
            reader.requireFinished();
            drxPresent = true;
        }
        else if (ie.criticality == Criticality::REJECT)
            throw CodecError("Unknown reject-criticality IE in S1 Setup Request");
    }
    if (!globalPresent || !tasPresent || !drxPresent)
        throw CodecError("S1 Setup Request is missing mandatory information");
    return result;
}

ServedGummei DecodeServedGummeiItem(BitReader &reader)
{
    ServedGummei result{};
    if (reader.readBit() || reader.readBit())
        throw CodecError("Unsupported ServedGUMMEIsItem extension");
    size_t plmnCount = ReadConstrained(reader, 1, 32, true);
    for (size_t i = 0; i < plmnCount; ++i)
    {
        auto bytes = ReadFixedOctets(reader, 3);
        result.plmns.push_back(DecodePlmn(bytes.data(), bytes.size()));
    }
    size_t groupCount = ReadConstrained(reader, 1, 65535, true);
    result.groupIds.reserve(groupCount);
    for (size_t i = 0; i < groupCount; ++i)
        result.groupIds.push_back(static_cast<uint16_t>(reader.readBits(16)));
    size_t codeCount = ReadConstrained(reader, 1, 256, true);
    result.mmeCodes.reserve(codeCount);
    for (size_t i = 0; i < codeCount; ++i)
        result.mmeCodes.push_back(static_cast<uint8_t>(reader.readBits(8)));
    return result;
}

std::vector<ServedGummei> DecodeServedGummeis(const std::vector<uint8_t> &data)
{
    BitReader reader(data);
    size_t count = ReadConstrained(reader, 1, 8, true);
    std::vector<ServedGummei> result;
    result.reserve(count);
    for (size_t i = 0; i < count; ++i)
        result.push_back(DecodeServedGummeiItem(reader));
    reader.requireFinished();
    return result;
}

int ReadExtensibleEnum(BitReader &reader, size_t rootCount)
{
    if (!reader.readBit())
    {
        auto value = static_cast<int>(reader.readBits(BitsForRange(rootCount)));
        if (value >= static_cast<int>(rootCount))
            throw CodecError("Invalid root enumeration value");
        return value;
    }
    if (reader.readBit())
        throw CodecError("Large extension enumeration is not supported");
    return static_cast<int>(rootCount + reader.readBits(6));
}

std::string CauseText(const std::string &category, int value)
{
    static const std::array<const char *, 2> transport = {"transport-resource-unavailable", "unspecified"};
    static const std::array<const char *, 4> nas = {"normal-release", "authentication-failure", "detach",
                                                    "unspecified"};
    static const std::array<const char *, 7> protocol = {"transfer-syntax-error",
                                                         "abstract-syntax-error-reject",
                                                         "abstract-syntax-error-ignore-and-notify",
                                                         "message-not-compatible-with-receiver-state",
                                                         "semantic-error",
                                                         "abstract-syntax-error-falsely-constructed-message",
                                                         "unspecified"};
    static const std::array<const char *, 6> misc = {"control-processing-overload",
                                                     "not-enough-user-plane-processing-resources",
                                                     "hardware-failure",
                                                     "om-intervention",
                                                     "unspecified",
                                                     "unknown-PLMN"};
    if (category == "transport" && value < static_cast<int>(transport.size()))
        return transport[value];
    if (category == "nas" && value < static_cast<int>(nas.size()))
        return nas[value];
    if (category == "protocol" && value < static_cast<int>(protocol.size()))
        return protocol[value];
    if (category == "misc" && value < static_cast<int>(misc.size()))
        return misc[value];
    if (category == "radioNetwork" && value == 0)
        return "unspecified";
    return "value-" + std::to_string(value);
}

void DecodeCause(const std::vector<uint8_t> &data, SetupOutcome &result)
{
    BitReader reader(data);
    if (reader.readBit())
        throw CodecError("Extended S1AP Cause category is not supported");
    int category = static_cast<int>(reader.readBits(3));
    static const std::array<const char *, 5> names = {"radioNetwork", "transport", "nas", "protocol", "misc"};
    static const std::array<size_t, 5> counts = {36, 2, 4, 7, 6};
    if (category < 0 || category >= static_cast<int>(names.size()))
        throw CodecError("Invalid S1AP Cause category");
    result.causeCategory = names[category];
    result.causeValue = ReadExtensibleEnum(reader, counts[category]);
    result.causeText = CauseText(result.causeCategory, result.causeValue);
    reader.requireFinished();
}

// BitRate ::= INTEGER (0..10000000000): 34-bit large-range constrained whole number.
void WriteBitRate(BitWriter &writer, uint64_t value)
{
    if (value > 10000000000ULL)
        throw CodecError("S1AP BitRate is out of range");
    WriteConstrained(writer, static_cast<size_t>(value), 0, 10000000000ULL, true);
}

uint64_t ReadBitRate(BitReader &reader)
{
    return static_cast<uint64_t>(ReadConstrained(reader, 0, 10000000000ULL, true));
}

// E-RAB-ID ::= INTEGER (0..15,...): extension marker plus a 4-bit root value.
void WriteErabId(BitWriter &writer, uint8_t erabId)
{
    if (erabId > 15)
        throw CodecError("E-RAB-ID is out of the root range");
    writer.writeBit(false);
    writer.writeBits(erabId, 4);
}

uint8_t ReadErabId(BitReader &reader)
{
    if (reader.readBit())
        throw CodecError("Extended E-RAB-ID is not supported");
    return static_cast<uint8_t>(reader.readBits(4));
}

// TransportLayerAddress ::= BIT STRING (SIZE(1..160,...)). IPv4 is 32 bits.
void WriteTransportLayerAddress(BitWriter &writer, const std::array<uint8_t, 4> &address)
{
    writer.writeBit(false); // size within the extension root
    WriteConstrained(writer, 32, 1, 160, true);
    writer.align();
    writer.writeBytes(address.data(), address.size());
}

std::array<uint8_t, 4> ReadTransportLayerAddress(BitReader &reader)
{
    if (reader.readBit())
        throw CodecError("Extended TransportLayerAddress size is not supported");
    size_t lengthBits = ReadConstrained(reader, 1, 160, true);
    if (lengthBits != 32)
        throw CodecError("Only IPv4 TransportLayerAddress is supported");
    auto bytes = reader.readBytes(4);
    std::array<uint8_t, 4> result{};
    std::copy(bytes.begin(), bytes.end(), result.begin());
    return result;
}

// SecurityKey ::= BIT STRING (SIZE(256)): fixed 32 octets after octet alignment.
void WriteSecurityKey(BitWriter &writer, const std::array<uint8_t, 32> &key)
{
    writer.align();
    writer.writeBytes(key.data(), key.size());
}

std::array<uint8_t, 32> ReadSecurityKey(BitReader &reader)
{
    auto bytes = reader.readBytes(32);
    std::array<uint8_t, 32> result{};
    std::copy(bytes.begin(), bytes.end(), result.begin());
    return result;
}

// UESecurityCapabilities ::= SEQUENCE of two BIT STRING (SIZE(16,...)).
void WriteUeSecurityCapabilities(BitWriter &writer, const std::array<uint8_t, 2> &encryption,
                                 const std::array<uint8_t, 2> &integrity)
{
    writer.writeBit(false); // SEQUENCE extension marker
    writer.writeBit(false); // iE-Extensions absent
    writer.writeBit(false); // encryptionAlgorithms size within the root
    writer.writeBits((static_cast<uint64_t>(encryption[0]) << 8U) | encryption[1], 16);
    writer.writeBit(false); // integrityProtectionAlgorithms size within the root
    writer.writeBits((static_cast<uint64_t>(integrity[0]) << 8U) | integrity[1], 16);
}

void ReadUeSecurityCapabilities(BitReader &reader, std::array<uint8_t, 2> &encryption,
                                std::array<uint8_t, 2> &integrity)
{
    if (reader.readBit())
        throw CodecError("Extended UESecurityCapabilities is not supported");
    if (reader.readBit())
        throw CodecError("UESecurityCapabilities extensions are not supported");
    if (reader.readBit())
        throw CodecError("Extended EncryptionAlgorithms size is not supported");
    uint64_t eea = reader.readBits(16);
    if (reader.readBit())
        throw CodecError("Extended IntegrityProtectionAlgorithms size is not supported");
    uint64_t eia = reader.readBits(16);
    encryption = {static_cast<uint8_t>(eea >> 8U), static_cast<uint8_t>(eea & 0xFFU)};
    integrity = {static_cast<uint8_t>(eia >> 8U), static_cast<uint8_t>(eia & 0xFFU)};
}

// AllocationAndRetentionPriority with the non-extensible ARP enumerations.
void WriteArp(BitWriter &writer, uint8_t priorityLevel, bool preemptionCapability, bool preemptionVulnerability)
{
    if (priorityLevel > 15)
        throw CodecError("PriorityLevel is out of range");
    writer.writeBit(false); // SEQUENCE extension marker
    writer.writeBit(false); // iE-Extensions absent
    writer.writeBits(priorityLevel, 4);
    writer.writeBit(preemptionCapability);
    writer.writeBit(preemptionVulnerability);
}

void ReadArp(BitReader &reader, ErabToBeSetupItem &item)
{
    if (reader.readBit() || reader.readBit())
        throw CodecError("Unsupported AllocationAndRetentionPriority extension");
    item.priorityLevel = static_cast<uint8_t>(reader.readBits(4));
    item.preemptionCapability = reader.readBit();
    item.preemptionVulnerability = reader.readBit();
}

void WriteErabLevelQos(BitWriter &writer, uint8_t qci, uint8_t priorityLevel, bool preemptionCapability,
                       bool preemptionVulnerability, const std::optional<GbrQos> &gbr = std::nullopt)
{
    writer.writeBit(false); // SEQUENCE extension marker
    writer.writeBit(gbr.has_value());
    writer.writeBit(false); // iE-Extensions absent
    WriteConstrained(writer, qci, 0, 255, true);
    WriteArp(writer, priorityLevel, preemptionCapability, preemptionVulnerability);
    if (gbr)
    {
        writer.writeBit(false); // GBR sequence extension
        writer.writeBit(false); // GBR IE extensions absent
        WriteBitRate(writer, gbr->maximumDl);
        WriteBitRate(writer, gbr->maximumUl);
        WriteBitRate(writer, gbr->guaranteedDl);
        WriteBitRate(writer, gbr->guaranteedUl);
    }
}

void ReadErabLevelQos(BitReader &reader, ErabToBeSetupItem &item)
{
    if (reader.readBit())
        throw CodecError("Extended E-RABLevelQoSParameters is not supported");
    bool gbrPresent = reader.readBit();
    bool extensionsPresent = reader.readBit();
    item.qci = static_cast<uint8_t>(ReadConstrained(reader, 0, 255, true));
    ReadArp(reader, item);
    if (gbrPresent)
    {
        if (reader.readBit() || reader.readBit())
            throw CodecError("Extended GBR-QosInformation is not supported");
        item.gbr = GbrQos{ReadBitRate(reader), ReadBitRate(reader), ReadBitRate(reader), ReadBitRate(reader)};
    }
    if (extensionsPresent)
        throw CodecError("E-RABLevelQoSParameters extensions are not supported");
}

ErabToBeSetupItem ReadErabToBeSetupItem(BitReader &reader)
{
    ErabToBeSetupItem item{};
    // APER SEQUENCE: extension marker, then the OPTIONAL presence bits in
    // field order (nAS-PDU, iE-Extensions), then the fields themselves.
    if (reader.readBit())
        throw CodecError("Extended E-RABToBeSetupItemCtxtSUReq is not supported");
    const bool nasPduPresent = reader.readBit();
    const bool extensionsPresent = reader.readBit();
    item.erabId = ReadErabId(reader);
    ReadErabLevelQos(reader, item);
    if (reader.readBit())
        throw CodecError("Extended transport address size is not supported");
    const auto addressBits = ReadConstrained(reader, 1, 160, true);
    reader.align();
    item.ipv4Transport = addressBits == 32;
    for (size_t bit = 0; bit < addressBits; ++bit)
    {
        const bool value = reader.readBit();
        if (item.ipv4Transport)
            item.transportLayerAddress[bit / 8] |= static_cast<uint8_t>(value << (7 - bit % 8));
    }
    reader.align();
    {
        auto teid = ReadFixedOctets(reader, 4);
        std::copy(teid.begin(), teid.end(), item.gtpTeid.begin());
    }
    item.nasPduPresent = nasPduPresent;
    if (nasPduPresent)
        item.nasPdu = reader.readBytes(reader.readLength());
    if (extensionsPresent)
        throw CodecError("E-RABToBeSetupItemCtxtSUReq extensions are not supported");
    return item;
}

// E-RABToBeSetupItemBearerSUReq carries a mandatory nAS-PDU, unlike the
// CtxtSUReq variant whose nAS-PDU is OPTIONAL. Reading it with the CtxtSUReq
// layout consumes one bit too many and shifts every following field, so the two
// shapes must not share a decoder.
ErabToBeSetupItem ReadErabToBeSetupItemBearerSUReq(BitReader &reader)
{
    ErabToBeSetupItem item{};
    if (reader.readBit())
        throw CodecError("Extended E-RABToBeSetupItemBearerSUReq is not supported");
    const bool extensionsPresent = reader.readBit();
    item.erabId = ReadErabId(reader);
    ReadErabLevelQos(reader, item);
    item.transportLayerAddress = ReadTransportLayerAddress(reader);
    {
        auto teid = ReadFixedOctets(reader, 4);
        std::copy(teid.begin(), teid.end(), item.gtpTeid.begin());
    }
    item.nasPduPresent = true;
    item.nasPdu = reader.readBytes(reader.readLength());
    if (extensionsPresent)
        throw CodecError("E-RABToBeSetupItemBearerSUReq extensions are not supported");
    return item;
}

std::vector<uint8_t> EncodeErabToBeSetupItemBearerSUReq(const ErabToBeSetupItem &item)
{
    BitWriter writer;
    writer.writeBit(false); // SEQUENCE extension marker
    writer.writeBit(false); // iE-Extensions absent
    WriteErabId(writer, item.erabId);
    WriteErabLevelQos(writer, item.qci, item.priorityLevel, item.preemptionCapability, item.preemptionVulnerability,
                      item.gbr);
    WriteTransportLayerAddress(writer, item.transportLayerAddress);
    WriteFixedOctets(writer, item.gtpTeid.data(), item.gtpTeid.size());
    writer.writeLength(item.nasPdu.size());
    writer.writeBytes(item.nasPdu);
    return writer.take();
}

std::vector<uint8_t> EncodeErabSetupItem(const ErabSetupItem &item)
{
    BitWriter writer;
    writer.writeBit(false); // SEQUENCE extension marker
    writer.writeBit(false); // iE-Extensions absent
    WriteErabId(writer, item.erabId);
    WriteTransportLayerAddress(writer, item.transportLayerAddress);
    WriteFixedOctets(writer, item.gtpTeid.data(), item.gtpTeid.size());
    return writer.take();
}

std::vector<uint8_t> EncodePdu(uint8_t choice, uint16_t procedure, Criticality pduCriticality,
                               const std::vector<std::pair<std::pair<uint16_t, Criticality>, std::vector<uint8_t>>> &ies)
{
    BitWriter message;
    message.writeBit(false); // SEQUENCE extension marker
    WriteConstrained(message, ies.size(), 0, 65535, true);
    for (const auto &ie : ies)
        WriteIe(message, ie.first.first, ie.first.second, ie.second);
    auto body = message.take();
    BitWriter pdu;
    pdu.writeBit(false); // S1AP-PDU CHOICE extension marker
    pdu.writeBits(choice, 2);
    pdu.align();
    WriteConstrained(pdu, procedure, 0, 255, true);
    pdu.writeBits(static_cast<uint8_t>(pduCriticality), 2);
    pdu.align();
    pdu.writeLength(body.size());
    pdu.writeBytes(body);
    return pdu.take();
}

} // namespace

std::array<uint8_t, 3> EncodePlmn(const Plmn &plmn)
{
    if (plmn.mcc.size() != 3 || (plmn.mnc.size() != 2 && plmn.mnc.size() != 3))
        throw CodecError("PLMN requires a three-digit MCC and a two- or three-digit MNC");
    auto digit = [](char c) -> uint8_t {
        if (c < '0' || c > '9')
            throw CodecError("PLMN contains a non-decimal digit");
        return static_cast<uint8_t>(c - '0');
    };
    uint8_t mnc3 = plmn.mnc.size() == 3 ? digit(plmn.mnc[2]) : 0x0F;
    return {static_cast<uint8_t>((digit(plmn.mcc[1]) << 4U) | digit(plmn.mcc[0])),
            static_cast<uint8_t>((mnc3 << 4U) | digit(plmn.mcc[2])),
            static_cast<uint8_t>((digit(plmn.mnc[1]) << 4U) | digit(plmn.mnc[0]))};
}

Plmn DecodePlmn(const uint8_t *data, size_t length)
{
    if (data == nullptr || length != 3)
        throw CodecError("PLMN identity must contain three octets");
    std::array<uint8_t, 6> digits = {static_cast<uint8_t>(data[0] & 0x0F), static_cast<uint8_t>(data[0] >> 4U),
                                     static_cast<uint8_t>(data[1] & 0x0F), static_cast<uint8_t>(data[2] & 0x0F),
                                     static_cast<uint8_t>(data[2] >> 4U),  static_cast<uint8_t>(data[1] >> 4U)};
    for (size_t i = 0; i < 5; ++i)
        if (digits[i] > 9)
            throw CodecError("PLMN identity contains an invalid BCD digit");
    if (digits[5] > 9 && digits[5] != 0x0F)
        throw CodecError("PLMN identity contains an invalid MNC digit");
    Plmn result;
    result.mcc = std::string{static_cast<char>('0' + digits[0]), static_cast<char>('0' + digits[1]),
                             static_cast<char>('0' + digits[2])};
    result.mnc = std::string{static_cast<char>('0' + digits[3]), static_cast<char>('0' + digits[4])};
    if (digits[5] != 0x0F)
        result.mnc.push_back(static_cast<char>('0' + digits[5]));
    return result;
}

std::vector<uint8_t> EncodeS1SetupRequest(const EnbConfig &config)
{
    std::vector<std::pair<std::pair<uint16_t, Criticality>, std::vector<uint8_t>>> ies;
    ies.push_back({{IE_GLOBAL_ENB_ID, Criticality::REJECT}, EncodeGlobalEnbId(config)});
    if (config.enbName.has_value())
        ies.push_back({{IE_ENB_NAME, Criticality::IGNORE}, EncodePrintable(*config.enbName)});
    ies.push_back({{IE_SUPPORTED_TAS, Criticality::REJECT}, EncodeSupportedTas(config)});
    ies.push_back({{IE_DEFAULT_PAGING_DRX, Criticality::IGNORE}, EncodePagingDrx(config.pagingDrx)});

    BitWriter message;
    message.writeBit(false); // S1SetupRequest SEQUENCE extension marker
    WriteConstrained(message, ies.size(), 0, 65535, true);
    for (const auto &ie : ies)
        WriteIe(message, ie.first.first, ie.first.second, ie.second);
    auto messageBytes = message.take();

    BitWriter pdu;
    pdu.writeBit(false); // S1AP-PDU CHOICE extension marker
    pdu.writeBits(0, 2); // initiatingMessage
    pdu.align();
    WriteConstrained(pdu, PROCEDURE_S1_SETUP, 0, 255, true);
    pdu.writeBits(static_cast<uint8_t>(Criticality::REJECT), 2);
    pdu.align();
    pdu.writeLength(messageBytes.size());
    pdu.writeBytes(messageBytes);
    return pdu.take();
}

DecodedSetupRequest DecodeS1SetupRequest(const uint8_t *data, size_t length)
{
    auto envelope = DecodeEnvelope(data, length, PROCEDURE_S1_SETUP, static_cast<int>(Criticality::REJECT));
    if (envelope.choice != 0)
        throw CodecError("S1AP PDU is not an initiating message");
    return DecodeRequestIes(DecodeIeContainer(envelope.value));
}

SetupOutcome DecodeS1SetupOutcome(const uint8_t *data, size_t length)
{
    auto envelope = DecodeEnvelope(data, length, PROCEDURE_S1_SETUP, static_cast<int>(Criticality::REJECT));
    if (envelope.choice != 1 && envelope.choice != 2)
        throw CodecError("S1AP PDU is not an S1 Setup outcome");
    auto ies = DecodeIeContainer(envelope.value);
    SetupOutcome result{};
    result.type = envelope.choice == 1 ? OutcomeType::RESPONSE : OutcomeType::FAILURE;
    bool servedPresent = false;
    bool capacityPresent = false;
    bool causePresent = false;

    for (const auto &ie : ies)
    {
        if (result.type == OutcomeType::RESPONSE && ie.id == IE_MME_NAME)
        {
            if (ie.criticality != Criticality::IGNORE)
                throw CodecError("MMEname has invalid criticality");
            result.mmeName = DecodePrintable(ie.value);
        }
        else if (result.type == OutcomeType::RESPONSE && ie.id == IE_SERVED_GUMMEIS)
        {
            if (ie.criticality != Criticality::REJECT)
                throw CodecError("ServedGUMMEIs has invalid criticality");
            result.servedGummeis = DecodeServedGummeis(ie.value);
            servedPresent = true;
        }
        else if (result.type == OutcomeType::RESPONSE && ie.id == IE_RELATIVE_MME_CAPACITY)
        {
            if (ie.criticality != Criticality::IGNORE)
                throw CodecError("RelativeMMECapacity has invalid criticality");
            BitReader reader(ie.value);
            result.relativeMmeCapacity = static_cast<uint8_t>(reader.readBits(8));
            reader.requireFinished();
            capacityPresent = true;
        }
        else if (result.type == OutcomeType::FAILURE && ie.id == IE_CAUSE)
        {
            if (ie.criticality != Criticality::IGNORE)
                throw CodecError("Cause has invalid criticality");
            DecodeCause(ie.value, result);
            causePresent = true;
        }
        else if (result.type == OutcomeType::FAILURE && ie.id == IE_TIME_TO_WAIT)
        {
            if (ie.criticality != Criticality::IGNORE)
                throw CodecError("TimeToWait has invalid criticality");
            BitReader reader(ie.value);
            int index = ReadExtensibleEnum(reader, 6);
            reader.requireFinished();
            if (index >= 0 && index < 6)
                result.timeToWaitSeconds = std::array<int, 6>{1, 2, 5, 10, 20, 60}[index];
        }
        else if (ie.id == IE_CRITICALITY_DIAGNOSTICS)
        {
            if (ie.criticality != Criticality::IGNORE)
                throw CodecError("CriticalityDiagnostics has invalid criticality");
            result.diagnosticsPresent = true;
        }
        else if (ie.criticality == Criticality::REJECT)
            throw CodecError("Unknown reject-criticality IE in S1 Setup outcome");
    }

    if (result.type == OutcomeType::RESPONSE && (!servedPresent || !capacityPresent))
        throw CodecError("S1 Setup Response is missing mandatory information");
    if (result.type == OutcomeType::FAILURE && !causePresent)
        throw CodecError("S1 Setup Failure is missing the mandatory Cause");
    return result;
}

std::vector<uint8_t> EncodeInitialUeMessage(const EnbConfig &config, uint32_t enbUeS1apId,
                                            const std::vector<uint8_t> &nasPdu, std::optional<STmsi> sTmsi)
{
    if (enbUeS1apId == 0 || enbUeS1apId > 0xFFFFFFU)
        throw CodecError("eNB-UE-S1AP-ID is out of range");
    std::vector<std::pair<std::pair<uint16_t, Criticality>, std::vector<uint8_t>>> ies;
    ies.push_back({{IE_ENB_UE_S1AP_ID, Criticality::REJECT}, EncodeUeId(enbUeS1apId, 0xFFFFFFU)});
    ies.push_back({{IE_NAS_PDU, Criticality::REJECT}, EncodeNasPdu(nasPdu)});
    ies.push_back({{IE_TAI, Criticality::REJECT}, EncodeTai(config)});
    ies.push_back({{IE_EUTRAN_CGI, Criticality::IGNORE}, EncodeEutranCgi(config)});
    ies.push_back({{IE_RRC_ESTABLISHMENT_CAUSE, Criticality::IGNORE}, EncodeRrcEstablishmentCause()});
    if (sTmsi.has_value())
    {
        if (sTmsi->mTmsi == 0) throw CodecError("S-TMSI has an invalid M-TMSI");
        BitWriter value;
        value.writeBit(false);
        value.writeBit(false);
        value.writeBits(sTmsi->mmeCode, 8);
        // X.691 aligned PER: the one-octet MMEC follows the SEQUENCE
        // preamble bit-packed, while the fixed four-octet M-TMSI starts on
        // the next octet boundary.
        value.align();
        value.writeBits(sTmsi->mTmsi, 32);
        ies.push_back({{IE_S_TMSI, Criticality::REJECT}, value.take()});
    }
    return EncodeUeMessage(PROCEDURE_INITIAL_UE_MESSAGE, Criticality::IGNORE, ies);
}

std::vector<uint8_t> EncodeUplinkNasTransport(const EnbConfig &config, const UeContext &context,
                                              const std::vector<uint8_t> &nasPdu)
{
    if (context.enbUeS1apId == 0 || context.enbUeS1apId > 0xFFFFFFU || !context.mmeUeS1apId.has_value())
        throw CodecError("Uplink NAS Transport has no complete UE S1AP context");
    std::vector<std::pair<std::pair<uint16_t, Criticality>, std::vector<uint8_t>>> ies;
    ies.push_back({{IE_MME_UE_S1AP_ID, Criticality::REJECT}, EncodeUeId(*context.mmeUeS1apId, 0xFFFFFFFFU)});
    ies.push_back({{IE_ENB_UE_S1AP_ID, Criticality::REJECT}, EncodeUeId(context.enbUeS1apId, 0xFFFFFFU)});
    ies.push_back({{IE_NAS_PDU, Criticality::REJECT}, EncodeNasPdu(nasPdu)});
    ies.push_back({{IE_EUTRAN_CGI, Criticality::IGNORE}, EncodeEutranCgi(config)});
    ies.push_back({{IE_TAI, Criticality::IGNORE}, EncodeTai(config)});
    return EncodeUeMessage(PROCEDURE_UPLINK_NAS_TRANSPORT, Criticality::IGNORE, ies);
}

DownlinkNasTransport DecodeDownlinkNasTransport(const uint8_t *data, size_t length)
{
    auto envelope = DecodeEnvelope(data, length, PROCEDURE_DOWNLINK_NAS_TRANSPORT, static_cast<int>(Criticality::IGNORE));
    if (envelope.choice != 0)
        throw CodecError("Downlink NAS Transport is not an initiating message");
    DownlinkNasTransport result{};
    bool mmePresent = false;
    bool enbPresent = false;
    bool nasPresent = false;
    for (const auto &ie : DecodeIeContainer(envelope.value))
    {
        if (ie.id == IE_MME_UE_S1AP_ID)
        {
            if (ie.criticality != Criticality::REJECT) throw CodecError("MME-UE-S1AP-ID has invalid criticality");
            result.mmeUeS1apId = DecodeUeId(ie.value, 0xFFFFFFFFU);
            mmePresent = true;
        }
        else if (ie.id == IE_ENB_UE_S1AP_ID)
        {
            if (ie.criticality != Criticality::REJECT) throw CodecError("eNB-UE-S1AP-ID has invalid criticality");
            result.enbUeS1apId = DecodeUeId(ie.value, 0xFFFFFFU);
            enbPresent = true;
        }
        else if (ie.id == IE_NAS_PDU)
        {
            if (ie.criticality != Criticality::REJECT) throw CodecError("NAS-PDU has invalid criticality");
            result.nasPdu = DecodeNasPdu(ie.value);
            nasPresent = true;
        }
        else if (ie.criticality == Criticality::REJECT)
            throw CodecError("Unknown reject-criticality IE in Downlink NAS Transport");
    }
    if (!mmePresent || !enbPresent || !nasPresent)
        throw CodecError("Downlink NAS Transport is missing a mandatory IE");
    return result;
}

std::vector<uint8_t> EncodeDownlinkNasTransport(uint32_t mmeUeS1apId, uint32_t enbUeS1apId,
                                                const std::vector<uint8_t> &nasPdu)
{
    if (mmeUeS1apId == 0 || enbUeS1apId == 0 || enbUeS1apId > 0xFFFFFFU || nasPdu.empty())
        throw CodecError("Downlink NAS Transport has no complete UE S1AP context");
    std::vector<std::pair<std::pair<uint16_t, Criticality>, std::vector<uint8_t>>> ies;
    ies.push_back({{IE_MME_UE_S1AP_ID, Criticality::REJECT}, EncodeUeId(mmeUeS1apId, 0xFFFFFFFFU)});
    ies.push_back({{IE_ENB_UE_S1AP_ID, Criticality::REJECT}, EncodeUeId(enbUeS1apId, 0xFFFFFFU)});
    ies.push_back({{IE_NAS_PDU, Criticality::REJECT}, EncodeNasPdu(nasPdu)});
    return EncodeUeMessage(PROCEDURE_DOWNLINK_NAS_TRANSPORT, Criticality::IGNORE, ies);
}

UplinkNas DecodeUplinkNas(const uint8_t *data, size_t length)
{
    // Which of the two messages this is decides only which identifiers are
    // mandatory. The NAS payload is the same octet string in both, and neither
    // is interpreted here.
    const S1apPdu probe = ProbeS1apPdu(data, length);
    if (probe.kind != S1apPdu::Kind::INITIATING)
        throw CodecError("an uplink NAS message is not an initiating message");
    if (probe.procedureCode != PROCEDURE_INITIAL_UE_MESSAGE && probe.procedureCode != PROCEDURE_UPLINK_NAS_TRANSPORT)
        throw CodecError("this message does not carry a UE's NAS uplink");
    const bool initial = probe.procedureCode == PROCEDURE_INITIAL_UE_MESSAGE;
    auto envelope = DecodeEnvelope(data, length, probe.procedureCode, static_cast<int>(Criticality::IGNORE));
    if (envelope.choice != 0)
        throw CodecError("an uplink NAS message is not an initiating message");

    UplinkNas result{};
    bool enbPresent = false;
    bool nasPresent = false;
    for (const auto &ie : DecodeIeContainer(envelope.value))
    {
        if (ie.id == IE_MME_UE_S1AP_ID)
        {
            // An Initial UE Message carries none: it is what names the UE to
            // the MME in the first place. One appearing there is a message that
            // does not match the procedure it was sent under.
            if (initial)
                throw CodecError("an Initial UE Message carries no MME-UE-S1AP-ID");
            if (ie.criticality != Criticality::REJECT) throw CodecError("MME-UE-S1AP-ID has invalid criticality");
            result.mmeUeS1apId = DecodeUeId(ie.value, 0xFFFFFFFFU);
        }
        else if (ie.id == IE_ENB_UE_S1AP_ID)
        {
            if (ie.criticality != Criticality::REJECT) throw CodecError("eNB-UE-S1AP-ID has invalid criticality");
            result.enbUeS1apId = DecodeUeId(ie.value, 0xFFFFFFU);
            enbPresent = true;
        }
        else if (ie.id == IE_NAS_PDU)
        {
            if (ie.criticality != Criticality::REJECT) throw CodecError("NAS-PDU has invalid criticality");
            result.nasPdu = DecodeNasPdu(ie.value);
            nasPresent = true;
        }
        // Beyond those, each procedure carries a fixed, named set of IEs that
        // say where the message came from and not what the UE said. TS 36.413
        // states every one of them and its criticality, and the encoders above
        // emit exactly that, so they are read and dropped here. This function
        // answers for the NAS payload and the UE it belongs to, not for a
        // conformance verdict on the message around it; anything a receiver
        // must reject is still rejected.
        else if (ie.id == IE_TAI)
        {
            // Reject in an Initial UE Message (§9.1.7.1), ignore in an Uplink
            // NAS Transport (§9.1.3.2).
            const Criticality expected = initial ? Criticality::REJECT : Criticality::IGNORE;
            if (ie.criticality != expected) throw CodecError("TAI has invalid criticality");
        }
        else if (ie.id == IE_EUTRAN_CGI)
        {
            if (ie.criticality != Criticality::IGNORE) throw CodecError("E-UTRAN CGI has invalid criticality");
        }
        else if (ie.id == IE_RRC_ESTABLISHMENT_CAUSE)
        {
            if (!initial) throw CodecError("an Uplink NAS Transport carries no RRC Establishment Cause");
            if (ie.criticality != Criticality::IGNORE) throw CodecError("RRC Establishment Cause has invalid criticality");
        }
        else if (ie.id == IE_S_TMSI)
        {
            if (!initial) throw CodecError("an Uplink NAS Transport carries no S-TMSI");
            if (ie.criticality != Criticality::REJECT) throw CodecError("S-TMSI has invalid criticality");
        }
        else if (ie.criticality == Criticality::REJECT)
            throw CodecError("Unknown reject-criticality IE in an uplink NAS message");
    }
    if (!enbPresent || !nasPresent)
        throw CodecError("an uplink NAS message is missing a mandatory IE");
    if (!initial && !result.mmeUeS1apId.has_value())
        throw CodecError("Uplink NAS Transport is missing MME-UE-S1AP-ID");
    return result;
}

S1apPdu ProbeS1apPdu(const uint8_t *data, size_t length)
{
    if (data == nullptr || length == 0)
        throw CodecError("Empty S1AP PDU");
    BitReader reader(data, length);
    if (reader.readBit())
        throw CodecError("Extended S1AP PDU choice is not supported");
    uint8_t choice = static_cast<uint8_t>(reader.readBits(2));
    if (choice > 2)
        throw CodecError("Invalid S1AP PDU choice");
    reader.align();
    auto procedure = static_cast<uint16_t>(ReadConstrained(reader, 0, 255, true));
    S1apPdu result{};
    result.kind = choice == 0 ? S1apPdu::Kind::INITIATING
                             : (choice == 1 ? S1apPdu::Kind::SUCCESSFUL_OUTCOME : S1apPdu::Kind::UNSUCCESSFUL_OUTCOME);
    result.procedureCode = procedure;
    return result;
}

InitialContextSetupRequest DecodeInitialContextSetupRequest(const uint8_t *data, size_t length)
{
    auto envelope = DecodeEnvelope(data, length, PROCEDURE_INITIAL_CONTEXT_SETUP,
                                   static_cast<int>(Criticality::REJECT));
    if (envelope.choice != 0)
        throw CodecError("Initial Context Setup Request is not an initiating message");

    InitialContextSetupRequest result{};
    bool mmePresent = false;
    bool enbPresent = false;
    bool ambrPresent = false;
    bool erabsPresent = false;
    bool securityCapabilitiesPresent = false;
    bool securityKeyPresent = false;

    for (const auto &ie : DecodeIeContainer(envelope.value))
    {
        if (ie.id == IE_MME_UE_S1AP_ID)
        {
            if (ie.criticality != Criticality::REJECT)
                throw CodecError("MME-UE-S1AP-ID has invalid criticality");
            result.mmeUeS1apId = DecodeUeId(ie.value, 0xFFFFFFFFU);
            mmePresent = true;
        }
        else if (ie.id == IE_ENB_UE_S1AP_ID)
        {
            if (ie.criticality != Criticality::REJECT)
                throw CodecError("eNB-UE-S1AP-ID has invalid criticality");
            result.enbUeS1apId = DecodeUeId(ie.value, 0xFFFFFFU);
            enbPresent = true;
        }
        else if (ie.id == IE_UE_AGGREGATE_MAXIMUM_BITRATE)
        {
            if (ie.criticality != Criticality::REJECT)
                throw CodecError("UEAggregateMaximumBitrate has invalid criticality");
            BitReader reader(ie.value);
            if (reader.readBit() || reader.readBit())
                throw CodecError("Unsupported UEAggregateMaximumBitrate extension");
            result.ueAmbrDl = ReadBitRate(reader);
            result.ueAmbrUl = ReadBitRate(reader);
            reader.requireFinished();
            ambrPresent = true;
        }
        else if (ie.id == IE_E_RAB_TO_BE_SETUP_LIST_CTXT_SU_REQ)
        {
            if (ie.criticality != Criticality::REJECT)
                throw CodecError("E-RABToBeSetupListCtxtSUReq has invalid criticality");
            BitReader reader(ie.value);
            size_t count = ReadConstrained(reader, 1, 256, true);
            result.erabs.reserve(count);
            for (size_t i = 0; i < count; ++i)
            {
                auto id = static_cast<uint16_t>(ReadConstrained(reader, 0, 65535, true));
                if (id != IE_E_RAB_TO_BE_SETUP_ITEM_CTXT_SU_REQ)
                    throw CodecError("Unexpected E-RABToBeSetupListCtxtSUReq item identity");
                if (reader.readBits(2) != static_cast<uint8_t>(Criticality::REJECT))
                    throw CodecError("E-RAB setup item has invalid criticality");
                reader.align();
                auto value = reader.readOpenType();
                BitReader itemReader(value);
                result.erabs.push_back(ReadErabToBeSetupItem(itemReader));
                itemReader.requireFinished();
            }
            reader.requireFinished();
            erabsPresent = true;
        }
        else if (ie.id == IE_UE_SECURITY_CAPABILITIES)
        {
            if (ie.criticality != Criticality::REJECT)
                throw CodecError("UESecurityCapabilities has invalid criticality");
            BitReader reader(ie.value);
            ReadUeSecurityCapabilities(reader, result.encryptionAlgorithms, result.integrityAlgorithms);
            reader.requireFinished();
            securityCapabilitiesPresent = true;
        }
        else if (ie.id == IE_SECURITY_KEY)
        {
            if (ie.criticality != Criticality::REJECT)
                throw CodecError("SecurityKey has invalid criticality");
            BitReader reader(ie.value);
            result.securityKey = ReadSecurityKey(reader);
            reader.requireFinished();
            securityKeyPresent = true;
        }
        else if (ie.criticality == Criticality::REJECT)
            throw CodecError("Unknown reject-criticality IE in Initial Context Setup Request");
    }

    if (!mmePresent || !enbPresent || !ambrPresent || !erabsPresent || !securityCapabilitiesPresent ||
        !securityKeyPresent)
        throw CodecError("Initial Context Setup Request is missing a mandatory IE");
    if (result.mmeUeS1apId == 0 || result.enbUeS1apId == 0)
        throw CodecError("Initial Context Setup has a zero UE identity");
    if (result.erabs.empty())
        throw CodecError("Initial Context Setup Request contains no E-RAB to establish");
    return result;
}

std::vector<uint8_t> EncodeInitialContextSetupRequest(const InitialContextSetupRequest &request)
{
    if (request.erabs.empty() || request.erabs.size() > 256)
        throw CodecError("Initial Context Setup Request requires 1..256 E-RABs");
    if (request.mmeUeS1apId == 0 || request.enbUeS1apId == 0 || request.enbUeS1apId > 0xFFFFFFU)
        throw CodecError("Initial Context Setup Request has an invalid UE S1AP identity");

    BitWriter list;
    WriteConstrained(list, request.erabs.size(), 1, 256, true);
    for (const auto &erab : request.erabs)
    {
        BitWriter item;
        item.writeBit(false); // SEQUENCE extension marker
        item.writeBit(erab.nasPduPresent);
        item.writeBit(false); // iE-Extensions absent
        WriteErabId(item, erab.erabId);
        WriteErabLevelQos(item, erab.qci, erab.priorityLevel, erab.preemptionCapability, erab.preemptionVulnerability,
                          erab.gbr);
        WriteTransportLayerAddress(item, erab.transportLayerAddress);
        WriteFixedOctets(item, erab.gtpTeid.data(), erab.gtpTeid.size());
        if (erab.nasPduPresent)
        {
            item.writeLength(erab.nasPdu.size());
            item.writeBytes(erab.nasPdu);
        }
        WriteIe(list, IE_E_RAB_TO_BE_SETUP_ITEM_CTXT_SU_REQ, Criticality::REJECT, item.take());
    }
    auto listBytes = list.take();

    BitWriter ambr;
    ambr.writeBit(false); // SEQUENCE extension marker
    ambr.writeBit(false); // iE-Extensions absent
    WriteBitRate(ambr, request.ueAmbrDl);
    WriteBitRate(ambr, request.ueAmbrUl);

    BitWriter securityCapabilities;
    WriteUeSecurityCapabilities(securityCapabilities, request.encryptionAlgorithms, request.integrityAlgorithms);

    BitWriter securityKey;
    WriteSecurityKey(securityKey, request.securityKey);

    std::vector<std::pair<std::pair<uint16_t, Criticality>, std::vector<uint8_t>>> ies;
    ies.push_back({{IE_MME_UE_S1AP_ID, Criticality::REJECT}, EncodeUeId(request.mmeUeS1apId, 0xFFFFFFFFU)});
    ies.push_back({{IE_ENB_UE_S1AP_ID, Criticality::REJECT}, EncodeUeId(request.enbUeS1apId, 0xFFFFFFU)});
    ies.push_back({{IE_UE_AGGREGATE_MAXIMUM_BITRATE, Criticality::REJECT}, ambr.take()});
    ies.push_back({{IE_E_RAB_TO_BE_SETUP_LIST_CTXT_SU_REQ, Criticality::REJECT}, listBytes});
    ies.push_back({{IE_UE_SECURITY_CAPABILITIES, Criticality::REJECT}, securityCapabilities.take()});
    ies.push_back({{IE_SECURITY_KEY, Criticality::REJECT}, securityKey.take()});
    return EncodePdu(0, PROCEDURE_INITIAL_CONTEXT_SETUP, Criticality::REJECT, ies);
}

std::vector<uint8_t> EncodeInitialContextSetupResponse(uint32_t mmeUeS1apId, uint32_t enbUeS1apId,
                                                       const std::vector<ErabSetupItem> &erabs,
                                                       const std::vector<ErabFailedItem> &failed)
{
    if (mmeUeS1apId == 0 || enbUeS1apId == 0 || enbUeS1apId > 0xFFFFFFU)
        throw CodecError("Initial Context Setup Response has an invalid UE S1AP identity");
    if (erabs.empty() || erabs.size() > 256)
        throw CodecError("Initial Context Setup Response requires 1..256 established E-RABs");

    if (failed.size() > 256)
        throw CodecError("Too many failed E-RABs");
    std::set<uint8_t> seen;
    for (const auto &item : erabs)
        if (item.erabId < 5 || item.erabId > 15 || item.transportLayerAddress[0] == 0 ||
            item.transportLayerAddress[0] >= 224 || item.gtpTeid == std::array<uint8_t, 4>{} ||
            !seen.insert(item.erabId).second)
            throw CodecError("Invalid or repeated established EBI");
    for (const auto &item : failed)
        if (item.erabId > 15 || !seen.insert(item.erabId).second)
            throw CodecError("EBI occurs more than once across setup outcomes");
    BitWriter list;
    WriteConstrained(list, erabs.size(), 1, 256, true);
    for (const auto &item : erabs)
        WriteIe(list, IE_E_RAB_SETUP_ITEM_CTXT_SU_RES, Criticality::IGNORE, EncodeErabSetupItem(item));
    auto listBytes = list.take();

    std::vector<std::pair<std::pair<uint16_t, Criticality>, std::vector<uint8_t>>> ies;
    ies.push_back({{IE_MME_UE_S1AP_ID, Criticality::IGNORE}, EncodeUeId(mmeUeS1apId, 0xFFFFFFFFU)});
    ies.push_back({{IE_ENB_UE_S1AP_ID, Criticality::IGNORE}, EncodeUeId(enbUeS1apId, 0xFFFFFFU)});
    ies.push_back({{IE_E_RAB_SETUP_LIST_CTXT_SU_RES, Criticality::IGNORE}, std::move(listBytes)});
    if (!failed.empty())
    {
        BitWriter failures;
        WriteConstrained(failures, failed.size(), 1, 256, true);
        for (const auto &item : failed)
        {
            BitWriter value;
            value.writeBit(false);
            value.writeBit(false);
            WriteErabId(value, item.erabId);
            WriteCause(value, item.causeCategory, item.causeValue);
            WriteIe(failures, IE_E_RAB_ITEM, Criticality::IGNORE, value.take());
        }
        ies.push_back({{IE_E_RAB_FAILED_TO_SETUP_LIST_CTXT_SU_RES, Criticality::IGNORE}, failures.take()});
    }
    return EncodePdu(1, PROCEDURE_INITIAL_CONTEXT_SETUP, Criticality::REJECT, ies);
}

std::vector<uint8_t> EncodeInitialContextSetupFailure(uint32_t mmeUeS1apId, uint32_t enbUeS1apId,
                                                      const std::string &category, int value)
{
    if (mmeUeS1apId == 0 || enbUeS1apId == 0 || enbUeS1apId > 0xFFFFFFU)
        throw CodecError("Initial Context Setup Failure has invalid UE identities");
    BitWriter cause;
    WriteCause(cause, category, value);
    return EncodePdu(2, PROCEDURE_INITIAL_CONTEXT_SETUP, Criticality::REJECT, {
        {{IE_MME_UE_S1AP_ID, Criticality::IGNORE}, EncodeUeId(mmeUeS1apId, 0xFFFFFFFFU)},
        {{IE_ENB_UE_S1AP_ID, Criticality::IGNORE}, EncodeUeId(enbUeS1apId, 0xFFFFFFU)},
        {{IE_CAUSE, Criticality::IGNORE}, cause.take()}});
}

UeContextReleaseCommand DecodeUeContextReleaseCommand(const uint8_t *data, size_t length)
{
    auto envelope = DecodeEnvelope(data, length, PROCEDURE_UE_CONTEXT_RELEASE, static_cast<int>(Criticality::REJECT));
    if (envelope.choice != 0)
        throw CodecError("UE Context Release Command is not an initiating message");

    UeContextReleaseCommand result{};
    bool idsPresent = false;
    bool causePresent = false;
    for (const auto &ie : DecodeIeContainer(envelope.value))
    {
        if (ie.id == IE_UE_S1AP_IDS)
        {
            if (ie.criticality != Criticality::REJECT)
                throw CodecError("UE-S1AP-IDs has invalid criticality");
            BitReader reader(ie.value);
            if (reader.readBit())
                throw CodecError("Extended UE-S1AP-IDs is not supported");
            uint8_t choice = static_cast<uint8_t>(reader.readBits(1));
            if (choice == 0)
            {
                if (reader.readBit())
                    throw CodecError("Extended UE-S1AP-ID-pair is not supported");
                if (reader.readBit())
                    throw CodecError("UE-S1AP-ID-pair extensions are not supported");
                result.mmeUeS1apId = static_cast<uint32_t>(ReadConstrained(reader, 0, 0xFFFFFFFFU, true));
                result.enbUeS1apId = static_cast<uint32_t>(ReadConstrained(reader, 0, 0xFFFFFFU, true));
            }
            else
            {
                result.mmeUeS1apId = static_cast<uint32_t>(ReadConstrained(reader, 0, 0xFFFFFFFFU, true));
                result.enbUeS1apId.reset();
            }
            reader.requireFinished();
            idsPresent = true;
        }
        else if (ie.id == IE_CAUSE)
        {
            if (ie.criticality != Criticality::IGNORE)
                throw CodecError("Cause has invalid criticality");
            BitReader reader(ie.value);
            if (reader.readBit())
                throw CodecError("Extended S1AP Cause category is not supported");
            int category = static_cast<int>(reader.readBits(3));
            static const std::array<const char *, 5> names = {"radioNetwork", "transport", "nas", "protocol", "misc"};
            static const std::array<size_t, 5> counts = {36, 2, 4, 7, 6};
            if (category < 0 || category >= static_cast<int>(names.size()))
                throw CodecError("Invalid S1AP Cause category");
            result.causeCategory = names[category];
            result.causeValue = ReadExtensibleEnum(reader, counts[category]);
            reader.requireFinished();
            causePresent = true;
        }
        else if (ie.criticality == Criticality::REJECT)
            throw CodecError("Unknown reject-criticality IE in UE Context Release Command");
    }
    if (!idsPresent || !causePresent)
        throw CodecError("UE Context Release Command is missing a mandatory IE");
    return result;
}

std::vector<uint8_t> EncodeUeContextReleaseCommand(uint32_t mmeUeS1apId, std::optional<uint32_t> enbUeS1apId,
                                                   const std::string &causeCategory, int causeValue)
{
    if (mmeUeS1apId == 0)
        throw CodecError("UE Context Release Command has an invalid MME-UE-S1AP-ID");
    if (enbUeS1apId.has_value() && (*enbUeS1apId == 0 || *enbUeS1apId > 0xFFFFFFU))
        throw CodecError("UE Context Release Command has an invalid eNB-UE-S1AP-ID");

    static const std::array<const char *, 5> names = {"radioNetwork", "transport", "nas", "protocol", "misc"};
    static const std::array<size_t, 5> counts = {36, 2, 4, 7, 6};
    int category = -1;
    for (size_t i = 0; i < names.size(); ++i)
    {
        if (causeCategory == names[i])
        {
            category = static_cast<int>(i);
            break;
        }
    }
    if (category < 0)
        throw CodecError("Unknown S1AP Cause category");
    if (causeValue < 0 || causeValue >= static_cast<int>(counts[static_cast<size_t>(category)]))
        throw CodecError("Invalid S1AP Cause value");

    BitWriter ids;
    ids.writeBit(false); // UE-S1AP-IDs CHOICE not extended
    if (enbUeS1apId.has_value())
    {
        ids.writeBits(0, 1); // uE-S1AP-ID-pair
        ids.writeBit(false); // SEQUENCE extension marker
        ids.writeBit(false); // iE-Extensions absent
        WriteConstrained(ids, mmeUeS1apId, 0, 0xFFFFFFFFU, true);
        WriteConstrained(ids, *enbUeS1apId, 0, 0xFFFFFFU, true);
    }
    else
    {
        ids.writeBits(1, 1); // mME-UE-S1AP-ID
        WriteConstrained(ids, mmeUeS1apId, 0, 0xFFFFFFFFU, true);
    }

    BitWriter cause;
    cause.writeBit(false); // Cause CHOICE not extended
    cause.writeBits(static_cast<uint8_t>(category), 3);
    cause.writeBit(false); // root enumeration
    cause.writeBits(static_cast<uint64_t>(causeValue), BitsForRange(counts[static_cast<size_t>(category)]));

    std::vector<std::pair<std::pair<uint16_t, Criticality>, std::vector<uint8_t>>> ies;
    ies.push_back({{IE_UE_S1AP_IDS, Criticality::REJECT}, ids.take()});
    ies.push_back({{IE_CAUSE, Criticality::IGNORE}, cause.take()});
    return EncodePdu(0, PROCEDURE_UE_CONTEXT_RELEASE, Criticality::REJECT, ies);
}

std::vector<uint8_t> EncodeUeContextReleaseComplete(uint32_t mmeUeS1apId, uint32_t enbUeS1apId)
{
    if (mmeUeS1apId == 0 || enbUeS1apId == 0 || enbUeS1apId > 0xFFFFFFU)
        throw CodecError("UE Context Release Complete has an invalid UE S1AP identity");
    std::vector<std::pair<std::pair<uint16_t, Criticality>, std::vector<uint8_t>>> ies;
    ies.push_back({{IE_MME_UE_S1AP_ID, Criticality::REJECT}, EncodeUeId(mmeUeS1apId, 0xFFFFFFFFU)});
    ies.push_back({{IE_ENB_UE_S1AP_ID, Criticality::REJECT}, EncodeUeId(enbUeS1apId, 0xFFFFFFU)});
    return EncodePdu(1, PROCEDURE_UE_CONTEXT_RELEASE, Criticality::REJECT, ies);
}

UeContextReleaseComplete DecodeUeContextReleaseComplete(const uint8_t *data, size_t length)
{
    auto envelope = DecodeEnvelope(data, length, PROCEDURE_UE_CONTEXT_RELEASE, static_cast<int>(Criticality::REJECT));
    if (envelope.choice != 1)
        throw CodecError("UE Context Release Complete is not a successful outcome");

    UeContextReleaseComplete result{};
    bool mmePresent = false;
    bool enbPresent = false;
    for (const auto &ie : DecodeIeContainer(envelope.value))
    {
        if (ie.id == IE_MME_UE_S1AP_ID)
        {
            if (ie.criticality != Criticality::REJECT)
                throw CodecError("MME-UE-S1AP-ID has invalid criticality");
            result.mmeUeS1apId = DecodeUeId(ie.value, 0xFFFFFFFFU);
            mmePresent = true;
        }
        else if (ie.id == IE_ENB_UE_S1AP_ID)
        {
            if (ie.criticality != Criticality::REJECT)
                throw CodecError("eNB-UE-S1AP-ID has invalid criticality");
            result.enbUeS1apId = DecodeUeId(ie.value, 0xFFFFFFU);
            enbPresent = true;
        }
        else if (ie.criticality == Criticality::REJECT)
            throw CodecError("Unknown reject-criticality IE in UE Context Release Complete");
    }
    if (!mmePresent || !enbPresent)
        throw CodecError("UE Context Release Complete is missing a mandatory IE");
    if (result.mmeUeS1apId == 0 || result.enbUeS1apId == 0)
        throw CodecError("UE Context Release Complete names no UE");
    return result;
}

std::vector<uint8_t> EncodeUeContextReleaseRequest(uint32_t mmeUeS1apId, uint32_t enbUeS1apId,
                                                   const std::string &causeCategory, int causeValue)
{
    if (mmeUeS1apId == 0 || enbUeS1apId == 0 || enbUeS1apId > 0xFFFFFFU)
        throw CodecError("UE Context Release Request has an invalid UE S1AP identity");

    static const std::array<const char *, 5> names = {"radioNetwork", "transport", "nas", "protocol", "misc"};
    static const std::array<size_t, 5> counts = {36, 2, 4, 7, 6};
    int category = -1;
    for (size_t i = 0; i < names.size(); ++i)
        if (causeCategory == names[i]) category = static_cast<int>(i);
    if (category < 0 || causeValue < 0 || causeValue >= static_cast<int>(counts[static_cast<size_t>(category)]))
        throw CodecError("UE Context Release Request has an invalid Cause");

    BitWriter cause;
    cause.writeBit(false); // Cause CHOICE not extended
    cause.writeBits(static_cast<uint8_t>(category), 3);
    cause.writeBit(false); // root enumeration
    cause.writeBits(static_cast<uint64_t>(causeValue), BitsForRange(counts[static_cast<size_t>(category)]));

    std::vector<std::pair<std::pair<uint16_t, Criticality>, std::vector<uint8_t>>> ies;
    ies.push_back({{IE_MME_UE_S1AP_ID, Criticality::REJECT}, EncodeUeId(mmeUeS1apId, 0xFFFFFFFFU)});
    ies.push_back({{IE_ENB_UE_S1AP_ID, Criticality::REJECT}, EncodeUeId(enbUeS1apId, 0xFFFFFFU)});
    ies.push_back({{IE_CAUSE, Criticality::IGNORE}, cause.take()});
    return EncodePdu(0, PROCEDURE_UE_CONTEXT_RELEASE_REQUEST, Criticality::IGNORE, ies);
}

UeContextReleaseRequest DecodeUeContextReleaseRequest(const uint8_t *data, size_t length)
{
    auto envelope = DecodeEnvelope(data, length, PROCEDURE_UE_CONTEXT_RELEASE_REQUEST,
                                   static_cast<int>(Criticality::IGNORE));
    if (envelope.choice != 0)
        throw CodecError("UE Context Release Request is not an initiating message");
    UeContextReleaseRequest result{};
    bool mmePresent = false, enbPresent = false, causePresent = false;
    for (const auto &ie : DecodeIeContainer(envelope.value))
    {
        if (ie.id == IE_MME_UE_S1AP_ID)
        {
            if (ie.criticality != Criticality::REJECT) throw CodecError("MME-UE-S1AP-ID has invalid criticality");
            result.mmeUeS1apId = DecodeUeId(ie.value, 0xFFFFFFFFU);
            mmePresent = true;
        }
        else if (ie.id == IE_ENB_UE_S1AP_ID)
        {
            if (ie.criticality != Criticality::REJECT) throw CodecError("eNB-UE-S1AP-ID has invalid criticality");
            result.enbUeS1apId = DecodeUeId(ie.value, 0xFFFFFFU);
            enbPresent = true;
        }
        else if (ie.id == IE_CAUSE)
        {
            if (ie.criticality != Criticality::IGNORE) throw CodecError("Cause has invalid criticality");
            BitReader reader(ie.value);
            if (reader.readBit()) throw CodecError("Extended S1AP Cause category is not supported");
            const int category = static_cast<int>(reader.readBits(3));
            static const std::array<const char *, 5> names = {"radioNetwork", "transport", "nas", "protocol", "misc"};
            static const std::array<size_t, 5> counts = {36, 2, 4, 7, 6};
            if (category < 0 || category >= static_cast<int>(names.size()))
                throw CodecError("Invalid S1AP Cause category");
            result.causeCategory = names[static_cast<size_t>(category)];
            result.causeValue = ReadExtensibleEnum(reader, counts[static_cast<size_t>(category)]);
            reader.requireFinished();
            causePresent = true;
        }
        else if (ie.criticality == Criticality::REJECT)
            throw CodecError("Unknown reject-criticality IE in UE Context Release Request");
    }
    if (!mmePresent || !enbPresent || !causePresent)
        throw CodecError("UE Context Release Request is missing a mandatory IE");
    return result;
}

// --- Phase 6: S1AP Paging -----------------------------------------------------
//
// Paging is a non-UE-associated S1AP procedure (TS 36.413 9.1.6). Its IE
// container is decoded with the same APER primitives as the rest of the LTE
// codec, but nothing here resolves an eNB-UE-S1AP-ID or MME-UE-S1AP-ID: a
// Paging PDU can never establish, resume or mutate an S1 UE context.
namespace
{

// TBCD IMSI validation shared by the Paging encoder and decoder. Every
// semi-octet is a decimal digit; an odd-length IMSI uses 0xF as the filler in
// the most significant nibble of the last octet (TS 29.002 / TS 24.008).
void ValidateTbcdImsi(const std::vector<uint8_t> &imsi)
{
    for (size_t i = 0; i < imsi.size(); ++i)
    {
        const uint8_t high = static_cast<uint8_t>(imsi[i] >> 4U);
        const uint8_t low = static_cast<uint8_t>(imsi[i] & 0x0FU);
        if (low > 9)
            throw CodecError("Paging IMSI contains a non-decimal digit");
        const bool lastOctet = i + 1 == imsi.size();
        if (high > 9 && !(lastOctet && high == 0x0F))
            throw CodecError("Paging IMSI contains a non-decimal digit");
    }
}

std::vector<uint8_t> EncodePagingIdentityValue(const PagingMessage &message)
{
    BitWriter writer;
    writer.writeBit(false); // UEPagingIdentity CHOICE extension marker
    if (message.identity == PagingMessage::Identity::S_TMSI)
    {
        if (message.sTmsi.mTmsi == 0)
            throw CodecError("Paging S-TMSI has an invalid zero M-TMSI");
        writer.writeBit(false); // s-TMSI alternative
        writer.writeBit(false); // S-TMSI SEQUENCE extension marker
        writer.writeBit(false); // S-TMSI iE-Extensions absent
        writer.writeBits(message.sTmsi.mmeCode, 8);
        // X.691 aligned PER: an 8-bit fixed bit string is bit-packed, while the
        // 32-bit M-TMSI starts on the next octet boundary. This is the exact
        // layout the live Open5GS MME accepts in Initial UE Message S-TMSI.
        writer.align();
        writer.writeBits(message.sTmsi.mTmsi, 32);
        return writer.take();
    }

    writer.writeBit(true); // iMSI alternative
    if (message.imsi.size() < 3 || message.imsi.size() > 8)
        throw CodecError("Paging IMSI identity must be 3..8 TBCD octets");
    ValidateTbcdImsi(message.imsi);
    WriteConstrained(writer, message.imsi.size(), 3, 8, true);
    writer.align();
    writer.writeBytes(message.imsi);
    return writer.take();
}

std::vector<uint8_t> EncodePagingTaiListValue(const std::vector<Tai> &taiList)
{
    if (taiList.empty() || taiList.size() > 16)
        throw CodecError("Paging TAI list must contain 1..16 tracking areas");
    BitWriter writer;
    WriteConstrained(writer, taiList.size() - 1, 0, 15, true);
    for (const auto &tai : taiList)
    {
        // TS 36.413 TAIList is a SEQUENCE OF ProtocolIE-SingleContainer, so each
        // tracking area travels inside an id-TAIItem field rather than bare.
        BitWriter item;
        item.writeBit(false); // TAI SEQUENCE extension marker
        item.writeBit(false); // TAI iE-Extensions absent
        auto plmn = EncodePlmn(tai.plmn);
        WriteFixedOctets(item, plmn.data(), plmn.size());
        item.writeBits(tai.tac, 16);
        WriteIe(writer, IE_TAI_ITEM, Criticality::IGNORE, item.take());
    }
    return writer.take();
}

uint16_t DecodeUeIdentityIndexValue(const std::vector<uint8_t> &value)
{
    BitReader reader(value);
    // TS 36.413 UEIdentityIndexValue ::= INTEGER (0..1023). Aligned PER carries
    // the ten bits in the most significant bits of two octets, with six pad
    // bits; a live Open5GS page encodes index 1 as 0x0040.
    reader.align();
    const uint16_t encoded = static_cast<uint16_t>(reader.readBits(16));
    if ((encoded & 0x003FU) != 0)
        throw CodecError("UE Identity Index value has non-zero APER pad bits");
    reader.requireFinished();
    return static_cast<uint16_t>(encoded >> 6U);
}

} // namespace

PagingMessage DecodePaging(const uint8_t *data, size_t length)
{
    auto envelope = DecodeEnvelope(data, length, PROCEDURE_PAGING, static_cast<int>(Criticality::IGNORE));
    if (envelope.choice != 0)
        throw CodecError("Paging must be an initiating S1AP message");

    PagingMessage result{};
    bool indexPresent = false, identityPresent = false, domainPresent = false, taiListPresent = false;
    for (const auto &ie : DecodeIeContainer(envelope.value))
    {
        if (ie.id == IE_UE_IDENTITY_INDEX_VALUE)
        {
            if (ie.criticality != Criticality::IGNORE)
                throw CodecError("UE Identity Index value has unexpected criticality");
            if (indexPresent)
                throw CodecError("Duplicate UE Identity Index value");
            result.ueIdentityIndexValue = DecodeUeIdentityIndexValue(ie.value);
            indexPresent = true;
        }
        else if (ie.id == IE_UE_PAGING_IDENTITY)
        {
            if (ie.criticality != Criticality::IGNORE)
                throw CodecError("UE Paging Identity has unexpected criticality");
            if (identityPresent)
                throw CodecError("Duplicate UE Paging Identity");
            BitReader reader(ie.value);
            if (reader.readBit())
                throw CodecError("Extended UE Paging Identity choice is not supported");
            if (reader.readBit())
            {
                result.identity = PagingMessage::Identity::IMSI;
                const size_t octets = ReadConstrained(reader, 3, 8, true);
                result.imsi = ReadFixedOctets(reader, octets);
                ValidateTbcdImsi(result.imsi);
            }
            else
            {
                result.identity = PagingMessage::Identity::S_TMSI;
                if (reader.readBit() || reader.readBit())
                    throw CodecError("Unsupported S-TMSI extension in Paging");
                result.sTmsi.mmeCode = static_cast<uint8_t>(reader.readBits(8));
                reader.align();
                result.sTmsi.mTmsi = static_cast<uint32_t>(reader.readBits(32));
                if (result.sTmsi.mTmsi == 0)
                    throw CodecError("Paging S-TMSI has an invalid zero M-TMSI");
            }
            reader.requireFinished();
            identityPresent = true;
        }
        else if (ie.id == IE_CN_DOMAIN)
        {
            if (ie.criticality != Criticality::IGNORE)
                throw CodecError("CN Domain has unexpected criticality");
            if (domainPresent)
                throw CodecError("Duplicate CN Domain");
            BitReader reader(ie.value);
            if (reader.readBit())
                throw CodecError("Extended CN Domain is not supported");
            result.cnDomain = static_cast<uint8_t>(reader.readBits(1));
            reader.requireFinished();
            domainPresent = true;
        }
        else if (ie.id == IE_TAI_LIST)
        {
            if (ie.criticality != Criticality::IGNORE)
                throw CodecError("TAI list has unexpected criticality");
            if (taiListPresent)
                throw CodecError("Duplicate TAI list");
            BitReader reader(ie.value);
            const size_t count = ReadConstrained(reader, 0, 15, true) + 1;
            result.taiList.reserve(count);
            for (size_t i = 0; i < count; ++i)
            {
                if (ReadConstrained(reader, 0, 65535, true) != IE_TAI_ITEM)
                    throw CodecError("Paging TAI list contains an unexpected item identifier");
                if (reader.readBits(2) != static_cast<uint8_t>(Criticality::IGNORE))
                    throw CodecError("Paging TAI item has unexpected criticality");
                reader.align();
                const auto itemValue = reader.readOpenType();
                BitReader item(itemValue);
                if (item.readBit() || item.readBit())
                    throw CodecError("Unsupported TAI extension in Paging");
                auto plmn = ReadFixedOctets(item, 3);
                Tai tai{DecodePlmn(plmn.data(), plmn.size()), static_cast<uint16_t>(item.readBits(16))};
                item.requireFinished();
                result.taiList.push_back(std::move(tai));
            }
            reader.requireFinished();
            taiListPresent = true;
        }
        else if (ie.id == IE_DEFAULT_PAGING_DRX)
        {
            if (ie.criticality != Criticality::IGNORE)
                throw CodecError("PagingDRX has unexpected criticality");
            BitReader reader(ie.value);
            if (reader.readBit())
                throw CodecError("Extended PagingDRX is not supported");
            result.pagingDrx = static_cast<uint8_t>(reader.readBits(2));
            reader.requireFinished();
        }
        else if (ie.criticality == Criticality::REJECT)
            throw CodecError("Unsupported reject-criticality IE " + std::to_string(ie.id) + " in Paging");
        // IGNORE/NOTIFY criticality: an unknown optional Paging IE is skipped.
    }

    if (!indexPresent || !identityPresent || !domainPresent || !taiListPresent)
        throw CodecError("Paging is missing a mandatory information element");
    return result;
}

std::vector<uint8_t> EncodePaging(const PagingMessage &message)
{
    if (message.taiList.empty() || message.taiList.size() > 16)
        throw CodecError("Paging TAI list must contain 1..16 tracking areas");
    if (message.cnDomain > 1)
        throw CodecError("CN Domain must be ps-domain or cs-domain");

    BitWriter index;
    index.align();
    index.writeBits(static_cast<uint64_t>(message.ueIdentityIndexValue) << 6U, 16);
    index.align();

    BitWriter domain;
    domain.writeBit(false); // enumerations are not extended
    domain.writeBits(message.cnDomain, 1);

    std::vector<std::pair<std::pair<uint16_t, Criticality>, std::vector<uint8_t>>> ies;
    ies.push_back({{IE_UE_IDENTITY_INDEX_VALUE, Criticality::IGNORE}, index.take()});
    ies.push_back({{IE_UE_PAGING_IDENTITY, Criticality::IGNORE}, EncodePagingIdentityValue(message)});
    ies.push_back({{IE_CN_DOMAIN, Criticality::IGNORE}, domain.take()});
    ies.push_back({{IE_TAI_LIST, Criticality::IGNORE}, EncodePagingTaiListValue(message.taiList)});
    if (message.pagingDrx.has_value())
    {
        if (*message.pagingDrx > 3)
            throw CodecError("PagingDRX index is out of range");
        BitWriter drx;
        drx.writeBit(false);
        drx.writeBits(*message.pagingDrx, 2);
        ies.push_back({{IE_DEFAULT_PAGING_DRX, Criticality::IGNORE}, drx.take()});
    }
    return EncodePdu(0, PROCEDURE_PAGING, Criticality::IGNORE, ies);
}


// --- Phase 7: S1AP E-RAB management (TS 36.413, procedures 5 and 7) ---------

namespace
{

// Cause ::= CHOICE { radioNetwork(0), transport(1), nas(2), protocol(3), misc(4), ... }
// Only the five standard categories are encoded; an extension cause would mean
// the peer speaks a vocabulary this eNB does not implement.
void WriteCause(BitWriter &writer, const std::string &category, int value)
{
    static const std::array<const char *, 5> names{"radioNetwork", "transport", "nas", "protocol", "misc"};
    size_t index = names.size();
    for (size_t i = 0; i < names.size(); ++i)
    {
        if (category == names[i])
        {
            index = i;
            break;
        }
    }
    if (index == names.size())
        throw CodecError("Unsupported S1AP cause category " + category);
    if (value < 0 || value > 255)
        throw CodecError("S1AP cause value is out of range");
    static const std::array<size_t, 5> roots{36, 2, 4, 7, 6};
    writer.writeBit(false); // Cause CHOICE root
    writer.writeBits(index, 3);
    const auto root = roots[index];
    writer.writeBit(static_cast<size_t>(value) >= root);
    if (static_cast<size_t>(value) < root)
        writer.writeBits(value, BitsForRange(root));
    else
    {
        if (static_cast<size_t>(value) - root >= 64)
            throw CodecError("Large Cause extension enumeration unsupported");
        writer.writeBit(false); // normally small extension index
        writer.writeBits(static_cast<size_t>(value) - root, 6);
    }
}

void ReadCause(BitReader &reader, std::string &category, int &value)
{
    static const std::array<const char *, 5> names{"radioNetwork", "transport", "nas", "protocol", "misc"};
    if (reader.readBit())
        throw CodecError("Unsupported S1AP Cause choice extension");
    const auto index = static_cast<size_t>(reader.readBits(3));
    if (index >= names.size())
        throw CodecError("Unsupported S1AP cause choice");
    category = names[index];
    static const std::array<size_t, 5> roots{36, 2, 4, 7, 6};
    value = ReadExtensibleEnum(reader, roots[index]);
}

} // namespace

ErabSetupRequest DecodeErabSetupRequest(const uint8_t *data, size_t length)
{
    auto envelope = DecodeEnvelope(data, length, PROCEDURE_E_RAB_SETUP, static_cast<int>(Criticality::REJECT));
    if (envelope.choice != 0)
        throw CodecError("E-RAB Setup Request is not an initiating message");

    ErabSetupRequest result{};
    bool mmePresent = false;
    bool enbPresent = false;
    bool erabsPresent = false;

    for (const auto &ie : DecodeIeContainer(envelope.value))
    {
        if (ie.id == IE_MME_UE_S1AP_ID)
        {
            if (ie.criticality != Criticality::REJECT)
                throw CodecError("MME-UE-S1AP-ID has invalid criticality");
            result.mmeUeS1apId = DecodeUeId(ie.value, 0xFFFFFFFFU);
            mmePresent = true;
        }
        else if (ie.id == IE_ENB_UE_S1AP_ID)
        {
            if (ie.criticality != Criticality::REJECT)
                throw CodecError("eNB-UE-S1AP-ID has invalid criticality");
            result.enbUeS1apId = DecodeUeId(ie.value, 0xFFFFFFU);
            enbPresent = true;
        }
        else if (ie.id == IE_E_RAB_TO_BE_SETUP_LIST_BEARER_SU_REQ)
        {
            if (ie.criticality != Criticality::REJECT)
                throw CodecError("E-RABToBeSetupListBearerSUReq has invalid criticality");
            BitReader reader(ie.value);
            const size_t count = ReadConstrained(reader, 1, 256, true);
            result.erabs.reserve(count);
            for (size_t i = 0; i < count; ++i)
            {
                const auto id = static_cast<uint16_t>(ReadConstrained(reader, 0, 65535, true));
                if (id != IE_E_RAB_TO_BE_SETUP_ITEM_BEARER_SU_REQ)
                    throw CodecError("Unexpected E-RABToBeSetupListBearerSUReq item identity");
                reader.readBits(2);
                reader.align();
                auto value = reader.readOpenType();
                BitReader itemReader(value);
                result.erabs.push_back(ReadErabToBeSetupItemBearerSUReq(itemReader));
                itemReader.requireFinished();
            }
            reader.requireFinished();
            erabsPresent = true;
        }
        else if (ie.criticality == Criticality::REJECT)
            throw CodecError("Unknown reject-criticality IE in E-RAB Setup Request");
    }

    if (!mmePresent || !enbPresent || !erabsPresent)
        throw CodecError("E-RAB Setup Request is missing a mandatory IE");
    if (result.erabs.empty())
        throw CodecError("E-RAB Setup Request contains no E-RAB to establish");

    for (size_t i = 0; i < result.erabs.size(); ++i)
    {
        for (size_t j = i + 1; j < result.erabs.size(); ++j)
        {
            if (result.erabs[i].erabId == result.erabs[j].erabId)
                throw CodecError("E-RAB Setup Request repeats an E-RAB identity");
        }
    }

    return result;
}

std::vector<uint8_t> EncodeErabSetupRequest(const ErabSetupRequest &request)
{
    if (request.erabs.empty() || request.erabs.size() > 256)
        throw CodecError("E-RAB Setup Request requires 1..256 E-RABs");
    if (request.mmeUeS1apId == 0 || request.enbUeS1apId == 0 || request.enbUeS1apId > 0xFFFFFFU)
        throw CodecError("E-RAB Setup Request has an invalid UE S1AP identity");

    BitWriter list;
    WriteConstrained(list, request.erabs.size(), 1, 256, true);
    for (const auto &erab : request.erabs)
    {
        WriteIe(list, IE_E_RAB_TO_BE_SETUP_ITEM_BEARER_SU_REQ, Criticality::REJECT,
               EncodeErabToBeSetupItemBearerSUReq(erab));
    }

    std::vector<std::pair<std::pair<uint16_t, Criticality>, std::vector<uint8_t>>> ies;
    ies.push_back({{IE_MME_UE_S1AP_ID, Criticality::REJECT}, EncodeUeId(request.mmeUeS1apId, 0xFFFFFFFFU)});
    ies.push_back({{IE_ENB_UE_S1AP_ID, Criticality::REJECT}, EncodeUeId(request.enbUeS1apId, 0xFFFFFFU)});
    ies.push_back({{IE_E_RAB_TO_BE_SETUP_LIST_BEARER_SU_REQ, Criticality::REJECT}, list.take()});
    return EncodePdu(0, PROCEDURE_E_RAB_SETUP, Criticality::REJECT, ies);
}

std::vector<uint8_t> EncodeErabSetupResponse(uint32_t mmeUeS1apId, uint32_t enbUeS1apId,
                                             const std::vector<ErabSetupItem> &established,
                                             const std::vector<ErabFailedItem> &failed)
{
    if (mmeUeS1apId == 0 || enbUeS1apId == 0 || enbUeS1apId > 0xFFFFFFU)
        throw CodecError("E-RAB Setup Response has an invalid UE S1AP identity");
    if ((established.empty() && failed.empty()) || established.size() > 256 || failed.size() > 256)
        throw CodecError("E-RAB Setup Response requires bounded nonempty outcomes");
    std::set<uint8_t> seen;
    for (const auto &item : established)
        if (!seen.insert(item.erabId).second)
            throw CodecError("Repeated E-RAB setup outcome");
    for (const auto &item : failed)
        if (!seen.insert(item.erabId).second)
            throw CodecError("Repeated E-RAB setup outcome");

    BitWriter list;
    if (!established.empty())
        WriteConstrained(list, established.size(), 1, 256, true);
    for (const auto &erab : established)
    {
        BitWriter item;
        item.writeBit(false);
        item.writeBit(false);
        WriteErabId(item, erab.erabId);
        WriteTransportLayerAddress(item, erab.transportLayerAddress);
        WriteFixedOctets(item, erab.gtpTeid.data(), erab.gtpTeid.size());
        WriteIe(list, IE_E_RAB_SETUP_ITEM_BEARER_SU_RES, Criticality::IGNORE, item.take());
    }

    std::vector<std::pair<std::pair<uint16_t, Criticality>, std::vector<uint8_t>>> ies;
    ies.push_back({{IE_MME_UE_S1AP_ID, Criticality::IGNORE}, EncodeUeId(mmeUeS1apId, 0xFFFFFFFFU)});
    ies.push_back({{IE_ENB_UE_S1AP_ID, Criticality::IGNORE}, EncodeUeId(enbUeS1apId, 0xFFFFFFU)});
    if (!established.empty())
        ies.push_back({{IE_E_RAB_SETUP_LIST_BEARER_SU_RES, Criticality::IGNORE}, list.take()});

    if (!failed.empty())
    {
        BitWriter failedList;
        WriteConstrained(failedList, failed.size(), 1, 256, true);
        for (const auto &erab : failed)
        {
            BitWriter item;
            item.writeBit(false);
            item.writeBit(false);
            WriteErabId(item, erab.erabId);
            WriteCause(item, erab.causeCategory, erab.causeValue);
            WriteIe(failedList, IE_E_RAB_ITEM, Criticality::IGNORE, item.take());
        }
        ies.push_back({{IE_E_RAB_FAILED_TO_SETUP_LIST_BEARER_SU_RES, Criticality::IGNORE}, failedList.take()});
    }

    return EncodePdu(1, PROCEDURE_E_RAB_SETUP, Criticality::REJECT, ies);
}

ErabReleaseCommand DecodeErabReleaseCommand(const uint8_t *data, size_t length)
{
    auto envelope = DecodeEnvelope(data, length, PROCEDURE_E_RAB_RELEASE, static_cast<int>(Criticality::REJECT));
    if (envelope.choice != 0)
        throw CodecError("E-RAB Release Command is not an initiating message");

    ErabReleaseCommand result{};
    bool mmePresent = false;
    bool erabsPresent = false;

    for (const auto &ie : DecodeIeContainer(envelope.value))
    {
        if (ie.id == IE_MME_UE_S1AP_ID)
        {
            if (ie.criticality != Criticality::REJECT)
                throw CodecError("MME-UE-S1AP-ID has invalid criticality");
            result.mmeUeS1apId = DecodeUeId(ie.value, 0xFFFFFFFFU);
            mmePresent = true;
        }
        else if (ie.id == IE_ENB_UE_S1AP_ID)
        {
            if (ie.criticality != Criticality::REJECT)
                throw CodecError("eNB-UE-S1AP-ID has invalid criticality");
            result.enbUeS1apId = DecodeUeId(ie.value, 0xFFFFFFU);
        }
        else if (ie.id == IE_E_RAB_TO_BE_RELEASED_LIST)
        {
            // TS 36.413 declares this list, its items and the NAS-PDU of the
            // release command with ignore criticality. Treating the list as
            // reject made the eNB discard a legitimate MME release.
            if (ie.criticality != Criticality::IGNORE)
                throw CodecError("E-RABToBeReleasedList has invalid criticality");
            BitReader reader(ie.value);
            const size_t count = ReadConstrained(reader, 1, 256, true);
            result.erabIds.reserve(count);
            for (size_t i = 0; i < count; ++i)
            {
                const auto id = static_cast<uint16_t>(ReadConstrained(reader, 0, 65535, true));
                if (id != IE_E_RAB_ITEM)
                    throw CodecError("Unexpected E-RABToBeReleasedList item identity");
                if (reader.readBits(2) != static_cast<uint64_t>(Criticality::IGNORE))
                    throw CodecError("E-RABToBeReleasedList item has invalid criticality");
                reader.align();
                auto value = reader.readOpenType();
                BitReader itemReader(value);
                if (itemReader.readBit())
                    throw CodecError("Unsupported E-RAB release item extension");
                if (itemReader.readBit())
                    throw CodecError("E-RAB release item extensions are not supported");
                result.erabIds.push_back(ReadErabId(itemReader));
                // E-RABItem also carries a Cause. It is not decoded: the chosen
                // alternative varies its ENUMERATED width, and the eNB takes no
                // decision from it. The item length already bounds the field.
            }
            reader.requireFinished();
            erabsPresent = true;
        }
        else if (ie.id == IE_NAS_PDU)
        {
            if (ie.criticality != Criticality::IGNORE)
                throw CodecError("NAS-PDU has invalid criticality");
            // NAS-PDU is an OCTET STRING, so its open type still starts with the
            // length determinant. Forwarding the raw value would hand the UE a
            // buffer whose first octet is a length instead of a security header.
            BitReader reader(ie.value);
            result.nasPdu = reader.readBytes(reader.readLength());
            result.nasPduPresent = true;
        }
        else if (ie.id == IE_CAUSE)
        {
            if (ie.criticality != Criticality::IGNORE)
                throw CodecError("Cause has invalid criticality");
            BitReader reader(ie.value);
            ReadCause(reader, result.causeCategory, result.causeValue);
            reader.requireFinished();
        }
        else if (ie.criticality == Criticality::REJECT)
            throw CodecError("Unknown reject-criticality IE in E-RAB Release Command");
    }

    if (!mmePresent || !erabsPresent)
        throw CodecError("E-RAB Release Command is missing a mandatory IE");
    if (result.erabIds.empty())
        throw CodecError("E-RAB Release Command requests no E-RAB release");
    return result;
}

std::vector<uint8_t> EncodeErabReleaseCommand(const ErabReleaseCommand &command)
{
    if (command.erabIds.empty() || command.erabIds.size() > 256)
        throw CodecError("E-RAB Release Command requires 1..256 E-RABs");
    if (command.mmeUeS1apId == 0 || command.enbUeS1apId == 0 || command.enbUeS1apId > 0xFFFFFFU)
        throw CodecError("E-RAB Release Command has an invalid UE S1AP identity");

    BitWriter list;
    WriteConstrained(list, command.erabIds.size(), 1, 256, true);
    for (auto erabId : command.erabIds)
    {
        BitWriter item;
        item.writeBit(false); // SEQUENCE extension marker
        item.writeBit(false); // iE-Extensions absent
        WriteErabId(item, erabId);
        WriteCause(item, "radioNetwork", 0);
        WriteIe(list, IE_E_RAB_ITEM, Criticality::IGNORE, item.take());
    }

    std::vector<std::pair<std::pair<uint16_t, Criticality>, std::vector<uint8_t>>> ies;
    ies.push_back({{IE_MME_UE_S1AP_ID, Criticality::REJECT}, EncodeUeId(command.mmeUeS1apId, 0xFFFFFFFFU)});
    ies.push_back({{IE_ENB_UE_S1AP_ID, Criticality::REJECT}, EncodeUeId(command.enbUeS1apId, 0xFFFFFFU)});
    ies.push_back({{IE_E_RAB_TO_BE_RELEASED_LIST, Criticality::IGNORE}, list.take()});
    if (command.nasPduPresent)
    {
        BitWriter nas;
        nas.writeLength(command.nasPdu.size());
        nas.writeBytes(command.nasPdu);
        ies.push_back({{IE_NAS_PDU, Criticality::IGNORE}, nas.take()});
    }
    if (!command.causeCategory.empty())
    {
        BitWriter cause;
        WriteCause(cause, command.causeCategory, command.causeValue);
        ies.push_back({{IE_CAUSE, Criticality::IGNORE}, cause.take()});
    }
    return EncodePdu(0, PROCEDURE_E_RAB_RELEASE, Criticality::REJECT, ies);
}

std::vector<uint8_t> EncodeErabReleaseResponse(uint32_t mmeUeS1apId, uint32_t enbUeS1apId,
                                               const std::vector<uint8_t> &releasedErabIds)
{
    if (releasedErabIds.empty() || releasedErabIds.size() > 256)
        throw CodecError("E-RAB Release Response requires 1..256 E-RABs");
    if (mmeUeS1apId == 0 || enbUeS1apId == 0 || enbUeS1apId > 0xFFFFFFU)
        throw CodecError("E-RAB Release Response has an invalid UE S1AP identity");

    BitWriter list;
    WriteConstrained(list, releasedErabIds.size(), 1, 256, true);
    for (auto erabId : releasedErabIds)
    {
        BitWriter item;
        item.writeBit(false);
        item.writeBit(false);
        WriteErabId(item, erabId);
        // A successful release still carries a cause; unspecified radioNetwork
        // is the neutral value that claims nothing about why it happened.
        WriteCause(item, "radioNetwork", 0);
        WriteIe(list, IE_E_RAB_ITEM, Criticality::IGNORE, item.take());
    }

    std::vector<std::pair<std::pair<uint16_t, Criticality>, std::vector<uint8_t>>> ies;
    ies.push_back({{IE_MME_UE_S1AP_ID, Criticality::REJECT}, EncodeUeId(mmeUeS1apId, 0xFFFFFFFFU)});
    ies.push_back({{IE_ENB_UE_S1AP_ID, Criticality::REJECT}, EncodeUeId(enbUeS1apId, 0xFFFFFFU)});
    ies.push_back({{IE_E_RAB_RELEASED_LIST, Criticality::IGNORE}, list.take()});
    return EncodePdu(1, PROCEDURE_E_RAB_RELEASE, Criticality::REJECT, ies);
}

// TS 36.413 9.1.3.3: this item has mandatory NAS, no root transport
// fields, and an optional extension container containing TransportInformation.
ErabModifyRequest DecodeErabModifyRequest(const uint8_t *data, size_t length)
{
    const auto envelope = DecodeEnvelope(data, length, 6, static_cast<int>(Criticality::REJECT));
    if (envelope.choice != 0)
        throw CodecError("E-RAB Modify Request must be initiating");
    ErabModifyRequest result;
    bool mme = false, enb = false, list = false;
    for (const auto &ie : DecodeIeContainer(envelope.value))
    {
        if (ie.id == 0 || ie.id == 8 || ie.id == 66 || ie.id == 30)
        {
            if (ie.criticality != Criticality::REJECT)
                throw CodecError("Invalid E-RAB Modify Request IE criticality");
        }
        if (ie.id == 0)
        {
            result.mmeUeS1apId = DecodeUeId(ie.value, 0xFFFFFFFFU);
            mme = true;
        }
        else if (ie.id == 8)
        {
            result.enbUeS1apId = DecodeUeId(ie.value, 0xFFFFFFU);
            enb = true;
        }
        else if (ie.id == 66)
        {
            BitReader r(ie.value);
            if (r.readBit() || r.readBit())
                throw CodecError("Unsupported UE-AMBR extension");
            result.ueAmbr = UeAmbr{ReadBitRate(r), ReadBitRate(r)};
            r.requireFinished();
        }
        else if (ie.id == 30)
        {
            BitReader r(ie.value);
            const size_t count = ReadConstrained(r, 1, 256, true);
            std::set<uint8_t> seen;
            for (size_t i = 0; i < count; ++i)
            {
                if (ReadConstrained(r, 0, 65535, true) != 36 || r.readBits(2) != 0)
                    throw CodecError("Invalid E-RAB Modify item identity/criticality");
                auto bytes = r.readOpenType();
                BitReader item(bytes);
                if (item.readBit())
                    throw CodecError("Unsupported E-RAB Modify sequence extension");
                const bool extensions = item.readBit();
                ErabToBeModifiedItem value;
                value.erabId = ReadErabId(item);
                if (!seen.insert(value.erabId).second)
                    throw CodecError("Duplicate E-RAB Modify identity");
                ErabToBeSetupItem qos;
                ReadErabLevelQos(item, qos);
                value.qos = {qos.qci, qos.priorityLevel, qos.preemptionCapability, qos.preemptionVulnerability,
                             qos.gbr};
                value.nasPdu = item.readBytes(item.readLength());
                if (value.nasPdu.size() > 4096)
                    throw CodecError("Oversized E-RAB Modify NAS-PDU");
                if (extensions)
                {
                    const size_t n = ReadConstrained(item, 1, 65535, true);
                    std::set<uint16_t> ids;
                    for (size_t j = 0; j < n; ++j)
                    {
                        const auto id = static_cast<uint16_t>(ReadConstrained(item, 0, 65535, true));
                        const auto criticality = item.readBits(2);
                        auto ext = item.readOpenType();
                        if (!ids.insert(id).second || criticality > 2)
                            throw CodecError("Invalid E-RAB Modify extension container");
                        if (id == 185)
                        {
                            if (criticality != 0)
                                throw CodecError("TransportInformation must have reject criticality");
                            BitReader tr(ext);
                            if (tr.readBit())
                                throw CodecError("Extended TransportInformation unsupported");
                            ErabTransport transport;
                            if (tr.readBit())
                                throw CodecError("Extended transport address size unsupported");
                            const size_t bits = ReadConstrained(tr, 1, 160, true);
                            transport.ipv4 = bits == 32;
                            if (bits > 16)
                                tr.align();
                            for (size_t b = 0; b < bits; ++b)
                            {
                                const bool bit = tr.readBit();
                                if (transport.ipv4 && bit)
                                    transport.address[b / 8] |= static_cast<uint8_t>(1U << (7U - b % 8));
                            }
                            const auto teid = ReadFixedOctets(tr, 4);
                            for (auto octet : teid)
                                transport.teid = (transport.teid << 8U) | octet;
                            tr.requireFinished();
                            value.transport = transport;
                        }
                        else if (criticality != 1)
                            throw CodecError("Unsupported reject/notify E-RAB Modify extension");
                    }
                }
                item.requireFinished();
                result.erabs.push_back(std::move(value));
            }
            r.requireFinished();
            list = true;
        }
        else if (ie.criticality != Criticality::IGNORE)
            throw CodecError("Unsupported reject/notify E-RAB Modify IE");
    }
    if (!mme || !enb || !list)
        throw CodecError("Missing mandatory E-RAB Modify IE");
    return result;
}

std::vector<uint8_t> EncodeErabModifyRequest(const ErabModifyRequest &request)
{
    if (request.erabs.empty() || request.erabs.size() > 256)
        throw CodecError("Invalid E-RAB Modify list size");
    BitWriter list;
    WriteConstrained(list, request.erabs.size(), 1, 256, true);
    for (const auto &erab : request.erabs)
    {
        BitWriter item;
        item.writeBit(false);
        item.writeBit(erab.transport.has_value());
        WriteErabId(item, erab.erabId);
        const auto &q = erab.qos;
        WriteErabLevelQos(item, q.qci, q.priorityLevel, q.preemptionCapability, q.preemptionVulnerability, q.gbr);
        item.writeLength(erab.nasPdu.size());
        item.writeBytes(erab.nasPdu);
        if (erab.transport)
        {
            if (!erab.transport->ipv4)
                throw CodecError("Offline Modify encoder only supports IPv4 transport");
            WriteConstrained(item, 1, 1, 65535, true);
            BitWriter transport;
            transport.writeBit(false);
            WriteTransportLayerAddress(transport, erab.transport->address);
            const uint32_t t = erab.transport->teid;
            const std::array<uint8_t, 4> teid{static_cast<uint8_t>(t >> 24U), static_cast<uint8_t>(t >> 16U),
                                              static_cast<uint8_t>(t >> 8U), static_cast<uint8_t>(t)};
            WriteFixedOctets(transport, teid.data(), teid.size());
            WriteIe(item, 185, Criticality::REJECT, transport.take());
        }
        WriteIe(list, 36, Criticality::REJECT, item.take());
    }
    std::vector<std::pair<std::pair<uint16_t, Criticality>, std::vector<uint8_t>>> ies;
    ies.push_back({{0, Criticality::REJECT}, EncodeUeId(request.mmeUeS1apId, 0xFFFFFFFFU)});
    ies.push_back({{8, Criticality::REJECT}, EncodeUeId(request.enbUeS1apId, 0xFFFFFFU)});
    if (request.ueAmbr)
    {
        BitWriter ambr;
        ambr.writeBit(false);
        ambr.writeBit(false);
        WriteBitRate(ambr, request.ueAmbr->downlink);
        WriteBitRate(ambr, request.ueAmbr->uplink);
        ies.push_back({{66, Criticality::REJECT}, ambr.take()});
    }
    ies.push_back({{30, Criticality::REJECT}, list.take()});
    return EncodePdu(0, 6, Criticality::REJECT, ies);
}

std::vector<uint8_t> EncodeErabModifyResponse(uint32_t mmeId, uint32_t enbId, const std::vector<uint8_t> &modified,
                                              const std::vector<ErabFailedItem> &failed)
{
    if (modified.size() + failed.size() == 0 || modified.size() + failed.size() > 256)
        throw CodecError("Invalid E-RAB Modify outcome count");
    std::set<uint8_t> seen;
    std::vector<std::pair<std::pair<uint16_t, Criticality>, std::vector<uint8_t>>> ies;
    // Response identities are IGNORE, unlike the request.
    ies.push_back({{0, Criticality::IGNORE}, EncodeUeId(mmeId, 0xFFFFFFFFU)});
    ies.push_back({{8, Criticality::IGNORE}, EncodeUeId(enbId, 0xFFFFFFU)});
    auto append = [&](bool success) {
        const size_t count = success ? modified.size() : failed.size();
        if (count == 0)
            return;
        BitWriter list;
        WriteConstrained(list, count, 1, 256, true);
        for (size_t i = 0; i < count; ++i)
        {
            const auto ebi = success ? modified[i] : failed[i].erabId;
            if (!seen.insert(ebi).second)
                throw CodecError("Duplicate E-RAB Modify outcome");
            BitWriter item;
            item.writeBit(false);
            item.writeBit(false);
            WriteErabId(item, ebi);
            if (!success)
                WriteCause(item, failed[i].causeCategory, failed[i].causeValue);
            WriteIe(list, success ? 37 : 35, Criticality::IGNORE, item.take());
        }
        ies.push_back({{static_cast<uint16_t>(success ? 31 : 32), Criticality::IGNORE}, list.take()});
    };
    append(true);
    append(false);
    return EncodePdu(1, 6, Criticality::REJECT, ies);
}

// --- Phase 18-A: S1-based connected-mode handover ---------------------------
//
// The encoders and decoders below cover the five S1-based handover message
// families of TS 36.413 V16.4.0 §9.1.3.1 and the two wire failure messages.
// Every procedure code, IE identifier, criticality and presence value is
// transcribed from the reference ASN.1 module 36413-g40.asn; nothing here is
// derived from a guess.
//
// id-PathSwitchRequest (procedure 3) is the X2-based bearer path update. It is
// deliberately absent. A handover path update is the MME's, and Handover Notify
// is what asks for it.

namespace
{

// --- HandoverType -----------------------------------------------------------
//
// HandoverType ::= ENUMERATED { intralte, ltetoutran, ltetogeran, utrantolte,
//                               gerantolte, ..., eps-to-5gs, fivegs-to-eps }.
// Five root values, so three bits, behind an extension marker. Only the root
// value intralte is implemented: the four other root values are inter-RAT
// handovers and the two extension values are 5GS ones, and encoding any of
// them without an inter-RAT or 5GS implementation behind it would put a
// message on the wire that this eNB cannot honour.

void WriteHandoverType(BitWriter &writer, HandoverType type)
{
    if (type != HandoverType::INTRA_LTE)
        throw HandoverRefused(HandoverRefusal::UNSUPPORTED_HANDOVER_TYPE,
                              "Only an intra-LTE HandoverType can be encoded");
    writer.writeBit(false); // root enumeration
    writer.writeBits(static_cast<uint64_t>(type), 3);
}

HandoverType ReadHandoverType(BitReader &reader)
{
    if (reader.readBit())
        throw HandoverRefused(HandoverRefusal::UNSUPPORTED_HANDOVER_TYPE,
                              "Extended HandoverType is not supported");
    const auto index = reader.readBits(3);
    if (index > 4)
        throw HandoverRefused(HandoverRefusal::UNSUPPORTED_HANDOVER_TYPE,
                              "Reserved HandoverType enumeration value");
    const auto type = static_cast<HandoverType>(index);
    if (type != HandoverType::INTRA_LTE)
        throw HandoverRefused(HandoverRefusal::UNSUPPORTED_HANDOVER_TYPE,
                              "Only intra-LTE handover is supported");
    return type;
}

// --- Opaque transparent containers -----------------------------------------
//
// Source-ToTarget-TransparentContainer and Target-ToSource-TransparentContainer
// are plain OCTET STRING "coded according to the specifications of the target
// system". They are carried byte-for-byte. Nothing here parses, trims or
// rewrites one, so no RRC or security field can be read out of a container and
// no container can be used as authority to invent one.

std::vector<uint8_t> EncodeOpaqueContainer(const TransparentContainer &container)
{
    if (container.empty())
        throw HandoverRefused(HandoverRefusal::INVALID_TRANSPARENT_CONTAINER,
                              "A handover transparent container must not be empty");
    if (container.size() > MaxTransparentContainerSize)
        throw HandoverRefused(HandoverRefusal::INVALID_TRANSPARENT_CONTAINER,
                              "Handover transparent container exceeds the receiver bound");
    BitWriter writer;
    writer.writeLength(container.size());
    writer.writeBytes(container);
    return writer.take();
}

TransparentContainer DecodeOpaqueContainer(const std::vector<uint8_t> &value)
{
    BitReader reader(value);
    auto container = reader.readBytes(reader.readLength());
    reader.requireFinished();
    if (container.empty())
        throw HandoverRefused(HandoverRefusal::INVALID_TRANSPARENT_CONTAINER,
                              "A handover transparent container must not be empty");
    if (container.size() > MaxTransparentContainerSize)
        throw HandoverRefused(HandoverRefusal::INVALID_TRANSPARENT_CONTAINER,
                              "Handover transparent container exceeds the receiver bound");
    return container;
}

// --- Target identity --------------------------------------------------------
//
// TargetID ::= CHOICE { targeteNB-ID TargeteNB-ID, targetRNC-ID TargetRNC-ID,
//                       cGI CGI, ..., targetgNgRanNode-ID TargetNgRanNode-ID }
// with TargeteNB-ID ::= SEQUENCE { global-ENB-ID Global-ENB-ID,
//                                  selected-TAI TAI,
//                                  iE-Extensions ... OPTIONAL, ... }.
//
// Only the targeteNB-ID choice is named. A targetRNC-ID or a CGI would be an
// inter-RAT target and a targetgNgRanNode-ID a 5GS one; both are refused as an
// invalid context identity rather than decoded by guesswork. The PLMN of the
// Global-ENB-ID and the PLMN of the selected TAI are two separate fields on the
// wire and must agree: a target that names two different networks is not a
// coherent target.

void WriteEnbIdentity(BitWriter &writer, const EnbIdentity &identity)
{
    writer.writeBit(false); // TargeteNB-ID extension marker
    writer.writeBit(false); // TargeteNB-ID iE-Extensions absent
    auto plmn = EncodePlmn(identity.plmn);
    // Global-ENB-ID
    writer.writeBit(false); // Global-ENB-ID extension marker
    writer.writeBit(false); // Global-ENB-ID iE-Extensions absent
    WriteFixedOctets(writer, plmn.data(), plmn.size());
    writer.writeBit(false); // ENB-ID CHOICE extension marker
    writer.writeBit(false); // macroENB-ID
    writer.align();
    writer.writeBits(identity.enbId & 0xFFFFFU, 20);
    // selected-TAI
    writer.writeBit(false); // TAI extension marker
    writer.writeBit(false); // TAI iE-Extensions absent
    WriteFixedOctets(writer, plmn.data(), plmn.size());
    writer.writeBits(identity.tac, 16);
}

EnbIdentity ReadEnbIdentity(BitReader &reader)
{
    if (reader.readBit())
        throw HandoverRefused(HandoverRefusal::INVALID_CONTEXT_IDENTITY,
                              "Extended TargeteNB-ID is not supported");
    if (reader.readBit())
        throw HandoverRefused(HandoverRefusal::INVALID_CONTEXT_IDENTITY,
                              "TargeteNB-ID extensions are not supported");
    if (reader.readBit() || reader.readBit())
        throw HandoverRefused(HandoverRefusal::INVALID_CONTEXT_IDENTITY,
                              "Unsupported Global-ENB-ID extension in TargetID");
    auto idPlmn = ReadFixedOctets(reader, 3);
    if (reader.readBit() || reader.readBit())
        throw HandoverRefused(HandoverRefusal::INVALID_CONTEXT_IDENTITY,
                              "Only macroENB-ID is supported in TargetID");
    reader.align();
    const auto enbId = static_cast<uint32_t>(reader.readBits(20));
    if (reader.readBit() || reader.readBit())
        throw HandoverRefused(HandoverRefusal::INVALID_CONTEXT_IDENTITY,
                              "Unsupported TAI extension in TargetID");
    auto taiPlmn = ReadFixedOctets(reader, 3);
    const auto tac = static_cast<uint16_t>(reader.readBits(16));
    if (!std::equal(idPlmn.begin(), idPlmn.end(), taiPlmn.begin(), taiPlmn.end()))
        throw HandoverRefused(HandoverRefusal::INVALID_CONTEXT_IDENTITY,
                              "TargetID names two different PLMN identities");
    EnbIdentity identity{};
    identity.plmn = DecodePlmn(idPlmn.data(), idPlmn.size());
    identity.enbId = enbId;
    identity.tac = tac;
    return identity;
}

std::vector<uint8_t> EncodeTargetId(const EnbIdentity &identity)
{
    BitWriter writer;
    writer.writeBit(false); // TargetID CHOICE extension marker
    writer.writeBits(0, 2); // targeteNB-ID
    WriteEnbIdentity(writer, identity);
    return writer.take();
}

EnbIdentity ReadTargetId(const std::vector<uint8_t> &value)
{
    BitReader reader(value);
    if (reader.readBit())
        throw HandoverRefused(HandoverRefusal::INVALID_CONTEXT_IDENTITY,
                              "Extended TargetID choice is not supported");
    const auto index = reader.readBits(2);
    if (index != 0)
        throw HandoverRefused(HandoverRefusal::INVALID_CONTEXT_IDENTITY,
                              "Only the targeteNB-ID TargetID choice is supported");
    auto identity = ReadEnbIdentity(reader);
    reader.requireFinished();
    return identity;
}

// --- Security context -------------------------------------------------------
//
// SecurityContext ::= SEQUENCE { nextHopChainingCount INTEGER (0..7),
//                                nextHopParameter SecurityKey,
//                                iE-Extensions ... OPTIONAL, ... }.
// This is handover security material. It is taken from the MME's signalling and
// is never generated here, never defaulted and never logged.

void WriteSecurityContext(BitWriter &writer, const SecurityContext &context)
{
    writer.writeBit(false); // SEQUENCE extension marker
    writer.writeBit(false); // iE-Extensions absent
    WriteConstrained(writer, context.nextHopChainingCount, 0, 7, false);
    WriteSecurityKey(writer, context.nextHopParameter);
}

SecurityContext ReadSecurityContext(BitReader &reader)
{
    if (reader.readBit())
        throw HandoverRefused(HandoverRefusal::MISSING_MANDATORY_IE,
                              "Extended SecurityContext is not supported");
    if (reader.readBit())
        throw HandoverRefused(HandoverRefusal::MISSING_MANDATORY_IE,
                              "SecurityContext extensions are not supported");
    SecurityContext context{};
    context.nextHopChainingCount = static_cast<uint8_t>(ReadConstrained(reader, 0, 7, false));
    context.nextHopParameter = ReadSecurityKey(reader);
    return context;
}

// --- E-RAB item shapes ------------------------------------------------------
//
// There are three E-RABToBeSetup item shapes in S1AP and they do not share a
// field order. CtxtSUReq is (id, QoS, transport, TEID, optional NAS);
// BearerSUReq is (id, QoS, transport, TEID, mandatory NAS); HOReq is
// (id, transport, TEID, QoS). Reading one with another's layout consumes the
// wrong number of bits and shifts every following field, so this third shape
// gets its own encoder and its own decoder.

void WriteErabToBeSetupItemHoReq(BitWriter &writer, const ErabToBeSetupItemHoReq &item)
{
    if (!item.qos.valid())
        throw HandoverRefused(HandoverRefusal::UNSUPPORTED_ERAB_LIST,
                              "E-RABToBeSetupItemHOReq carries invalid QoS");
    // A non-GBR QCI carries no GBR QoS Information. Fabricating one here would
    // advertise a guaranteed bitrate that the bearer was never given.
    if (item.qos.qci > 4 && item.qos.gbr.has_value())
        throw HandoverRefused(HandoverRefusal::UNSUPPORTED_ERAB_LIST,
                              "A non-GBR QCI must not carry GBR QoS Information");
    writer.writeBit(false); // SEQUENCE extension marker
    writer.writeBit(false); // iE-Extensions absent
    WriteErabId(writer, item.erabId);
    WriteTransportLayerAddress(writer, item.sgwAddress);
    WriteFixedOctets(writer, item.sgwTeid.data(), item.sgwTeid.size());
    WriteErabLevelQos(writer, item.qos.qci, item.qos.priorityLevel, item.qos.preemptionCapability,
                      item.qos.preemptionVulnerability, item.qos.gbr);
}

// ReadErabLevelQos and ReadArp write into the CtxtSUReq item shape. Reusing
// them for the handover item means collecting the negotiated QoS through that
// shape and copying it out, rather than duplicating the ARP and GBR readers.
ErabQos ReadErabLevelQosAsQos(BitReader &reader)
{
    ErabToBeSetupItem carrier{};
    ReadErabLevelQos(reader, carrier);
    ErabQos qos;
    qos.qci = carrier.qci;
    qos.priorityLevel = carrier.priorityLevel;
    qos.preemptionCapability = carrier.preemptionCapability;
    qos.preemptionVulnerability = carrier.preemptionVulnerability;
    qos.gbr = carrier.gbr;
    return qos;
}

ErabToBeSetupItemHoReq ReadErabToBeSetupItemHoReq(BitReader &reader)
{
    if (reader.readBit())
        throw HandoverRefused(HandoverRefusal::UNSUPPORTED_ERAB_LIST,
                              "Extended E-RABToBeSetupItemHOReq is not supported");
    const bool extensionsPresent = reader.readBit();
    ErabToBeSetupItemHoReq item{};
    item.erabId = ReadErabId(reader);
    item.sgwAddress = ReadTransportLayerAddress(reader);
    auto teid = ReadFixedOctets(reader, 4);
    std::copy(teid.begin(), teid.end(), item.sgwTeid.begin());
    item.qos = ReadErabLevelQosAsQos(reader);
    if (extensionsPresent)
        throw HandoverRefused(HandoverRefusal::UNSUPPORTED_ERAB_LIST,
                              "E-RABToBeSetupItemHOReq extensions are not supported");
    if (!item.qos.valid())
        throw HandoverRefused(HandoverRefusal::UNSUPPORTED_ERAB_LIST,
                              "E-RABToBeSetupItemHOReq carries invalid QoS");
    if (item.qos.qci > 4 && item.qos.gbr.has_value())
        throw HandoverRefused(HandoverRefusal::UNSUPPORTED_ERAB_LIST,
                              "A non-GBR QCI must not carry GBR QoS Information");
    return item;
}

// E-RABAdmittedItem and E-RABDataForwardingItem both carry up to two optional
// forwarding endpoints, each an address and a TEID. An address without its TEID
// is not an endpoint, so the pair is admitted or refused together.
//
// In APER a SEQUENCE writes its extension marker, then one presence bit per
// OPTIONAL field in declaration order, and only then the fields themselves.
// The presence bitmap therefore comes before the mandatory e-RAB-ID, not after
// it: writing it at the end shifts every field by its own width and the item
// decodes as a different bearer.
void WriteForwardingPresence(BitWriter &writer, bool dlPresent, bool ulPresent)
{
    writer.writeBit(dlPresent); // dL-transportLayerAddress
    writer.writeBit(dlPresent); // dL-gTP-TEID
    writer.writeBit(ulPresent); // uL-TransportLayerAddress
    writer.writeBit(ulPresent); // uL-gTP-TEID
    writer.writeBit(false);     // iE-Extensions
}

void WriteForwardingPairs(BitWriter &writer, bool dlPresent, const std::array<uint8_t, 4> &dlAddress,
                          const std::array<uint8_t, 4> &dlTeid, bool ulPresent,
                          const std::array<uint8_t, 4> &ulAddress, const std::array<uint8_t, 4> &ulTeid)
{
    if (dlPresent)
    {
        WriteTransportLayerAddress(writer, dlAddress);
        WriteFixedOctets(writer, dlTeid.data(), dlTeid.size());
    }
    if (ulPresent)
    {
        WriteTransportLayerAddress(writer, ulAddress);
        WriteFixedOctets(writer, ulTeid.data(), ulTeid.size());
    }
}

struct ForwardingPairs
{
    bool dlPresent{false};
    std::array<uint8_t, 4> dlAddress{};
    std::array<uint8_t, 4> dlTeid{};
    bool ulPresent{false};
    std::array<uint8_t, 4> ulAddress{};
    std::array<uint8_t, 4> ulTeid{};
    bool extensionsPresent{false};
};

ForwardingPairs ReadForwardingPresence(BitReader &reader, const char *what)
{
    ForwardingPairs pairs{};
    const bool dlAddress = reader.readBit();
    const bool dlTeid = reader.readBit();
    const bool ulAddress = reader.readBit();
    const bool ulTeid = reader.readBit();
    pairs.extensionsPresent = reader.readBit();
    if (dlAddress != dlTeid || ulAddress != ulTeid)
        throw HandoverRefused(HandoverRefusal::UNSUPPORTED_ERAB_LIST,
                              std::string(what) + " names a half-specified forwarding endpoint");
    pairs.dlPresent = dlAddress;
    pairs.ulPresent = ulAddress;
    return pairs;
}

void ReadForwardingPairs(BitReader &reader, ForwardingPairs &pairs, const char *what)
{
    if (pairs.dlPresent)
    {
        pairs.dlAddress = ReadTransportLayerAddress(reader);
        auto value = ReadFixedOctets(reader, 4);
        std::copy(value.begin(), value.end(), pairs.dlTeid.begin());
    }
    if (pairs.ulPresent)
    {
        pairs.ulAddress = ReadTransportLayerAddress(reader);
        auto value = ReadFixedOctets(reader, 4);
        std::copy(value.begin(), value.end(), pairs.ulTeid.begin());
    }
    if (pairs.extensionsPresent)
        throw HandoverRefused(HandoverRefusal::UNSUPPORTED_ERAB_LIST,
                              std::string(what) + " extensions are not supported");
}

void WriteErabAdmittedItem(BitWriter &writer, const ErabAdmittedItem &item)
{
    writer.writeBit(false); // SEQUENCE extension marker
    WriteForwardingPresence(writer, item.dlForwardingPresent, item.ulForwardingPresent);
    WriteErabId(writer, item.erabId);
    WriteTransportLayerAddress(writer, item.transportLayerAddress);
    WriteFixedOctets(writer, item.gtpTeid.data(), item.gtpTeid.size());
    WriteForwardingPairs(writer, item.dlForwardingPresent, item.dlTransportLayerAddress, item.dlGtpTeid,
                         item.ulForwardingPresent, item.ulTransportLayerAddress, item.ulGtpTeid);
}

ErabAdmittedItem ReadErabAdmittedItem(BitReader &reader)
{
    if (reader.readBit())
        throw HandoverRefused(HandoverRefusal::UNSUPPORTED_ERAB_LIST,
                              "Extended E-RABAdmittedItem is not supported");
    auto pairs = ReadForwardingPresence(reader, "E-RABAdmittedItem");
    ErabAdmittedItem item{};
    item.erabId = ReadErabId(reader);
    item.transportLayerAddress = ReadTransportLayerAddress(reader);
    auto teid = ReadFixedOctets(reader, 4);
    std::copy(teid.begin(), teid.end(), item.gtpTeid.begin());
    ReadForwardingPairs(reader, pairs, "E-RABAdmittedItem");
    item.dlForwardingPresent = pairs.dlPresent;
    item.dlTransportLayerAddress = pairs.dlAddress;
    item.dlGtpTeid = pairs.dlTeid;
    item.ulForwardingPresent = pairs.ulPresent;
    item.ulTransportLayerAddress = pairs.ulAddress;
    item.ulGtpTeid = pairs.ulTeid;
    return item;
}

void WriteErabDataForwardingItem(BitWriter &writer, const ErabDataForwardingItem &item)
{
    writer.writeBit(false); // SEQUENCE extension marker
    WriteForwardingPresence(writer, item.dlForwardingPresent, item.ulForwardingPresent);
    WriteErabId(writer, item.erabId);
    WriteForwardingPairs(writer, item.dlForwardingPresent, item.dlTransportLayerAddress, item.dlGtpTeid,
                         item.ulForwardingPresent, item.ulTransportLayerAddress, item.ulGtpTeid);
}

ErabDataForwardingItem ReadErabDataForwardingItem(BitReader &reader)
{
    if (reader.readBit())
        throw HandoverRefused(HandoverRefusal::UNSUPPORTED_ERAB_LIST,
                              "Extended E-RABDataForwardingItem is not supported");
    auto pairs = ReadForwardingPresence(reader, "E-RABDataForwardingItem");
    ErabDataForwardingItem item{};
    item.erabId = ReadErabId(reader);
    ReadForwardingPairs(reader, pairs, "E-RABDataForwardingItem");
    item.dlForwardingPresent = pairs.dlPresent;
    item.dlTransportLayerAddress = pairs.dlAddress;
    item.dlGtpTeid = pairs.dlTeid;
    item.ulForwardingPresent = pairs.ulPresent;
    item.ulTransportLayerAddress = pairs.ulAddress;
    item.ulGtpTeid = pairs.ulTeid;
    return item;
}

void WriteErabFailedItemHoReqAck(BitWriter &writer, const ErabFailedItemHoReqAck &item)
{
    writer.writeBit(false); // SEQUENCE extension marker
    writer.writeBit(false); // iE-Extensions absent
    WriteErabId(writer, item.erabId);
    WriteCause(writer, item.causeCategory, item.causeValue);
}

ErabFailedItemHoReqAck ReadErabFailedItemHoReqAck(BitReader &reader)
{
    if (reader.readBit() || reader.readBit())
        throw HandoverRefused(HandoverRefusal::UNSUPPORTED_ERAB_LIST,
                              "Unsupported E-RABFailedToSetupItemHOReqAck extension");
    ErabFailedItemHoReqAck item{};
    item.erabId = ReadErabId(reader);
    ReadCause(reader, item.causeCategory, item.causeValue);
    return item;
}

// --- E-RAB lists ------------------------------------------------------------
//
// E-RAB-IE-ContainerList is SEQUENCE (SIZE(1..maxnoofE-RABs)) OF
// ProtocolIE-SingleContainer, so a list is a bounded run of ordinary IE fields
// whose value is one item. An empty list is not a list this codec produces or
// accepts: maxnoofE-RABs is 256 and the lower bound is one.

constexpr size_t MaxHoErabs = 256;

void AppendHoList(BitWriter &writer, uint16_t itemId, const std::vector<std::vector<uint8_t>> &items,
                  const char *what)
{
    if (items.empty() || items.size() > MaxHoErabs)
        throw HandoverRefused(HandoverRefusal::UNSUPPORTED_ERAB_LIST,
                              std::string(what) + " must carry 1..256 items");
    WriteConstrained(writer, items.size(), 1, MaxHoErabs, true);
    for (const auto &item : items)
        WriteIe(writer, itemId, Criticality::IGNORE, item);
}

// Decodes one E-RAB list into its raw item values, refusing an unexpected item
// identity, an unexpected item criticality, a duplicate E-RAB identity and a
// list outside the 1..256 bound. The caller decodes each item value with the
// reader that matches its shape.
template <typename Item, typename Reader>
std::vector<Item> ReadHoList(const std::vector<uint8_t> &value, uint16_t itemId, Reader readItem, const char *what)
{
    BitReader reader(value);
    const size_t count = ReadConstrained(reader, 1, MaxHoErabs, true);
    std::vector<Item> result;
    result.reserve(count);
    std::set<uint8_t> seen;
    for (size_t i = 0; i < count; ++i)
    {
        const auto id = static_cast<uint16_t>(ReadConstrained(reader, 0, 65535, true));
        if (id != itemId)
            throw HandoverRefused(HandoverRefusal::UNSUPPORTED_ERAB_LIST,
                                  std::string("Unexpected item identity in ") + what);
        if (reader.readBits(2) != static_cast<uint8_t>(Criticality::IGNORE))
            throw HandoverRefused(HandoverRefusal::UNSUPPORTED_ERAB_LIST,
                                  std::string("Invalid item criticality in ") + what);
        reader.align();
        auto itemValue = reader.readOpenType();
        BitReader itemReader(itemValue);
        Item item = readItem(itemReader);
        itemReader.requireFinished();
        if (!seen.insert(item.erabId).second)
            throw HandoverRefused(HandoverRefusal::UNSUPPORTED_ERAB_LIST,
                                  std::string("Duplicated E-RAB identity in ") + what);
        result.push_back(std::move(item));
    }
    reader.requireFinished();
    return result;
}

// --- Cause ------------------------------------------------------------------

std::vector<uint8_t> EncodeCauseValue(const std::string &category, int value)
{
    BitWriter writer;
    WriteCause(writer, category, value);
    return writer.take();
}

void DecodeCauseValue(const std::vector<uint8_t> &value, std::string &category, int &causeValue)
{
    BitReader reader(value);
    ReadCause(reader, category, causeValue);
    reader.requireFinished();
}

// --- UE-associated identities ----------------------------------------------

void RequireUeIdentities(uint32_t mmeUeS1apId, uint32_t enbUeS1apId, bool enbRequired, const char *what)
{
    if (mmeUeS1apId == 0)
        throw HandoverRefused(HandoverRefusal::INVALID_CONTEXT_IDENTITY,
                              std::string(what) + " has a zero MME-UE-S1AP-ID");
    if (enbRequired && enbUeS1apId == 0)
        throw HandoverRefused(HandoverRefusal::INVALID_CONTEXT_IDENTITY,
                              std::string(what) + " has a zero eNB-UE-S1AP-ID");
    if (enbRequired && enbUeS1apId > 0xFFFFFFU)
        throw HandoverRefused(HandoverRefusal::INVALID_CONTEXT_IDENTITY,
                              std::string(what) + " has an eNB-UE-S1AP-ID out of range");
}

} // namespace

const char *ToString(HandoverType type)
{
    switch (type)
    {
    case HandoverType::INTRA_LTE:
        return "intralte";
    case HandoverType::LTE_TO_UTRAN:
        return "ltetoutran";
    case HandoverType::LTE_TO_GERAN:
        return "ltetogeran";
    case HandoverType::UTRAN_TO_LTE:
        return "utrantolte";
    case HandoverType::GERAN_TO_LTE:
        return "gerantolte";
    case HandoverType::EPS_TO_5GS:
        return "eps-to-5gs";
    case HandoverType::FIVEGS_TO_EPS:
        return "fivegs-to-eps";
    }
    return "unknown";
}

const char *ToString(HandoverRefusal refusal)
{
    switch (refusal)
    {
    case HandoverRefusal::UNSUPPORTED_HANDOVER_TYPE:
        return "unsupported-handover-type";
    case HandoverRefusal::INVALID_TRANSPARENT_CONTAINER:
        return "invalid-transparent-container";
    case HandoverRefusal::MISSING_MANDATORY_IE:
        return "missing-mandatory-ie";
    case HandoverRefusal::UNSUPPORTED_ERAB_LIST:
        return "unsupported-erab-list";
    case HandoverRefusal::INVALID_CONTEXT_IDENTITY:
        return "invalid-context-identity";
    }
    return "unknown";
}

// --- Handover Required (procedure 0, initiating) ----------------------------

std::vector<uint8_t> EncodeHandoverRequired(const HandoverRequired &message)
{
    RequireUeIdentities(message.mmeUeS1apId, message.enbUeS1apId, true, "Handover Required");
    std::vector<std::pair<std::pair<uint16_t, Criticality>, std::vector<uint8_t>>> ies;
    ies.push_back({{IE_MME_UE_S1AP_ID, Criticality::REJECT}, EncodeUeId(message.mmeUeS1apId, 0xFFFFFFFFU)});
    ies.push_back({{IE_ENB_UE_S1AP_ID, Criticality::REJECT}, EncodeUeId(message.enbUeS1apId, 0xFFFFFFU)});
    {
        BitWriter writer;
        WriteHandoverType(writer, message.handoverType);
        ies.push_back({{IE_HANDOVER_TYPE, Criticality::REJECT}, writer.take()});
    }
    ies.push_back({{IE_CAUSE, Criticality::IGNORE},
                   EncodeCauseValue(message.causeCategory, message.causeValue)});
    ies.push_back({{IE_TARGET_ID, Criticality::REJECT}, EncodeTargetId(message.target)});
    // Direct-Forwarding-Path-Availability is ENUMERATED { directPathAvailable,
    // ... }: one root value, so the enumeration carries no index at all and the
    // information element's presence is the whole statement. It is emitted only
    // when direct forwarding is available.
    if (message.directForwardingPathAvailable)
    {
        BitWriter writer;
        writer.writeBit(false); // root enumeration
        ies.push_back({{IE_DIRECT_FORWARDING_PATH_AVAILABILITY, Criticality::IGNORE}, writer.take()});
    }
    ies.push_back({{IE_SOURCE_TO_TARGET_TRANSPARENT_CONTAINER, Criticality::REJECT},
                   EncodeOpaqueContainer(message.sourceToTarget)});
    return EncodePdu(0, PROCEDURE_HANDOVER_PREPARATION, Criticality::REJECT, ies);
}

HandoverRequired DecodeHandoverRequired(const uint8_t *data, size_t length)
{
    auto envelope = DecodeEnvelope(data, length, PROCEDURE_HANDOVER_PREPARATION,
                                   static_cast<int>(Criticality::REJECT));
    if (envelope.choice != 0)
        throw CodecError("Handover Required is not an initiating message");

    HandoverRequired result{};
    bool mmePresent = false;
    bool enbPresent = false;
    bool typePresent = false;
    bool causePresent = false;
    bool targetPresent = false;
    bool containerPresent = false;
    bool directPath = false;

    for (const auto &ie : DecodeIeContainer(envelope.value))
    {
        if (ie.id == IE_MME_UE_S1AP_ID)
        {
            if (ie.criticality != Criticality::REJECT)
                throw HandoverRefused(HandoverRefusal::MISSING_MANDATORY_IE,
                                      "MME-UE-S1AP-ID has invalid criticality in Handover Required");
            result.mmeUeS1apId = DecodeUeId(ie.value, 0xFFFFFFFFU);
            mmePresent = true;
        }
        else if (ie.id == IE_ENB_UE_S1AP_ID)
        {
            if (ie.criticality != Criticality::REJECT)
                throw HandoverRefused(HandoverRefusal::MISSING_MANDATORY_IE,
                                      "eNB-UE-S1AP-ID has invalid criticality in Handover Required");
            result.enbUeS1apId = DecodeUeId(ie.value, 0xFFFFFFU);
            enbPresent = true;
        }
        else if (ie.id == IE_HANDOVER_TYPE)
        {
            if (ie.criticality != Criticality::REJECT)
                throw HandoverRefused(HandoverRefusal::MISSING_MANDATORY_IE,
                                      "HandoverType has invalid criticality in Handover Required");
            BitReader reader(ie.value);
            result.handoverType = ReadHandoverType(reader);
            reader.requireFinished();
            typePresent = true;
        }
        else if (ie.id == IE_CAUSE)
        {
            if (ie.criticality != Criticality::IGNORE)
                throw HandoverRefused(HandoverRefusal::MISSING_MANDATORY_IE,
                                      "Cause has invalid criticality in Handover Required");
            DecodeCauseValue(ie.value, result.causeCategory, result.causeValue);
            causePresent = true;
        }
        else if (ie.id == IE_TARGET_ID)
        {
            if (ie.criticality != Criticality::REJECT)
                throw HandoverRefused(HandoverRefusal::MISSING_MANDATORY_IE,
                                      "TargetID has invalid criticality in Handover Required");
            result.target = ReadTargetId(ie.value);
            targetPresent = true;
        }
        else if (ie.id == IE_DIRECT_FORWARDING_PATH_AVAILABILITY)
        {
            // Presence means directPathAvailable. The enumeration has one root
            // value, so its only content bit is the extension marker, which
            // must be clear: there is no second value to choose.
            if (ie.criticality != Criticality::IGNORE)
                throw HandoverRefused(HandoverRefusal::MISSING_MANDATORY_IE,
                                      "Direct-Forwarding-Path-Availability has invalid criticality");
            BitReader reader(ie.value);
            if (reader.readBit())
                throw HandoverRefused(HandoverRefusal::MISSING_MANDATORY_IE,
                                      "Extended Direct-Forwarding-Path-Availability is not supported");
            while (reader.remainingBits() != 0)
            {
                if (reader.readBit())
                    throw HandoverRefused(HandoverRefusal::MISSING_MANDATORY_IE,
                                          "Malformed Direct-Forwarding-Path-Availability");
            }
            directPath = true;
        }
        else if (ie.id == IE_SOURCE_TO_TARGET_TRANSPARENT_CONTAINER)
        {
            if (ie.criticality != Criticality::REJECT)
                throw HandoverRefused(HandoverRefusal::MISSING_MANDATORY_IE,
                                      "Source-ToTarget-TransparentContainer has invalid criticality");
            result.sourceToTarget = DecodeOpaqueContainer(ie.value);
            containerPresent = true;
        }
        else if (ie.id == IE_SOURCE_TO_TARGET_TRANSPARENT_CONTAINER_SECONDARY ||
                 ie.id == IE_TARGET_TO_SOURCE_TRANSPARENT_CONTAINER_SECONDARY)
            throw HandoverRefused(HandoverRefusal::INVALID_TRANSPARENT_CONTAINER,
                                  "A secondary transparent container is not an intra-LTE element");
        else if (ie.criticality == Criticality::REJECT)
            throw HandoverRefused(HandoverRefusal::MISSING_MANDATORY_IE,
                                  "Unexpected reject-criticality IE in Handover Required");
    }

    if (!mmePresent || !enbPresent || !typePresent || !causePresent || !targetPresent || !containerPresent)
        throw HandoverRefused(HandoverRefusal::MISSING_MANDATORY_IE,
                              "Handover Required is missing a mandatory information element");
    RequireUeIdentities(result.mmeUeS1apId, result.enbUeS1apId, true, "Handover Required");
    result.directForwardingPathAvailable = directPath;
    return result;
}

// --- Handover Command (procedure 0, successful outcome) ---------------------

std::vector<uint8_t> EncodeHandoverCommand(const HandoverCommand &message)
{
    RequireUeIdentities(message.mmeUeS1apId, message.enbUeS1apId, true, "Handover Command");

    std::vector<uint8_t> forwardingList;
    if (!message.dataForwarding.empty())
    {
        std::vector<std::vector<uint8_t>> items;
        items.reserve(message.dataForwarding.size());
        for (const auto &item : message.dataForwarding)
        {
            BitWriter writer;
            WriteErabDataForwardingItem(writer, item);
            items.push_back(writer.take());
        }
        BitWriter list;
        AppendHoList(list, IE_E_RAB_DATA_FORWARDING_ITEM, items, "E-RABSubjecttoDataForwardingList");
        forwardingList = list.take();
    }

    std::vector<std::pair<std::pair<uint16_t, Criticality>, std::vector<uint8_t>>> ies;
    ies.push_back({{IE_MME_UE_S1AP_ID, Criticality::REJECT}, EncodeUeId(message.mmeUeS1apId, 0xFFFFFFFFU)});
    ies.push_back({{IE_ENB_UE_S1AP_ID, Criticality::REJECT}, EncodeUeId(message.enbUeS1apId, 0xFFFFFFU)});
    {
        BitWriter writer;
        WriteHandoverType(writer, message.handoverType);
        ies.push_back({{IE_HANDOVER_TYPE, Criticality::REJECT}, writer.take()});
    }
    if (!forwardingList.empty())
        ies.push_back({{IE_E_RAB_SUBJECT_TO_DATA_FORWARDING_LIST, Criticality::IGNORE}, forwardingList});
    ies.push_back({{IE_TARGET_TO_SOURCE_TRANSPARENT_CONTAINER, Criticality::REJECT},
                   EncodeOpaqueContainer(message.targetToSource)});
    return EncodePdu(1, PROCEDURE_HANDOVER_PREPARATION, Criticality::REJECT, ies);
}

HandoverCommand DecodeHandoverCommand(const uint8_t *data, size_t length)
{
    auto envelope = DecodeEnvelope(data, length, PROCEDURE_HANDOVER_PREPARATION,
                                   static_cast<int>(Criticality::REJECT));
    if (envelope.choice != 1)
        throw CodecError("Handover Command is not a successful outcome message");

    HandoverCommand result{};
    bool mmePresent = false;
    bool enbPresent = false;
    bool typePresent = false;
    bool containerPresent = false;

    for (const auto &ie : DecodeIeContainer(envelope.value))
    {
        if (ie.id == IE_MME_UE_S1AP_ID)
        {
            if (ie.criticality != Criticality::REJECT)
                throw HandoverRefused(HandoverRefusal::MISSING_MANDATORY_IE,
                                      "MME-UE-S1AP-ID has invalid criticality in Handover Command");
            result.mmeUeS1apId = DecodeUeId(ie.value, 0xFFFFFFFFU);
            mmePresent = true;
        }
        else if (ie.id == IE_ENB_UE_S1AP_ID)
        {
            if (ie.criticality != Criticality::REJECT)
                throw HandoverRefused(HandoverRefusal::MISSING_MANDATORY_IE,
                                      "eNB-UE-S1AP-ID has invalid criticality in Handover Command");
            result.enbUeS1apId = DecodeUeId(ie.value, 0xFFFFFFU);
            enbPresent = true;
        }
        else if (ie.id == IE_HANDOVER_TYPE)
        {
            if (ie.criticality != Criticality::REJECT)
                throw HandoverRefused(HandoverRefusal::MISSING_MANDATORY_IE,
                                      "HandoverType has invalid criticality in Handover Command");
            BitReader reader(ie.value);
            result.handoverType = ReadHandoverType(reader);
            reader.requireFinished();
            typePresent = true;
        }
        else if (ie.id == IE_E_RAB_SUBJECT_TO_DATA_FORWARDING_LIST)
        {
            if (ie.criticality != Criticality::IGNORE)
                throw HandoverRefused(HandoverRefusal::MISSING_MANDATORY_IE,
                                      "E-RABSubjecttoDataForwardingList has invalid criticality");
            result.dataForwarding = ReadHoList<ErabDataForwardingItem>(
                ie.value, IE_E_RAB_DATA_FORWARDING_ITEM, ReadErabDataForwardingItem,
                "E-RABSubjecttoDataForwardingList");
        }
        else if (ie.id == IE_E_RAB_TO_RELEASE_LIST_HO_CMD)
        {
            // E-RABtoReleaseListHOCmd has type E-RABList, not
            // E-RABReleaseItemHOCmd. It names E-RABs the source eNB is to drop
            // after the handover, and Phase 18-A models no source-side
            // post-handover release, so the list is recognised and left alone
            // rather than decoded into a shape it does not have.
            if (ie.criticality != Criticality::IGNORE)
                throw HandoverRefused(HandoverRefusal::MISSING_MANDATORY_IE,
                                      "E-RABtoReleaseListHOCmd has invalid criticality");
        }
        else if (ie.id == IE_SOURCE_TO_TARGET_TRANSPARENT_CONTAINER_SECONDARY ||
                 ie.id == IE_TARGET_TO_SOURCE_TRANSPARENT_CONTAINER_SECONDARY)
        {
            // The secondary containers exist only for inter-RAT handover. An
            // intra-LTE handover carries neither; one that does is recognised
            // here and refused rather than passed through as an unknown IE.
            throw HandoverRefused(HandoverRefusal::INVALID_TRANSPARENT_CONTAINER,
                                  "A secondary transparent container is not an intra-LTE element");
        }
        else if (ie.id == IE_TARGET_TO_SOURCE_TRANSPARENT_CONTAINER)
        {
            if (ie.criticality != Criticality::REJECT)
                throw HandoverRefused(HandoverRefusal::MISSING_MANDATORY_IE,
                                      "Target-ToSource-TransparentContainer has invalid criticality");
            result.targetToSource = DecodeOpaqueContainer(ie.value);
            containerPresent = true;
        }
        else if (ie.criticality == Criticality::REJECT)
            throw HandoverRefused(HandoverRefusal::MISSING_MANDATORY_IE,
                                  "Unexpected reject-criticality IE in Handover Command");
    }

    if (!mmePresent || !enbPresent || !typePresent || !containerPresent)
        throw HandoverRefused(HandoverRefusal::MISSING_MANDATORY_IE,
                              "Handover Command is missing a mandatory information element");
    RequireUeIdentities(result.mmeUeS1apId, result.enbUeS1apId, true, "Handover Command");
    return result;
}

// --- Handover Preparation Failure (procedure 0, unsuccessful outcome) -------

std::vector<uint8_t> EncodeHandoverPreparationFailure(const HandoverPreparationFailure &message)
{
    RequireUeIdentities(message.mmeUeS1apId, message.enbUeS1apId, true, "Handover Preparation Failure");
    std::vector<std::pair<std::pair<uint16_t, Criticality>, std::vector<uint8_t>>> ies;
    ies.push_back({{IE_MME_UE_S1AP_ID, Criticality::IGNORE}, EncodeUeId(message.mmeUeS1apId, 0xFFFFFFFFU)});
    ies.push_back({{IE_ENB_UE_S1AP_ID, Criticality::IGNORE}, EncodeUeId(message.enbUeS1apId, 0xFFFFFFU)});
    ies.push_back({{IE_CAUSE, Criticality::IGNORE},
                   EncodeCauseValue(message.causeCategory, message.causeValue)});
    return EncodePdu(2, PROCEDURE_HANDOVER_PREPARATION, Criticality::REJECT, ies);
}

HandoverPreparationFailure DecodeHandoverPreparationFailure(const uint8_t *data, size_t length)
{
    auto envelope = DecodeEnvelope(data, length, PROCEDURE_HANDOVER_PREPARATION,
                                   static_cast<int>(Criticality::REJECT));
    if (envelope.choice != 2)
        throw CodecError("Handover Preparation Failure is not an unsuccessful outcome message");

    HandoverPreparationFailure result{};
    bool mmePresent = false;
    bool enbPresent = false;
    bool causePresent = false;

    for (const auto &ie : DecodeIeContainer(envelope.value))
    {
        if (ie.id == IE_MME_UE_S1AP_ID)
        {
            if (ie.criticality != Criticality::IGNORE)
                throw HandoverRefused(HandoverRefusal::MISSING_MANDATORY_IE,
                                      "MME-UE-S1AP-ID has invalid criticality in Handover Preparation Failure");
            result.mmeUeS1apId = DecodeUeId(ie.value, 0xFFFFFFFFU);
            mmePresent = true;
        }
        else if (ie.id == IE_ENB_UE_S1AP_ID)
        {
            if (ie.criticality != Criticality::IGNORE)
                throw HandoverRefused(HandoverRefusal::MISSING_MANDATORY_IE,
                                      "eNB-UE-S1AP-ID has invalid criticality in Handover Preparation Failure");
            result.enbUeS1apId = DecodeUeId(ie.value, 0xFFFFFFU);
            enbPresent = true;
        }
        else if (ie.id == IE_CAUSE)
        {
            if (ie.criticality != Criticality::IGNORE)
                throw HandoverRefused(HandoverRefusal::MISSING_MANDATORY_IE,
                                      "Cause has invalid criticality in Handover Preparation Failure");
            DecodeCauseValue(ie.value, result.causeCategory, result.causeValue);
            causePresent = true;
        }
        else if (ie.criticality == Criticality::REJECT)
            throw HandoverRefused(HandoverRefusal::MISSING_MANDATORY_IE,
                                  "Unexpected reject-criticality IE in Handover Preparation Failure");
    }

    if (!mmePresent || !enbPresent || !causePresent)
        throw HandoverRefused(HandoverRefusal::MISSING_MANDATORY_IE,
                              "Handover Preparation Failure is missing a mandatory information element");
    RequireUeIdentities(result.mmeUeS1apId, result.enbUeS1apId, true, "Handover Preparation Failure");
    return result;
}

// --- Handover Request (procedure 1, initiating) -----------------------------

std::vector<uint8_t> EncodeHandoverRequest(const HandoverRequest &message)
{
    RequireUeIdentities(message.mmeUeS1apId, 0, false, "Handover Request");

    std::vector<std::vector<uint8_t>> erabItems;
    erabItems.reserve(message.erabs.size());
    for (const auto &erab : message.erabs)
    {
        BitWriter writer;
        WriteErabToBeSetupItemHoReq(writer, erab);
        erabItems.push_back(writer.take());
    }

    BitWriter erabList;
    AppendHoList(erabList, IE_E_RAB_TO_BE_SETUP_ITEM_HO_REQ, erabItems, "E-RABToBeSetupListHOReq");

    BitWriter ambr;
    ambr.writeBit(false); // SEQUENCE extension marker
    ambr.writeBit(false); // iE-Extensions absent
    WriteBitRate(ambr, message.ueAmbr.downlink);
    WriteBitRate(ambr, message.ueAmbr.uplink);

    BitWriter capabilities;
    WriteUeSecurityCapabilities(capabilities, message.encryptionAlgorithms, message.integrityAlgorithms);

    BitWriter security;
    WriteSecurityContext(security, message.securityContext);

    std::vector<std::pair<std::pair<uint16_t, Criticality>, std::vector<uint8_t>>> ies;
    ies.push_back({{IE_MME_UE_S1AP_ID, Criticality::REJECT}, EncodeUeId(message.mmeUeS1apId, 0xFFFFFFFFU)});
    {
        BitWriter writer;
        WriteHandoverType(writer, message.handoverType);
        ies.push_back({{IE_HANDOVER_TYPE, Criticality::REJECT}, writer.take()});
    }
    ies.push_back({{IE_CAUSE, Criticality::IGNORE},
                   EncodeCauseValue(message.causeCategory, message.causeValue)});
    ies.push_back({{IE_UE_AGGREGATE_MAXIMUM_BITRATE, Criticality::REJECT}, ambr.take()});
    ies.push_back({{IE_E_RAB_TO_BE_SETUP_LIST_HO_REQ, Criticality::REJECT}, erabList.take()});
    ies.push_back({{IE_SOURCE_TO_TARGET_TRANSPARENT_CONTAINER, Criticality::REJECT},
                   EncodeOpaqueContainer(message.sourceToTarget)});
    ies.push_back({{IE_UE_SECURITY_CAPABILITIES, Criticality::REJECT}, capabilities.take()});
    ies.push_back({{IE_SECURITY_CONTEXT, Criticality::REJECT}, security.take()});
    return EncodePdu(0, PROCEDURE_HANDOVER_RESOURCE_ALLOCATION, Criticality::REJECT, ies);
}

HandoverRequest DecodeHandoverRequest(const uint8_t *data, size_t length)
{
    auto envelope = DecodeEnvelope(data, length, PROCEDURE_HANDOVER_RESOURCE_ALLOCATION,
                                   static_cast<int>(Criticality::REJECT));
    if (envelope.choice != 0)
        throw CodecError("Handover Request is not an initiating message");

    HandoverRequest result{};
    bool mmePresent = false;
    bool typePresent = false;
    bool causePresent = false;
    bool ambrPresent = false;
    bool erabsPresent = false;
    bool containerPresent = false;
    bool capabilitiesPresent = false;
    bool securityPresent = false;

    for (const auto &ie : DecodeIeContainer(envelope.value))
    {
        if (ie.id == IE_MME_UE_S1AP_ID)
        {
            if (ie.criticality != Criticality::REJECT)
                throw HandoverRefused(HandoverRefusal::MISSING_MANDATORY_IE,
                                      "MME-UE-S1AP-ID has invalid criticality in Handover Request");
            result.mmeUeS1apId = DecodeUeId(ie.value, 0xFFFFFFFFU);
            mmePresent = true;
        }
        else if (ie.id == IE_HANDOVER_TYPE)
        {
            if (ie.criticality != Criticality::REJECT)
                throw HandoverRefused(HandoverRefusal::MISSING_MANDATORY_IE,
                                      "HandoverType has invalid criticality in Handover Request");
            BitReader reader(ie.value);
            result.handoverType = ReadHandoverType(reader);
            reader.requireFinished();
            typePresent = true;
        }
        else if (ie.id == IE_CAUSE)
        {
            if (ie.criticality != Criticality::IGNORE)
                throw HandoverRefused(HandoverRefusal::MISSING_MANDATORY_IE,
                                      "Cause has invalid criticality in Handover Request");
            DecodeCauseValue(ie.value, result.causeCategory, result.causeValue);
            causePresent = true;
        }
        else if (ie.id == IE_UE_AGGREGATE_MAXIMUM_BITRATE)
        {
            if (ie.criticality != Criticality::REJECT)
                throw HandoverRefused(HandoverRefusal::MISSING_MANDATORY_IE,
                                      "UEAggregateMaximumBitrate has invalid criticality in Handover Request");
            BitReader reader(ie.value);
            if (reader.readBit() || reader.readBit())
                throw HandoverRefused(HandoverRefusal::MISSING_MANDATORY_IE,
                                      "Unsupported UEAggregateMaximumBitrate extension");
            result.ueAmbr.downlink = ReadBitRate(reader);
            result.ueAmbr.uplink = ReadBitRate(reader);
            reader.requireFinished();
            ambrPresent = true;
        }
        else if (ie.id == IE_E_RAB_TO_BE_SETUP_LIST_HO_REQ)
        {
            if (ie.criticality != Criticality::REJECT)
                throw HandoverRefused(HandoverRefusal::MISSING_MANDATORY_IE,
                                      "E-RABToBeSetupListHOReq has invalid criticality");
            result.erabs = ReadHoList<ErabToBeSetupItemHoReq>(
                ie.value, IE_E_RAB_TO_BE_SETUP_ITEM_HO_REQ, ReadErabToBeSetupItemHoReq,
                "E-RABToBeSetupListHOReq");
            erabsPresent = true;
        }
        else if (ie.id == IE_SOURCE_TO_TARGET_TRANSPARENT_CONTAINER)
        {
            if (ie.criticality != Criticality::REJECT)
                throw HandoverRefused(HandoverRefusal::MISSING_MANDATORY_IE,
                                      "Source-ToTarget-TransparentContainer has invalid criticality");
            result.sourceToTarget = DecodeOpaqueContainer(ie.value);
            containerPresent = true;
        }
        else if (ie.id == IE_UE_SECURITY_CAPABILITIES)
        {
            if (ie.criticality != Criticality::REJECT)
                throw HandoverRefused(HandoverRefusal::MISSING_MANDATORY_IE,
                                      "UESecurityCapabilities has invalid criticality in Handover Request");
            BitReader reader(ie.value);
            ReadUeSecurityCapabilities(reader, result.encryptionAlgorithms, result.integrityAlgorithms);
            reader.requireFinished();
            capabilitiesPresent = true;
        }
        else if (ie.id == IE_SECURITY_CONTEXT)
        {
            if (ie.criticality != Criticality::REJECT)
                throw HandoverRefused(HandoverRefusal::MISSING_MANDATORY_IE,
                                      "SecurityContext has invalid criticality in Handover Request");
            BitReader reader(ie.value);
            result.securityContext = ReadSecurityContext(reader);
            reader.requireFinished();
            securityPresent = true;
        }
        else if (ie.criticality == Criticality::REJECT)
            throw HandoverRefused(HandoverRefusal::MISSING_MANDATORY_IE,
                                  "Unexpected reject-criticality IE in Handover Request");
    }

    if (!mmePresent || !typePresent || !causePresent || !ambrPresent || !erabsPresent || !containerPresent ||
        !capabilitiesPresent || !securityPresent)
        throw HandoverRefused(HandoverRefusal::MISSING_MANDATORY_IE,
                              "Handover Request is missing a mandatory information element");
    RequireUeIdentities(result.mmeUeS1apId, 0, false, "Handover Request");
    return result;
}

// --- Handover Request Acknowledge (procedure 1, successful outcome) ---------

std::vector<uint8_t> EncodeHandoverRequestAcknowledge(const HandoverRequestAcknowledge &message)
{
    RequireUeIdentities(message.mmeUeS1apId, message.enbUeS1apId, true, "Handover Request Acknowledge");

    std::vector<std::vector<uint8_t>> admittedItems;
    admittedItems.reserve(message.admitted.size());
    for (const auto &item : message.admitted)
    {
        BitWriter writer;
        WriteErabAdmittedItem(writer, item);
        admittedItems.push_back(writer.take());
    }
    BitWriter admittedList;
    AppendHoList(admittedList, IE_E_RAB_ADMITTED_ITEM, admittedItems, "E-RABAdmittedList");

    std::vector<std::pair<std::pair<uint16_t, Criticality>, std::vector<uint8_t>>> ies;
    ies.push_back({{IE_MME_UE_S1AP_ID, Criticality::IGNORE}, EncodeUeId(message.mmeUeS1apId, 0xFFFFFFFFU)});
    ies.push_back({{IE_ENB_UE_S1AP_ID, Criticality::IGNORE}, EncodeUeId(message.enbUeS1apId, 0xFFFFFFU)});
    ies.push_back({{IE_E_RAB_ADMITTED_LIST, Criticality::IGNORE}, admittedList.take()});
    if (!message.failed.empty())
    {
        std::vector<std::vector<uint8_t>> failedItems;
        failedItems.reserve(message.failed.size());
        for (const auto &item : message.failed)
        {
            BitWriter writer;
            WriteErabFailedItemHoReqAck(writer, item);
            failedItems.push_back(writer.take());
        }
        BitWriter failedList;
        AppendHoList(failedList, IE_E_RAB_FAILED_TO_SETUP_ITEM_HO_REQ_ACK, failedItems,
                     "E-RABFailedToSetupListHOReqAck");
        ies.push_back({{IE_E_RAB_FAILED_TO_SETUP_LIST_HO_REQ_ACK, Criticality::IGNORE}, failedList.take()});
    }
    ies.push_back({{IE_TARGET_TO_SOURCE_TRANSPARENT_CONTAINER, Criticality::REJECT},
                   EncodeOpaqueContainer(message.targetToSource)});
    return EncodePdu(1, PROCEDURE_HANDOVER_RESOURCE_ALLOCATION, Criticality::REJECT, ies);
}

HandoverRequestAcknowledge DecodeHandoverRequestAcknowledge(const uint8_t *data, size_t length)
{
    auto envelope = DecodeEnvelope(data, length, PROCEDURE_HANDOVER_RESOURCE_ALLOCATION,
                                   static_cast<int>(Criticality::REJECT));
    if (envelope.choice != 1)
        throw CodecError("Handover Request Acknowledge is not a successful outcome message");

    HandoverRequestAcknowledge result{};
    bool mmePresent = false;
    bool enbPresent = false;
    bool admittedPresent = false;
    bool containerPresent = false;

    for (const auto &ie : DecodeIeContainer(envelope.value))
    {
        if (ie.id == IE_MME_UE_S1AP_ID)
        {
            if (ie.criticality != Criticality::IGNORE)
                throw HandoverRefused(HandoverRefusal::MISSING_MANDATORY_IE,
                                      "MME-UE-S1AP-ID has invalid criticality in Handover Request Acknowledge");
            result.mmeUeS1apId = DecodeUeId(ie.value, 0xFFFFFFFFU);
            mmePresent = true;
        }
        else if (ie.id == IE_ENB_UE_S1AP_ID)
        {
            if (ie.criticality != Criticality::IGNORE)
                throw HandoverRefused(HandoverRefusal::MISSING_MANDATORY_IE,
                                      "eNB-UE-S1AP-ID has invalid criticality in Handover Request Acknowledge");
            result.enbUeS1apId = DecodeUeId(ie.value, 0xFFFFFFU);
            enbPresent = true;
        }
        else if (ie.id == IE_E_RAB_ADMITTED_LIST)
        {
            if (ie.criticality != Criticality::IGNORE)
                throw HandoverRefused(HandoverRefusal::MISSING_MANDATORY_IE,
                                      "E-RABAdmittedList has invalid criticality");
            result.admitted = ReadHoList<ErabAdmittedItem>(ie.value, IE_E_RAB_ADMITTED_ITEM,
                                                          ReadErabAdmittedItem, "E-RABAdmittedList");
            admittedPresent = true;
        }
        else if (ie.id == IE_E_RAB_FAILED_TO_SETUP_LIST_HO_REQ_ACK)
        {
            if (ie.criticality != Criticality::IGNORE)
                throw HandoverRefused(HandoverRefusal::MISSING_MANDATORY_IE,
                                      "E-RABFailedToSetupListHOReqAck has invalid criticality");
            result.failed = ReadHoList<ErabFailedItemHoReqAck>(
                ie.value, IE_E_RAB_FAILED_TO_SETUP_ITEM_HO_REQ_ACK, ReadErabFailedItemHoReqAck,
                "E-RABFailedToSetupListHOReqAck");
        }
        else if (ie.id == IE_TARGET_TO_SOURCE_TRANSPARENT_CONTAINER)
        {
            if (ie.criticality != Criticality::REJECT)
                throw HandoverRefused(HandoverRefusal::MISSING_MANDATORY_IE,
                                      "Target-ToSource-TransparentContainer has invalid criticality");
            result.targetToSource = DecodeOpaqueContainer(ie.value);
            containerPresent = true;
        }
        else if (ie.criticality == Criticality::REJECT)
            throw HandoverRefused(HandoverRefusal::MISSING_MANDATORY_IE,
                                  "Unexpected reject-criticality IE in Handover Request Acknowledge");
    }

    if (!mmePresent || !enbPresent || !admittedPresent || !containerPresent)
        throw HandoverRefused(HandoverRefusal::MISSING_MANDATORY_IE,
                              "Handover Request Acknowledge is missing a mandatory information element");
    RequireUeIdentities(result.mmeUeS1apId, result.enbUeS1apId, true, "Handover Request Acknowledge");
    return result;
}

// --- Handover Failure (procedure 1, unsuccessful outcome) -------------------
//
// HandoverFailureIEs carries no eNB-UE-S1AP-ID: the target has failed before it
// bound one. A message that does carry one is not a Handover Failure.

std::vector<uint8_t> EncodeHandoverFailure(const HandoverFailure &message)
{
    RequireUeIdentities(message.mmeUeS1apId, 0, false, "Handover Failure");
    std::vector<std::pair<std::pair<uint16_t, Criticality>, std::vector<uint8_t>>> ies;
    ies.push_back({{IE_MME_UE_S1AP_ID, Criticality::IGNORE}, EncodeUeId(message.mmeUeS1apId, 0xFFFFFFFFU)});
    ies.push_back({{IE_CAUSE, Criticality::IGNORE},
                   EncodeCauseValue(message.causeCategory, message.causeValue)});
    return EncodePdu(2, PROCEDURE_HANDOVER_RESOURCE_ALLOCATION, Criticality::REJECT, ies);
}

HandoverFailure DecodeHandoverFailure(const uint8_t *data, size_t length)
{
    auto envelope = DecodeEnvelope(data, length, PROCEDURE_HANDOVER_RESOURCE_ALLOCATION,
                                   static_cast<int>(Criticality::REJECT));
    if (envelope.choice != 2)
        throw CodecError("Handover Failure is not an unsuccessful outcome message");

    HandoverFailure result{};
    bool mmePresent = false;
    bool causePresent = false;

    for (const auto &ie : DecodeIeContainer(envelope.value))
    {
        if (ie.id == IE_MME_UE_S1AP_ID)
        {
            if (ie.criticality != Criticality::IGNORE)
                throw HandoverRefused(HandoverRefusal::MISSING_MANDATORY_IE,
                                      "MME-UE-S1AP-ID has invalid criticality in Handover Failure");
            result.mmeUeS1apId = DecodeUeId(ie.value, 0xFFFFFFFFU);
            mmePresent = true;
        }
        else if (ie.id == IE_ENB_UE_S1AP_ID)
            throw HandoverRefused(HandoverRefusal::MISSING_MANDATORY_IE,
                                  "Handover Failure carries an eNB-UE-S1AP-ID it must not");
        else if (ie.id == IE_CAUSE)
        {
            if (ie.criticality != Criticality::IGNORE)
                throw HandoverRefused(HandoverRefusal::MISSING_MANDATORY_IE,
                                      "Cause has invalid criticality in Handover Failure");
            DecodeCauseValue(ie.value, result.causeCategory, result.causeValue);
            causePresent = true;
        }
        else if (ie.criticality == Criticality::REJECT)
            throw HandoverRefused(HandoverRefusal::MISSING_MANDATORY_IE,
                                  "Unexpected reject-criticality IE in Handover Failure");
    }

    if (!mmePresent || !causePresent)
        throw HandoverRefused(HandoverRefusal::MISSING_MANDATORY_IE,
                              "Handover Failure is missing a mandatory information element");
    RequireUeIdentities(result.mmeUeS1apId, 0, false, "Handover Failure");
    return result;
}

// --- Handover Notify (procedure 2, initiating) ------------------------------
//
// The procedure criticality of handoverNotification is ignore, not reject.
// Handover Notify carries no CriticalityDiagnostics.

std::vector<uint8_t> EncodeHandoverNotify(const HandoverNotify &message)
{
    RequireUeIdentities(message.mmeUeS1apId, message.enbUeS1apId, true, "Handover Notify");

    BitWriter cgi;
    cgi.writeBit(false); // EUTRAN-CGI extension marker
    cgi.writeBit(false); // EUTRAN-CGI iE-Extensions absent
    auto plmn = EncodePlmn(message.cgi.plmn);
    WriteFixedOctets(cgi, plmn.data(), plmn.size());
    cgi.writeBits(message.cgi.cellId & 0x0FFFFFFFU, 28);

    BitWriter tai;
    tai.writeBit(false); // TAI extension marker
    tai.writeBit(false); // TAI iE-Extensions absent
    auto taiPlmn = EncodePlmn(message.tai.plmn);
    WriteFixedOctets(tai, taiPlmn.data(), taiPlmn.size());
    tai.writeBits(message.tai.tac, 16);

    std::vector<std::pair<std::pair<uint16_t, Criticality>, std::vector<uint8_t>>> ies;
    ies.push_back({{IE_MME_UE_S1AP_ID, Criticality::REJECT}, EncodeUeId(message.mmeUeS1apId, 0xFFFFFFFFU)});
    ies.push_back({{IE_ENB_UE_S1AP_ID, Criticality::REJECT}, EncodeUeId(message.enbUeS1apId, 0xFFFFFFU)});
    ies.push_back({{IE_EUTRAN_CGI, Criticality::IGNORE}, cgi.take()});
    ies.push_back({{IE_TAI, Criticality::IGNORE}, tai.take()});
    return EncodePdu(0, PROCEDURE_HANDOVER_NOTIFICATION, Criticality::IGNORE, ies);
}

HandoverNotify DecodeHandoverNotify(const uint8_t *data, size_t length)
{
    auto envelope = DecodeEnvelope(data, length, PROCEDURE_HANDOVER_NOTIFICATION,
                                   static_cast<int>(Criticality::IGNORE));
    if (envelope.choice != 0)
        throw CodecError("Handover Notify is not an initiating message");

    HandoverNotify result{};
    bool mmePresent = false;
    bool enbPresent = false;
    bool cgiPresent = false;
    bool taiPresent = false;

    for (const auto &ie : DecodeIeContainer(envelope.value))
    {
        if (ie.id == IE_MME_UE_S1AP_ID)
        {
            if (ie.criticality != Criticality::REJECT)
                throw HandoverRefused(HandoverRefusal::MISSING_MANDATORY_IE,
                                      "MME-UE-S1AP-ID has invalid criticality in Handover Notify");
            result.mmeUeS1apId = DecodeUeId(ie.value, 0xFFFFFFFFU);
            mmePresent = true;
        }
        else if (ie.id == IE_ENB_UE_S1AP_ID)
        {
            if (ie.criticality != Criticality::REJECT)
                throw HandoverRefused(HandoverRefusal::MISSING_MANDATORY_IE,
                                      "eNB-UE-S1AP-ID has invalid criticality in Handover Notify");
            result.enbUeS1apId = DecodeUeId(ie.value, 0xFFFFFFU);
            enbPresent = true;
        }
        else if (ie.id == IE_EUTRAN_CGI)
        {
            if (ie.criticality != Criticality::IGNORE)
                throw HandoverRefused(HandoverRefusal::MISSING_MANDATORY_IE,
                                      "EUTRAN-CGI has invalid criticality in Handover Notify");
            BitReader reader(ie.value);
            if (reader.readBit() || reader.readBit())
                throw HandoverRefused(HandoverRefusal::INVALID_CONTEXT_IDENTITY,
                                      "Unsupported EUTRAN-CGI extension in Handover Notify");
            auto plmn = ReadFixedOctets(reader, 3);
            result.cgi.plmn = DecodePlmn(plmn.data(), plmn.size());
            result.cgi.cellId = static_cast<uint32_t>(reader.readBits(28));
            reader.requireFinished();
            cgiPresent = true;
        }
        else if (ie.id == IE_TAI)
        {
            if (ie.criticality != Criticality::IGNORE)
                throw HandoverRefused(HandoverRefusal::MISSING_MANDATORY_IE,
                                      "TAI has invalid criticality in Handover Notify");
            BitReader reader(ie.value);
            if (reader.readBit() || reader.readBit())
                throw HandoverRefused(HandoverRefusal::INVALID_CONTEXT_IDENTITY,
                                      "Unsupported TAI extension in Handover Notify");
            auto plmn = ReadFixedOctets(reader, 3);
            result.tai.plmn = DecodePlmn(plmn.data(), plmn.size());
            result.tai.tac = static_cast<uint16_t>(reader.readBits(16));
            reader.requireFinished();
            taiPresent = true;
        }
        else if (ie.criticality == Criticality::REJECT)
            throw HandoverRefused(HandoverRefusal::MISSING_MANDATORY_IE,
                                  "Unexpected reject-criticality IE in Handover Notify");
    }

    if (!mmePresent || !enbPresent || !cgiPresent || !taiPresent)
        throw HandoverRefused(HandoverRefusal::MISSING_MANDATORY_IE,
                              "Handover Notify is missing a mandatory information element");
    RequireUeIdentities(result.mmeUeS1apId, result.enbUeS1apId, true, "Handover Notify");
    return result;
}

} // namespace lte::enb::s1ap
