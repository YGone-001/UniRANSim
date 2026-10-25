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
constexpr uint16_t IE_EUTRAN_CGI = 100;
constexpr uint16_t IE_RRC_ESTABLISHMENT_CAUSE = 134;
constexpr uint16_t IE_S_TMSI = 96;

enum class Criticality : uint8_t
{
    REJECT = 0,
    IGNORE = 1,
    NOTIFY = 2
};

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
                       bool preemptionVulnerability)
{
    writer.writeBit(false); // SEQUENCE extension marker
    writer.writeBit(false); // gbrQosInformation absent
    writer.writeBit(false); // iE-Extensions absent
    WriteConstrained(writer, qci, 0, 255, true);
    WriteArp(writer, priorityLevel, preemptionCapability, preemptionVulnerability);
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
        throw CodecError("GBR-QosInformation is not supported for the default EPS bearer");
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
    item.transportLayerAddress = ReadTransportLayerAddress(reader);
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
                reader.readBits(2);
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
        WriteErabLevelQos(item, erab.qci, erab.priorityLevel, erab.preemptionCapability, erab.preemptionVulnerability);
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
                                                       const std::vector<ErabSetupItem> &erabs)
{
    if (mmeUeS1apId == 0 || enbUeS1apId == 0 || enbUeS1apId > 0xFFFFFFU)
        throw CodecError("Initial Context Setup Response has an invalid UE S1AP identity");
    if (erabs.empty() || erabs.size() > 256)
        throw CodecError("Initial Context Setup Response requires 1..256 established E-RABs");

    BitWriter list;
    WriteConstrained(list, erabs.size(), 1, 256, true);
    for (const auto &item : erabs)
        WriteIe(list, IE_E_RAB_SETUP_ITEM_CTXT_SU_RES, Criticality::IGNORE, EncodeErabSetupItem(item));
    auto listBytes = list.take();

    std::vector<std::pair<std::pair<uint16_t, Criticality>, std::vector<uint8_t>>> ies;
    ies.push_back({{IE_MME_UE_S1AP_ID, Criticality::REJECT}, EncodeUeId(mmeUeS1apId, 0xFFFFFFFFU)});
    ies.push_back({{IE_ENB_UE_S1AP_ID, Criticality::REJECT}, EncodeUeId(enbUeS1apId, 0xFFFFFFU)});
    ies.push_back({{IE_E_RAB_SETUP_LIST_CTXT_SU_RES, Criticality::IGNORE}, std::move(listBytes)});
    return EncodePdu(1, PROCEDURE_INITIAL_CONTEXT_SETUP, Criticality::REJECT, ies);
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

} // namespace lte::enb::s1ap
