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

constexpr uint16_t PROCEDURE_S1_SETUP = 17;
constexpr uint16_t IE_CAUSE = 2;
constexpr uint16_t IE_GLOBAL_ENB_ID = 59;
constexpr uint16_t IE_ENB_NAME = 60;
constexpr uint16_t IE_MME_NAME = 61;
constexpr uint16_t IE_SUPPORTED_TAS = 64;
constexpr uint16_t IE_TIME_TO_WAIT = 65;
constexpr uint16_t IE_RELATIVE_MME_CAPACITY = 87;
constexpr uint16_t IE_SERVED_GUMMEIS = 105;
constexpr uint16_t IE_DEFAULT_PAGING_DRX = 137;
constexpr uint16_t IE_CRITICALITY_DIAGNOSTICS = 58;

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

Envelope DecodeEnvelope(const uint8_t *data, size_t length)
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
    if (procedure != PROCEDURE_S1_SETUP)
        throw CodecError("Unexpected S1AP procedure code");
    auto criticality = reader.readBits(2);
    if (criticality != static_cast<uint8_t>(Criticality::REJECT))
        throw CodecError("Invalid S1 Setup procedure criticality");
    reader.align();
    auto value = reader.readOpenType();
    reader.requireFinished();
    return Envelope{choice, std::move(value)};
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
    auto envelope = DecodeEnvelope(data, length);
    if (envelope.choice != 0)
        throw CodecError("S1AP PDU is not an initiating message");
    return DecodeRequestIes(DecodeIeContainer(envelope.value));
}

SetupOutcome DecodeS1SetupOutcome(const uint8_t *data, size_t length)
{
    auto envelope = DecodeEnvelope(data, length);
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

} // namespace lte::enb::s1ap
