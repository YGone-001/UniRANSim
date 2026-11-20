//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//

#include "rlc_am.hpp"

namespace lte::rlc::am
{
namespace
{

// Explicit MSB-first bit writer. Compiler bitfields are never used for the wire
// format: their layout is implementation-defined.
class BitWriter
{
  public:
    void Write(uint64_t value, int bits)
    {
        for (int i = bits - 1; i >= 0; i--)
        {
            if (bit_ == 0)
                bytes_.push_back(0);
            const bool set = ((value >> i) & 1U) != 0;
            if (set)
                bytes_.back() |= static_cast<uint8_t>(0x80U >> bit_);
            bit_ = (bit_ + 1) & 7;
        }
    }

    void PadToOctet()
    {
        while (bit_ != 0)
            Write(0, 1);
    }

    [[nodiscard]] std::vector<uint8_t> Bytes() const
    {
        return bytes_;
    }

    [[nodiscard]] size_t BitCount() const
    {
        return bytes_.size() * 8 - (bit_ == 0 ? 0 : 8 - bit_) % 8;
    }

  private:
    std::vector<uint8_t> bytes_{};
    int bit_{0};
};

class BitReader
{
  public:
    BitReader(const uint8_t *data, size_t size) : data_(data), size_(size)
    {
    }

    bool Read(int bits, uint64_t &value)
    {
        value = 0;
        if (bits < 0 || Position() + static_cast<size_t>(bits) > size_ * 8)
            return false;
        for (int i = 0; i < bits; i++)
        {
            const size_t index = Position();
            const bool set = (data_[index / 8] & (0x80U >> (index % 8))) != 0;
            value = (value << 1U) | (set ? 1U : 0U);
            position_++;
        }
        return true;
    }

    [[nodiscard]] size_t Position() const
    {
        return position_;
    }

    [[nodiscard]] size_t Remaining() const
    {
        return size_ * 8 - position_;
    }

  private:
    const uint8_t *data_{nullptr};
    size_t size_{0};
    size_t position_{0};
};

[[noreturn]] void Fail(CodecError reason)
{
    throw CodecException(reason);
}

} // namespace

const char *ToString(CodecError error)
{
    switch (error)
    {
    case CodecError::TRUNCATED: return "TRUNCATED";
    case CodecError::BAD_DC: return "BAD_DC";
    case CodecError::BAD_RF: return "BAD_RF";
    case CodecError::RESERVED_LI: return "RESERVED_LI";
    case CodecError::PADDING_NOT_ZERO: return "PADDING_NOT_ZERO";
    case CodecError::TOO_MANY_LIS: return "TOO_MANY_LIS";
    case CodecError::BAD_SN: return "BAD_SN";
    case CodecError::BAD_SO: return "BAD_SO";
    case CodecError::BAD_NACK: return "BAD_NACK";
    }
    return "UNKNOWN_CODEC_ERROR";
}

CodecException::CodecException(CodecError reason)
    : std::runtime_error(std::string("RLC AM codec refusal: ") + ToString(reason)), reason_(reason)
{
}

std::vector<uint8_t> EncodeAmd(const AmdPdu &pdu)
{
    if (pdu.sn >= SnModulus)
        Fail(CodecError::BAD_SN);
    if (pdu.segment && pdu.so > SoMax)
        Fail(CodecError::BAD_SO);
    if (!pdu.li.empty() && pdu.li.size() > 15)
        Fail(CodecError::TOO_MANY_LIS);

    BitWriter writer;
    // Octet 1: D/C(1) RF(1) P(1) FI(2) E(1) SN[9:8](2)
    writer.Write(1, 1);                                  // D/C = data
    writer.Write(pdu.segment ? 1 : 0, 1);                // RF
    writer.Write(pdu.poll ? 1 : 0, 1);                   // P
    writer.Write(static_cast<uint64_t>(pdu.fi), 2);      // FI
    writer.Write(pdu.li.empty() ? 0 : 1, 1);             // E
    writer.Write((pdu.sn >> 8U) & 0x3U, 2);              // SN[9:8]
    writer.Write(pdu.sn & 0xFFU, 8);                     // octet 2: SN[7:0]

    if (pdu.segment)
    {
        // Octet 3: LSF(1) SO[14:8](7); octet 4: SO[7:0](8)
        writer.Write(pdu.lsf ? 1 : 0, 1);
        writer.Write((pdu.so >> 8U) & 0x7FU, 7);
        writer.Write(pdu.so & 0xFFU, 8);
    }

    for (size_t i = 0; i < pdu.li.size(); i++)
    {
        if (pdu.li[i] == 0)
            Fail(CodecError::RESERVED_LI);
        // E = 1 for every element but the last, whose E = 0 lets Data follow.
        writer.Write(i + 1 < pdu.li.size() ? 1 : 0, 1);
        writer.Write(pdu.li[i] & 0x7FFU, 11);
    }
    // An odd number of 11-bit LIs leaves four bits of padding.
    if (!pdu.li.empty() && (pdu.li.size() % 2) == 1)
        writer.Write(0, 4);

    for (uint8_t byte : pdu.data)
        writer.Write(byte, 8);
    writer.PadToOctet();
    return writer.Bytes();
}

bool DecodeAmd(const uint8_t *data, size_t size, AmdPdu &out, std::string *why)
{
    if (size < 2)
    {
        if (why)
            *why = "shorter than the fixed header";
        return false;
    }
    BitReader reader(data, size);
    uint64_t dc = 0, rf = 0, poll = 0, fi = 0, e = 0, snHigh = 0, snLow = 0;
    if (!reader.Read(1, dc) || !reader.Read(1, rf) || !reader.Read(1, poll) || !reader.Read(2, fi) ||
        !reader.Read(1, e) || !reader.Read(2, snHigh) || !reader.Read(8, snLow))
    {
        if (why)
            *why = "truncated fixed header";
        return false;
    }
    if (dc != 1)
    {
        if (why)
            *why = "D/C is not a data PDU";
        return false;
    }

    AmdPdu pdu;
    pdu.sn = static_cast<uint16_t>((snHigh << 8U) | snLow);
    pdu.poll = poll != 0;
    pdu.fi = static_cast<FramingInfo>(fi);
    pdu.segment = rf != 0;
    if (pdu.sn >= SnModulus)
    {
        if (why)
            *why = "SN above the modelled modulus";
        return false;
    }

    if (pdu.segment)
    {
        uint64_t lsf = 0, soHigh = 0, soLow = 0;
        if (!reader.Read(1, lsf) || !reader.Read(7, soHigh) || !reader.Read(8, soLow))
        {
            if (why)
                *why = "truncated segment header";
            return false;
        }
        pdu.lsf = lsf != 0;
        pdu.so = static_cast<uint16_t>((soHigh << 8U) | soLow);
        if (pdu.so > SoMax)
        {
            if (why)
                *why = "segment offset out of range";
            return false;
        }
    }

    // The header E says an extension part is present. Each element is
    // E(1) + LI(11); E=1 means another element follows, E=0 means the Data
    // field follows.
    if (e != 0)
    {
        size_t guard = 0;
        while (true)
        {
            if (++guard > 15)
            {
                if (why)
                    *why = "LI chain too long";
                return false;
            }
            uint64_t more = 0, li = 0;
            if (!reader.Read(1, more) || !reader.Read(11, li))
            {
                if (why)
                    *why = "truncated LI";
                return false;
            }
            if (li == 0)
            {
                if (why)
                    *why = "LI 0 is reserved";
                return false;
            }
            pdu.li.push_back(static_cast<uint16_t>(li));
            if (more == 0)
                break;
        }
    }
    // Odd LI count: four padding bits that must be zero.
    if (!pdu.li.empty() && (pdu.li.size() % 2) == 1)
    {
        uint64_t padding = 0;
        if (!reader.Read(4, padding))
        {
            if (why)
                *why = "truncated padding";
            return false;
        }
        if (padding != 0)
        {
            if (why)
                *why = "non-zero LI padding";
            return false;
        }
    }

    const size_t dataBytes = (reader.Remaining()) / 8;
    if (reader.Remaining() % 8 != 0)
    {
        if (why)
            *why = "data field is not octet aligned";
        return false;
    }
    pdu.data.resize(dataBytes);
    for (size_t i = 0; i < dataBytes; i++)
    {
        uint64_t byte = 0;
        reader.Read(8, byte);
        pdu.data[i] = static_cast<uint8_t>(byte);
    }

    // The LI chain must describe exactly the Data field.
    if (!pdu.li.empty())
    {
        size_t total = 0;
        for (uint16_t li : pdu.li)
            total += li;
        // n LIs describe the first n elements; the last element carries no LI,
        // so the sum may be smaller than the Data field but never larger.
        if (total > pdu.data.size())
        {
            if (why)
                *why = "LI chain does not match the data length";
            return false;
        }
    }

    out = pdu;
    return true;
}

std::vector<uint8_t> EncodeStatus(const StatusPdu &pdu)
{
    if (pdu.ackSn >= SnModulus)
        Fail(CodecError::BAD_SN);

    BitWriter writer;
    writer.Write(0, 1);  // D/C = control
    writer.Write(0, 3);  // CPT = 000 (STATUS)
    writer.Write(pdu.ackSn & 0x3FFU, 10);
    writer.Write(pdu.nacks.empty() ? 0 : 1, 1);  // E1

    for (size_t i = 0; i < pdu.nacks.size(); i++)
    {
        const auto &nack = pdu.nacks[i];
        if (nack.sn >= SnModulus)
            Fail(CodecError::BAD_NACK);
        const bool last = i + 1 == pdu.nacks.size();
        writer.Write(nack.sn & 0x3FFU, 10);
        writer.Write(last ? 0 : 1, 1);           // E1: another NACK follows
        writer.Write(nack.soRange ? 1 : 0, 1);   // E2
        if (nack.soRange)
        {
            if (nack.soRange->first > SoMax || nack.soRange->second > SoMax)
                Fail(CodecError::BAD_SO);
            writer.Write(nack.soRange->first, 15);
            writer.Write(nack.soRange->second, 15);
        }
    }
    writer.PadToOctet();
    return writer.Bytes();
}

bool DecodeStatus(const uint8_t *data, size_t size, StatusPdu &out, std::string *why)
{
    if (size < 1)
    {
        if (why)
            *why = "empty PDU";
        return false;
    }
    BitReader reader(data, size);
    uint64_t dc = 0, cpt = 0, ackSn = 0, e1 = 0;
    if (!reader.Read(1, dc) || !reader.Read(3, cpt) || !reader.Read(10, ackSn) || !reader.Read(1, e1))
    {
        if (why)
            *why = "truncated STATUS header";
        return false;
    }
    if (dc != 0 || cpt != 0)
    {
        if (why)
            *why = "not a STATUS PDU";
        return false;
    }

    StatusPdu pdu;
    pdu.ackSn = static_cast<uint16_t>(ackSn);
    uint64_t more = e1;
    while (more != 0)
    {
        uint64_t nackSn = 0, e1Next = 0, e2 = 0;
        if (!reader.Read(10, nackSn) || !reader.Read(1, e1Next) || !reader.Read(1, e2))
        {
            if (why)
                *why = "truncated NACK entry";
            return false;
        }
        StatusNack nack;
        nack.sn = static_cast<uint16_t>(nackSn);
        if (e2 != 0)
        {
            uint64_t soStart = 0, soEnd = 0;
            if (!reader.Read(15, soStart) || !reader.Read(15, soEnd))
            {
                if (why)
                    *why = "truncated segment range";
                return false;
            }
            nack.soRange = std::make_pair(static_cast<uint16_t>(soStart), static_cast<uint16_t>(soEnd));
        }
        pdu.nacks.push_back(nack);
        more = e1Next;
    }

    // Remaining bits are padding and must be zero.
    while (reader.Remaining() > 0)
    {
        uint64_t bit = 0;
        reader.Read(1, bit);
        if (bit != 0)
        {
            if (why)
                *why = "non-zero STATUS padding";
            return false;
        }
    }

    out = pdu;
    return true;
}

} // namespace lte::rlc::am
