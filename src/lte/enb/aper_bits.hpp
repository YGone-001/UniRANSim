//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

// The aligned-PER bit writer and reader every 36.413 structure in this
// repository is built with. They are shared by the S1AP message codec and the
// transparent-container codec so the two agree bit for bit on how a field is
// placed: one implementation of the encoding rules, not two that happen to
// match.

#pragma once

#include "codec.hpp"

#include <cstddef>
#include <cstdint>
#include <utility>
#include <vector>

namespace lte::enb::s1ap
{

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


// Aligned-PER field primitives shared by every 36.413 structure here.
// X.691 section 11: a constrained whole number in the range 256..65536 is
// written in the minimum number of octets and is octet-aligned; a fixed-size
// octet string of three or more octets is octet-aligned; a length determinant
// is octet-aligned.
inline size_t BitsForRange(size_t range)
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

inline void WriteConstrained(BitWriter &writer, size_t value, size_t lower, size_t upper, bool aligned)
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

inline size_t ReadConstrained(BitReader &reader, size_t lower, size_t upper, bool aligned)
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

inline void WriteFixedOctets(BitWriter &writer, const uint8_t *data, size_t length)
{
    if (length > 2)
        writer.align();
    for (size_t i = 0; i < length; ++i)
        writer.writeBits(data[i], 8);
}

inline std::vector<uint8_t> ReadFixedOctets(BitReader &reader, size_t length)
{
    if (length > 2)
        reader.align();
    std::vector<uint8_t> result;
    result.reserve(length);
    for (size_t i = 0; i < length; ++i)
        result.push_back(static_cast<uint8_t>(reader.readBits(8)));
    return result;
}


} // namespace lte::enb::s1ap
