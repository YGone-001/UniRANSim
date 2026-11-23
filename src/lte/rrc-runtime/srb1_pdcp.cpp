//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//

#include "srb1_pdcp.hpp"

namespace lte::pdcp
{

const char *ToString(SrbPdcpError error)
{
    switch (error)
    {
    case SrbPdcpError::MALFORMED_PDU: return "MALFORMED_PDU";
    case SrbPdcpError::RESERVED_BITS_SET: return "RESERVED_BITS_SET";
    case SrbPdcpError::DUPLICATE: return "DUPLICATE";
    case SrbPdcpError::OUT_OF_SEQUENCE: return "OUT_OF_SEQUENCE";
    case SrbPdcpError::COUNT_EXHAUSTED: return "COUNT_EXHAUSTED";
    case SrbPdcpError::RELEASED: return "RELEASED";
    }
    return "UNKNOWN_SRB_PDCP_ERROR";
}

SrbPdcpException::SrbPdcpException(SrbPdcpError reason)
    : std::runtime_error(std::string("SRB PDCP refusal: ") + ToString(reason)), reason_(reason)
{
}

SrbPdcpEntity SrbPdcpEntity::Create(bool uplink)
{
    SrbPdcpEntity entity;
    entity.uplink_ = uplink;
    return entity;
}

std::vector<uint8_t> SrbPdcpEntity::Protect(const std::vector<uint8_t> &sdu)
{
    if (released_)
        throw SrbPdcpException(SrbPdcpError::RELEASED);
    if (txCount_ >= 0x100000000ULL)
        throw SrbPdcpException(SrbPdcpError::COUNT_EXHAUSTED);

    // Octet 1: R(3) | SN(5). No D/C bit for SRBs, and pre-security there is no
    // MAC-I: the data follows the header directly.
    std::vector<uint8_t> pdu;
    pdu.reserve(HeaderBytes + sdu.size());
    pdu.push_back(static_cast<uint8_t>(static_cast<uint8_t>(txCount_ % SnModulus) & 0x1FU));
    pdu.insert(pdu.end(), sdu.begin(), sdu.end());
    txCount_++;
    return pdu;
}

std::vector<uint8_t> SrbPdcpEntity::Unprotect(const std::vector<uint8_t> &pdu)
{
    if (released_)
        throw SrbPdcpException(SrbPdcpError::RELEASED);
    if (pdu.size() < HeaderBytes)
    {
        refused_++;
        throw SrbPdcpException(SrbPdcpError::MALFORMED_PDU);
    }
    if ((pdu[0] & 0xE0U) != 0)
    {
        refused_++;
        throw SrbPdcpException(SrbPdcpError::RESERVED_BITS_SET);
    }

    const uint8_t sn = static_cast<uint8_t>(pdu[0] & 0x1FU);
    const uint8_t expected = static_cast<uint8_t>(rxCount_ % SnModulus);
    const uint8_t distance = static_cast<uint8_t>((sn + SnModulus - expected) % SnModulus);

    if (distance == 0)
    {
        std::vector<uint8_t> data(pdu.begin() + static_cast<long>(HeaderBytes), pdu.end());
        rxCount_++;
        delivered_++;
        return data;
    }

    refused_++;
    // The five-bit space is split in half: the nearer half is "ahead" (RLC AM
    // delivers in order, so this is a real gap), the other is "behind".
    if (distance < SnModulus / 2)
        throw SrbPdcpException(SrbPdcpError::OUT_OF_SEQUENCE);
    throw SrbPdcpException(SrbPdcpError::DUPLICATE);
}

void SrbPdcpEntity::Release() noexcept
{
    released_ = true;
}

} // namespace lte::pdcp
