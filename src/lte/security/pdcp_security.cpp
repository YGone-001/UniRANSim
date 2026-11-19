//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#include "pdcp_security.hpp"

#include <algorithm>
#include <cstring>

#include <lib/crypt/crypt.hpp>
#include <utils/octet_string.hpp>

namespace lte::security
{
namespace
{

constexpr uint32_t SnMask = 0x0FFFU;
constexpr uint32_t HfnStep = 0x1000U;
constexpr size_t HeaderSize = 2;
constexpr size_t MacSize = 4;

void SecureZero(uint8_t *data, size_t length) noexcept
{
    volatile uint8_t *cursor = data;
    while (length--)
        *cursor++ = 0;
}

void SecureZero(Key128 &value) noexcept
{
    SecureZero(value.data(), value.size());
}

bool AllZero(const Key128 &value)
{
    uint8_t accumulator = 0;
    for (uint8_t byte : value)
        accumulator |= byte;
    return accumulator == 0;
}

[[noreturn]] void Fail(PdcpSecurityError reason)
{
    throw PdcpSecurityException(reason);
}

} // namespace

const char *ToString(PdcpSecurityError error)
{
    switch (error)
    {
    case PdcpSecurityError::NOT_CONFIGURED: return "NOT_CONFIGURED";
    case PdcpSecurityError::ALGORITHM_UNSUPPORTED: return "ALGORITHM_UNSUPPORTED";
    case PdcpSecurityError::KEY_MISSING: return "KEY_MISSING";
    case PdcpSecurityError::PDU_TOO_SHORT: return "PDU_TOO_SHORT";
    case PdcpSecurityError::NOT_A_DATA_PDU: return "NOT_A_DATA_PDU";
    case PdcpSecurityError::INTEGRITY_FAILURE: return "INTEGRITY_FAILURE";
    case PdcpSecurityError::REPLAY_DETECTED: return "REPLAY_DETECTED";
    case PdcpSecurityError::COUNT_EXHAUSTED: return "COUNT_EXHAUSTED";
    }
    return "UNKNOWN_PDCP_ERROR";
}

PdcpSecurityException::PdcpSecurityException(PdcpSecurityError reason)
    : std::runtime_error(std::string("PDCP security refusal: ") + ToString(reason)), reason_(reason)
{
}

std::vector<uint8_t> ExtractPdcpPayload(const std::vector<uint8_t> &pdu, bool hasMac)
{
    const size_t trailer = hasMac ? MacSize : 0;
    if (pdu.size() < HeaderSize + trailer)
        Fail(PdcpSecurityError::PDU_TOO_SHORT);
    return std::vector<uint8_t>(pdu.begin() + HeaderSize, pdu.end() - trailer);
}

PdcpSecurityEntity::~PdcpSecurityEntity()
{
    SecureZero(kIntegrity_);
    SecureZero(kCiphering_);
}

PdcpSecurityEntity PdcpSecurityEntity::Create(uint8_t bearer, bool uplink, uint8_t integrityAlgorithm,
                                              uint8_t cipheringAlgorithm, const Key128 &kIntegrity,
                                              const Key128 &kCiphering)
{
    if (bearer == 0)
        Fail(PdcpSecurityError::NOT_CONFIGURED);
    if (integrityAlgorithm > 3 || cipheringAlgorithm > 3)
        Fail(PdcpSecurityError::ALGORITHM_UNSUPPORTED);
    if (integrityAlgorithm != 0 && AllZero(kIntegrity))
        Fail(PdcpSecurityError::KEY_MISSING);
    if (cipheringAlgorithm != 0 && AllZero(kCiphering))
        Fail(PdcpSecurityError::KEY_MISSING);

    PdcpSecurityEntity entity;
    entity.bearer_ = bearer;
    entity.uplink_ = uplink;
    entity.integrityAlgorithm_ = integrityAlgorithm;
    entity.cipheringAlgorithm_ = cipheringAlgorithm;
    entity.kIntegrity_ = kIntegrity;
    entity.kCiphering_ = kCiphering;
    return entity;
}

bool PdcpSecurityEntity::IntegrityProtects() const
{
    return integrityAlgorithm_ != 0;
}

bool PdcpSecurityEntity::CipheringProtects() const
{
    return cipheringAlgorithm_ != 0;
}

void PdcpSecurityEntity::ActivateIntegrity()
{
    if (bearer_ == 0)
        Fail(PdcpSecurityError::NOT_CONFIGURED);
    if (integrityAlgorithm_ != 0 && AllZero(kIntegrity_))
        Fail(PdcpSecurityError::KEY_MISSING);
    integrityActive_ = true;
}

void PdcpSecurityEntity::ActivateCiphering()
{
    if (bearer_ == 0)
        Fail(PdcpSecurityError::NOT_CONFIGURED);
    if (cipheringAlgorithm_ != 0 && AllZero(kCiphering_))
        Fail(PdcpSecurityError::KEY_MISSING);
    cipheringActive_ = true;
}

void PdcpSecurityEntity::DeactivateAll() noexcept
{
    integrityActive_ = false;
    cipheringActive_ = false;
}

uint32_t PdcpSecurityEntity::BuildCount(uint32_t sn) const
{
    // TS 36.323 5.5: COUNT = HFN || SN. The receiver reconstructs the HFN from
    // the SN it already accepted, so a 12-bit wrap becomes the next HFN.
    uint32_t count = (rxAny_ ? (rxCount_ & ~SnMask) : 0U) | (sn & SnMask);
    if (rxAny_ && count < rxCount_)
        count += HfnStep;
    return count;
}

uint32_t PdcpSecurityEntity::MacFor(uint32_t count, const uint8_t *data, size_t length) const
{
    const int direction = uplink_ ? 0 : 1;
    OctetString message = OctetString::FromArray(data, length);
    OctetString key = OctetString::FromArray(kIntegrity_.data(), kIntegrity_.size());
    switch (integrityAlgorithm_)
    {
    case 1: return crypto::ComputeMacEia1(count, bearer_, direction, message, key);
    case 2: return crypto::ComputeMacEia2(count, bearer_, direction, message, key);
    case 3: return crypto::ComputeMacEia3(count, bearer_, direction, message, key);
    default: Fail(PdcpSecurityError::ALGORITHM_UNSUPPORTED);
    }
}

std::vector<uint8_t> PdcpSecurityEntity::Protect(const std::vector<uint8_t> &plain)
{
    if (bearer_ == 0 || (!integrityActive_ && !cipheringActive_))
        Fail(PdcpSecurityError::NOT_CONFIGURED);
    if (txCount_ > 0xFFFFFFFFU - 1U)
        Fail(PdcpSecurityError::COUNT_EXHAUSTED);

    const uint32_t count = txCount_;
    const uint16_t header = static_cast<uint16_t>(0x8000U | (count & SnMask));

    std::vector<uint8_t> pdu;
    pdu.reserve(HeaderSize + plain.size() + (integrityActive_ ? MacSize : 0));
    pdu.push_back(static_cast<uint8_t>((header >> 8U) & 0xFFU));
    pdu.push_back(static_cast<uint8_t>(header & 0xFFU));
    pdu.insert(pdu.end(), plain.begin(), plain.end());

    uint32_t mac = 0;
    if (integrityActive_)
        mac = MacFor(count, pdu.data(), pdu.size());

    if (cipheringActive_ && !plain.empty())
    {
        const int direction = uplink_ ? 0 : 1;
        std::vector<uint8_t> data(plain.begin(), plain.end());
        OctetString body{std::move(data)};
        OctetString key = OctetString::FromArray(kCiphering_.data(), kCiphering_.size());
        switch (cipheringAlgorithm_)
        {
        case 1: crypto::EncryptEea1(count, bearer_, direction, body, key); break;
        case 2: crypto::EncryptEea2(count, bearer_, direction, body, key); break;
        case 3: crypto::EncryptEea3(count, bearer_, direction, body, key); break;
        default: Fail(PdcpSecurityError::ALGORITHM_UNSUPPORTED);
        }
        std::copy(body.data(), body.data() + body.length(), pdu.begin() + HeaderSize);
    }

    if (integrityActive_)
    {
        pdu.push_back(static_cast<uint8_t>((mac >> 24U) & 0xFFU));
        pdu.push_back(static_cast<uint8_t>((mac >> 16U) & 0xFFU));
        pdu.push_back(static_cast<uint8_t>((mac >> 8U) & 0xFFU));
        pdu.push_back(static_cast<uint8_t>(mac & 0xFFU));
    }

    txCount_++;
    return pdu;
}

std::vector<uint8_t> PdcpSecurityEntity::Unprotect(const std::vector<uint8_t> &pdu)
{
    if (bearer_ == 0)
        Fail(PdcpSecurityError::NOT_CONFIGURED);

    const size_t minimum = HeaderSize + (integrityActive_ ? MacSize : 0);
    if (pdu.size() < minimum)
        Fail(PdcpSecurityError::PDU_TOO_SHORT);

    const uint16_t header = static_cast<uint16_t>((pdu[0] << 8U) | pdu[1]);
    if ((header & 0x8000U) == 0)
        Fail(PdcpSecurityError::NOT_A_DATA_PDU);

    const uint32_t sn = header & SnMask;
    const uint32_t count = BuildCount(sn);

    std::vector<uint8_t> body(pdu.begin() + HeaderSize, pdu.end() - (integrityActive_ ? MacSize : 0));

    if (cipheringActive_ && !body.empty())
    {
        const int direction = uplink_ ? 0 : 1;
        OctetString data{std::move(body)};
        OctetString key = OctetString::FromArray(kCiphering_.data(), kCiphering_.size());
        switch (cipheringAlgorithm_)
        {
        case 1: crypto::DecryptEea1(count, bearer_, direction, data, key); break;
        case 2: crypto::DecryptEea2(count, bearer_, direction, data, key); break;
        case 3: crypto::DecryptEea3(count, bearer_, direction, data, key); break;
        default: Fail(PdcpSecurityError::ALGORITHM_UNSUPPORTED);
        }
        body.assign(data.data(), data.data() + data.length());
    }

    if (integrityActive_)
    {
        std::vector<uint8_t> macInput;
        macInput.reserve(HeaderSize + body.size());
        macInput.push_back(static_cast<uint8_t>((header >> 8U) & 0xFFU));
        macInput.push_back(static_cast<uint8_t>(header & 0xFFU));
        macInput.insert(macInput.end(), body.begin(), body.end());
        const uint32_t expected = MacFor(count, macInput.data(), macInput.size());
        const uint32_t received = (static_cast<uint32_t>(pdu[pdu.size() - 4]) << 24U) |
                                  (static_cast<uint32_t>(pdu[pdu.size() - 3]) << 16U) |
                                  (static_cast<uint32_t>(pdu[pdu.size() - 2]) << 8U) |
                                  static_cast<uint32_t>(pdu[pdu.size() - 1]);
        if (expected != received)
            Fail(PdcpSecurityError::INTEGRITY_FAILURE);
    }

    if (rxAny_ && count <= rxCount_)
        Fail(PdcpSecurityError::REPLAY_DETECTED);

    rxCount_ = count;
    rxAny_ = true;
    return body;
}

} // namespace lte::security
