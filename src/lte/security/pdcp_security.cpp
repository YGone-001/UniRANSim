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

constexpr size_t MacSize = 4;
constexpr uint8_t MaxRbIdentity = 32;

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

const char *ToString(PdcpProfile profile)
{
    switch (profile)
    {
    case PdcpProfile::SRB: return "SRB";
    case PdcpProfile::DRB12: return "DRB12";
    }
    return "UNKNOWN_PROFILE";
}

uint8_t PdcpSnBits(PdcpProfile profile)
{
    // TS 36.323 6.3.2: SRBs use 5 bits, the DRB profile implemented here 12.
    return profile == PdcpProfile::SRB ? 5 : 12;
}

uint8_t PdcpHeaderLength(PdcpProfile profile)
{
    // TS 36.323 6.2.2: one octet for SRB; 6.2.3: two octets for the 12-bit DRB.
    return profile == PdcpProfile::SRB ? 1 : 2;
}

bool PdcpHasMacI(PdcpProfile profile)
{
    // TS 36.323 6.2.2: the SRB data PDU carries a 32-bit MAC-I. The ordinary UE
    // DRB profile has no integrity protection and no MAC-I field.
    return profile == PdcpProfile::SRB;
}

const char *ToString(PdcpSecurityError error)
{
    switch (error)
    {
    case PdcpSecurityError::NOT_CONFIGURED: return "NOT_CONFIGURED";
    case PdcpSecurityError::ALGORITHM_UNSUPPORTED: return "ALGORITHM_UNSUPPORTED";
    case PdcpSecurityError::KEY_MISSING: return "KEY_MISSING";
    case PdcpSecurityError::UNSUPPORTED_PROFILE: return "UNSUPPORTED_PROFILE";
    case PdcpSecurityError::UNSUPPORTED_BEARER: return "UNSUPPORTED_BEARER";
    case PdcpSecurityError::PDU_TOO_SHORT: return "PDU_TOO_SHORT";
    case PdcpSecurityError::MALFORMED_HEADER: return "MALFORMED_HEADER";
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

bool RadioBearerIdentity::Valid() const
{
    return rbId >= 1 && rbId <= MaxRbIdentity;
}

uint8_t RadioBearerIdentity::BearerField() const
{
    // TS 36.323 6.3.5 / TS 33.401 5.1.3.2: BEARER = RB identity - 1, so SRB1 is 0.
    return static_cast<uint8_t>(rbId - 1);
}

std::vector<uint8_t> ExtractPdcpPayload(const std::vector<uint8_t> &pdu, PdcpProfile profile)
{
    const size_t header = PdcpHeaderLength(profile);
    const size_t trailer = PdcpHasMacI(profile) ? MacSize : 0;
    if (pdu.size() < header + trailer)
        Fail(PdcpSecurityError::PDU_TOO_SHORT);
    return std::vector<uint8_t>(pdu.begin() + header, pdu.end() - trailer);
}

PdcpSecurityEntity::~PdcpSecurityEntity()
{
    SecureZero(kIntegrity_);
    SecureZero(kCiphering_);
}

PdcpSecurityEntity::PdcpSecurityEntity(PdcpSecurityEntity &&other) noexcept
{
    *this = std::move(other);
}

PdcpSecurityEntity &PdcpSecurityEntity::operator=(PdcpSecurityEntity &&other) noexcept
{
    if (this == &other)
        return *this;
    SecureZero(kIntegrity_);
    SecureZero(kCiphering_);

    profile_ = other.profile_;
    bearer_ = other.bearer_;
    uplink_ = other.uplink_;
    integrityAlgorithm_ = other.integrityAlgorithm_;
    cipheringAlgorithm_ = other.cipheringAlgorithm_;
    kIntegrity_ = other.kIntegrity_;
    kCiphering_ = other.kCiphering_;
    integrityActive_ = other.integrityActive_;
    cipheringActive_ = other.cipheringActive_;
    txCount_ = other.txCount_;
    rxCount_ = other.rxCount_;
    rxAny_ = other.rxAny_;

    SecureZero(other.kIntegrity_);
    SecureZero(other.kCiphering_);
    other.integrityActive_ = false;
    other.cipheringActive_ = false;
    return *this;
}

PdcpSecurityEntity PdcpSecurityEntity::Create(PdcpProfile profile, RadioBearerIdentity bearer, bool uplink,
                                              uint8_t integrityAlgorithm, uint8_t cipheringAlgorithm,
                                              const Key128 &kIntegrity, const Key128 &kCiphering)
{
    if (!bearer.Valid())
        Fail(PdcpSecurityError::UNSUPPORTED_BEARER);
    if (profile == PdcpProfile::DRB12 && bearer.rbId < 3)
        Fail(PdcpSecurityError::UNSUPPORTED_BEARER);
    if (profile == PdcpProfile::SRB && bearer.rbId > 2)
        Fail(PdcpSecurityError::UNSUPPORTED_BEARER);
    if (integrityAlgorithm > 3 || cipheringAlgorithm > 3)
        Fail(PdcpSecurityError::ALGORITHM_UNSUPPORTED);
    if (profile == PdcpProfile::DRB12 && integrityAlgorithm != 0)
    {
        // The ordinary UE DRB profile implemented here has no integrity and no
        // MAC-I field; activating one would be a PDU the peer cannot parse.
        Fail(PdcpSecurityError::UNSUPPORTED_PROFILE);
    }
    if (integrityAlgorithm != 0 && AllZero(kIntegrity))
        Fail(PdcpSecurityError::KEY_MISSING);
    if (cipheringAlgorithm != 0 && AllZero(kCiphering))
        Fail(PdcpSecurityError::KEY_MISSING);

    PdcpSecurityEntity entity;
    entity.profile_ = profile;
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
    if (bearer_.rbId == 0)
        Fail(PdcpSecurityError::NOT_CONFIGURED);
    if (integrityAlgorithm_ != 0 && AllZero(kIntegrity_))
        Fail(PdcpSecurityError::KEY_MISSING);
    integrityActive_ = true;
}

void PdcpSecurityEntity::ActivateCiphering()
{
    if (bearer_.rbId == 0)
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

void PdcpSecurityEntity::Cipher(uint32_t count, uint8_t *data, size_t length, bool encipher) const
{
    if (length == 0)
        return;
    const int direction = uplink_ ? 0 : 1;
    const int bearerField = bearer_.BearerField();
    OctetString key = OctetString::FromArray(kCiphering_.data(), kCiphering_.size());
    OctetString body = OctetString::FromArray(data, length);
    switch (cipheringAlgorithm_)
    {
    case 1: encipher ? crypto::EncryptEea1(count, bearerField, direction, body, key)
                     : crypto::DecryptEea1(count, bearerField, direction, body, key); break;
    case 2: encipher ? crypto::EncryptEea2(count, bearerField, direction, body, key)
                     : crypto::DecryptEea2(count, bearerField, direction, body, key); break;
    case 3: encipher ? crypto::EncryptEea3(count, bearerField, direction, body, key)
                     : crypto::DecryptEea3(count, bearerField, direction, body, key); break;
    default: Fail(PdcpSecurityError::ALGORITHM_UNSUPPORTED);
    }
    std::copy(body.data(), body.data() + body.length(), data);
}

uint32_t PdcpSecurityEntity::BuildCount(uint32_t sn) const
{
    const uint8_t bits = PdcpSnBits(profile_);
    const uint32_t snMask = (1U << bits) - 1U;
    uint32_t count = (rxAny_ ? (rxCount_ & ~snMask) : 0U) | (sn & snMask);
    if (rxAny_ && count < rxCount_)
        count += (1U << bits);
    return count;
}

uint32_t PdcpSecurityEntity::MacFor(uint32_t count, const uint8_t *data, size_t length) const
{
    const int direction = uplink_ ? 0 : 1;
    const int bearerField = bearer_.BearerField();
    OctetString message = OctetString::FromArray(data, length);
    OctetString key = OctetString::FromArray(kIntegrity_.data(), kIntegrity_.size());
    switch (integrityAlgorithm_)
    {
    case 1: return crypto::ComputeMacEia1(count, bearerField, direction, message, key);
    case 2: return crypto::ComputeMacEia2(count, bearerField, direction, message, key);
    case 3: return crypto::ComputeMacEia3(count, bearerField, direction, message, key);
    default: Fail(PdcpSecurityError::ALGORITHM_UNSUPPORTED);
    }
}

std::vector<uint8_t> PdcpSecurityEntity::Protect(const std::vector<uint8_t> &plain)
{
    if (bearer_.rbId == 0 || (!integrityActive_ && !cipheringActive_))
        Fail(PdcpSecurityError::NOT_CONFIGURED);
    if (txCount_ > 0xFFFFFFFEU)
        Fail(PdcpSecurityError::COUNT_EXHAUSTED);

    const uint8_t bits = PdcpSnBits(profile_);
    const uint32_t snMask = (1U << bits) - 1U;
    const uint32_t count = txCount_;
    const uint32_t sn = count & snMask;

    std::vector<uint8_t> pdu;
    pdu.reserve(PdcpHeaderLength(profile_) + plain.size() + (PdcpHasMacI(profile_) ? MacSize : 0));

    if (profile_ == PdcpProfile::SRB)
    {
        // One octet: three reserved bits (zero) then the 5-bit SN. No D/C bit.
        pdu.push_back(static_cast<uint8_t>(sn & 0x1FU));
    }
    else
    {
        // Two octets: D/C = 1, three reserved bits, 12-bit SN.
        const uint16_t header = static_cast<uint16_t>(0x8000U | (sn & 0x0FFFU));
        pdu.push_back(static_cast<uint8_t>((header >> 8U) & 0xFFU));
        pdu.push_back(static_cast<uint8_t>(header & 0xFFU));
    }

    const size_t headerLength = pdu.size();
    pdu.insert(pdu.end(), plain.begin(), plain.end());

    if (PdcpHasMacI(profile_))
    {
        uint32_t mac = 0;
        if (integrityActive_)
            mac = MacFor(count, pdu.data(), pdu.size());
        pdu.push_back(static_cast<uint8_t>((mac >> 24U) & 0xFFU));
        pdu.push_back(static_cast<uint8_t>((mac >> 16U) & 0xFFU));
        pdu.push_back(static_cast<uint8_t>((mac >> 8U) & 0xFFU));
        pdu.push_back(static_cast<uint8_t>(mac & 0xFFU));
    }

    if (cipheringActive_ && cipheringAlgorithm_ != 0)
    {
        // TS 36.323 6.2.2: for SRB the MAC-I is ciphered with the data; the
        // header is never ciphered. TS 36.323 6.2.3: the DRB ciphers the data
        // field, and has no MAC-I to consider.
        //
        // EEA0 is a real selection that protects nothing: the header is emitted
        // and the data field is left in the clear, and nothing here describes
        // that as confidentiality.
        Cipher(count, pdu.data() + headerLength, pdu.size() - headerLength, true);
    }

    txCount_++;
    return pdu;
}

std::vector<uint8_t> PdcpSecurityEntity::Unprotect(const std::vector<uint8_t> &pdu)
{
    if (bearer_.rbId == 0)
        Fail(PdcpSecurityError::NOT_CONFIGURED);

    const size_t headerLength = PdcpHeaderLength(profile_);
    const size_t trailer = PdcpHasMacI(profile_) ? MacSize : 0;
    if (pdu.size() < headerLength + trailer)
        Fail(PdcpSecurityError::PDU_TOO_SHORT);

    const uint8_t bits = PdcpSnBits(profile_);
    const uint32_t snMask = (1U << bits) - 1U;
    uint32_t sn = 0;

    if (profile_ == PdcpProfile::SRB)
    {
        if ((pdu[0] & 0xE0U) != 0)
            Fail(PdcpSecurityError::MALFORMED_HEADER);
        sn = pdu[0] & 0x1FU;
    }
    else
    {
        const uint16_t header = static_cast<uint16_t>((pdu[0] << 8U) | pdu[1]);
        if ((header & 0x8000U) == 0)
            Fail(PdcpSecurityError::NOT_A_DATA_PDU);
        if ((header & 0x7000U) != 0)
            Fail(PdcpSecurityError::MALFORMED_HEADER);
        sn = header & snMask;
    }

    const uint32_t count = BuildCount(sn);

    std::vector<uint8_t> field(pdu.begin() + headerLength, pdu.end());
    if (cipheringActive_ && cipheringAlgorithm_ != 0)
        Cipher(count, field.data(), field.size(), false);

    const size_t dataLength = field.size() - trailer;
    std::vector<uint8_t> data(field.begin(), field.begin() + dataLength);

    if (PdcpHasMacI(profile_) && integrityActive_)
    {
        std::vector<uint8_t> macInput;
        macInput.reserve(headerLength + dataLength);
        macInput.insert(macInput.end(), pdu.begin(), pdu.begin() + headerLength);
        macInput.insert(macInput.end(), data.begin(), data.end());
        const uint32_t expected = MacFor(count, macInput.data(), macInput.size());
        const uint32_t received = (static_cast<uint32_t>(field[dataLength]) << 24U) |
                                  (static_cast<uint32_t>(field[dataLength + 1]) << 16U) |
                                  (static_cast<uint32_t>(field[dataLength + 2]) << 8U) |
                                  static_cast<uint32_t>(field[dataLength + 3]);
        if (expected != received)
            Fail(PdcpSecurityError::INTEGRITY_FAILURE);
    }

    if (rxAny_ && count <= rxCount_)
        Fail(PdcpSecurityError::REPLAY_DETECTED);

    rxCount_ = count;
    rxAny_ = true;
    return data;
}

} // namespace lte::security
