//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#include "security.hpp"

#include <algorithm>
#include <cstring>

#include <lib/crypt/crypt.hpp>
#include <utils/octet_string.hpp>

namespace lte::ue::nas
{
namespace
{

// TS 33.401 Annex A.2: FC = 0x15 for EPS NAS key derivation.
constexpr int KdfFcNas = 0x15;
// Open5GS/UERANSIM KDF parameter distinguishers (TS 33.220 B.2.0 style).
constexpr int KdfDistinguisherInt = 0x02;
constexpr int KdfDistinguisherEnc = 0x01;
// EPS NAS uses bearer identity 0 (TS 33.401 5.1.4.1).
constexpr int NasBearer = 0;
constexpr size_t NasMacSize = 4;

OctetString ToOctets(const uint8_t *data, size_t length)
{
    return OctetString::FromArray(data, length);
}

template <size_t N> OctetString ToOctets(const std::array<uint8_t, N> &value)
{
    return ToOctets(value.data(), value.size());
}

template <size_t N> std::array<uint8_t, N> ToArray(const OctetString &value)
{
    if (value.length() != static_cast<int>(N))
        throw SecurityError("Unexpected NAS key derivation length");
    std::array<uint8_t, N> result{};
    std::copy(value.data(), value.data() + N, result.begin());
    return result;
}

// TS 33.401 A.2 / TS 33.220 B.2.0: the 128-bit NAS key is the rightmost half of
// the HMAC-SHA-256 output.
std::array<uint8_t, 16> DeriveNasKey(const std::array<uint8_t, 32> &kasme, int distinguisher, uint8_t algorithmId)
{
    OctetString parameters[2] = {OctetString::FromOctet(distinguisher), OctetString::FromOctet(algorithmId)};
    auto full = crypto::CalculateKdfKey(ToOctets(kasme), KdfFcNas, parameters, 2);
    return ToArray<16>(full.subCopy(16, 16));
}

bool IsCipheredHeader(SecurityHeaderType headerType)
{
    return headerType == SecurityHeaderType::INTEGRITY_PROTECTED_AND_CIPHERED ||
           headerType == SecurityHeaderType::INTEGRITY_PROTECTED_AND_CIPHERED_WITH_NEW_CONTEXT;
}

bool IsNewContextHeader(SecurityHeaderType headerType)
{
    return headerType == SecurityHeaderType::INTEGRITY_PROTECTED_WITH_NEW_CONTEXT ||
           headerType == SecurityHeaderType::INTEGRITY_PROTECTED_AND_CIPHERED_WITH_NEW_CONTEXT;
}

void Cipher(const SecurityContext &context, bool uplink, uint32_t count, OctetString &body)
{
    switch (context.ciphering)
    {
    case CipheringAlgorithm::EEA0:
        break;
    case CipheringAlgorithm::EEA1:
        crypto::EncryptEea1(count, NasBearer, uplink ? 0 : 1, body, ToOctets(context.kNasEnc));
        break;
    case CipheringAlgorithm::EEA2:
        crypto::EncryptEea2(count, NasBearer, uplink ? 0 : 1, body, ToOctets(context.kNasEnc));
        break;
    case CipheringAlgorithm::EEA3:
        crypto::EncryptEea3(count, NasBearer, uplink ? 0 : 1, body, ToOctets(context.kNasEnc));
        break;
    }
}

void Decipher(const SecurityContext &context, bool uplink, uint32_t count, OctetString &body)
{
    switch (context.ciphering)
    {
    case CipheringAlgorithm::EEA0:
        break;
    case CipheringAlgorithm::EEA1:
        crypto::DecryptEea1(count, NasBearer, uplink ? 0 : 1, body, ToOctets(context.kNasEnc));
        break;
    case CipheringAlgorithm::EEA2:
        crypto::DecryptEea2(count, NasBearer, uplink ? 0 : 1, body, ToOctets(context.kNasEnc));
        break;
    case CipheringAlgorithm::EEA3:
        crypto::DecryptEea3(count, NasBearer, uplink ? 0 : 1, body, ToOctets(context.kNasEnc));
        break;
    }
}

uint32_t ComputeMac(const SecurityContext &context, bool uplink, uint32_t count, const OctetString &message)
{
    const int direction = uplink ? 0 : 1;
    switch (context.integrity)
    {
    case IntegrityAlgorithm::EIA0:
        return 0;
    case IntegrityAlgorithm::EIA1:
        return crypto::ComputeMacEia1(count, NasBearer, direction, message, ToOctets(context.kNasInt));
    case IntegrityAlgorithm::EIA2:
        return crypto::ComputeMacEia2(count, NasBearer, direction, message, ToOctets(context.kNasInt));
    case IntegrityAlgorithm::EIA3:
        return crypto::ComputeMacEia3(count, NasBearer, direction, message, ToOctets(context.kNasInt));
    }
    throw SecurityError("Unsupported NAS integrity algorithm");
}

} // namespace

bool IsSupported(IntegrityAlgorithm algorithm)
{
    // EIA0 is null integrity and is not permitted for an ordinary authenticated
    // EPS Attach (TS 33.401 5.1.3.1). The stack implements EIA2.
    return algorithm == IntegrityAlgorithm::EIA2;
}

bool IsSupported(CipheringAlgorithm algorithm)
{
    return algorithm == CipheringAlgorithm::EEA0 || algorithm == CipheringAlgorithm::EEA2;
}

const char *ToString(IntegrityAlgorithm algorithm)
{
    switch (algorithm)
    {
    case IntegrityAlgorithm::EIA0: return "EIA0";
    case IntegrityAlgorithm::EIA1: return "EIA1";
    case IntegrityAlgorithm::EIA2: return "EIA2";
    case IntegrityAlgorithm::EIA3: return "EIA3";
    }
    return "EIA-unknown";
}

const char *ToString(CipheringAlgorithm algorithm)
{
    switch (algorithm)
    {
    case CipheringAlgorithm::EEA0: return "EEA0";
    case CipheringAlgorithm::EEA1: return "EEA1";
    case CipheringAlgorithm::EEA2: return "EEA2";
    case CipheringAlgorithm::EEA3: return "EEA3";
    }
    return "EEA-unknown";
}

const char *ToString(SecurityHeaderType headerType)
{
    switch (headerType)
    {
    case SecurityHeaderType::PLAIN: return "PLAIN";
    case SecurityHeaderType::INTEGRITY_PROTECTED: return "INTEGRITY_PROTECTED";
    case SecurityHeaderType::INTEGRITY_PROTECTED_AND_CIPHERED: return "INTEGRITY_PROTECTED_AND_CIPHERED";
    case SecurityHeaderType::INTEGRITY_PROTECTED_WITH_NEW_CONTEXT: return "INTEGRITY_PROTECTED_WITH_NEW_CONTEXT";
    case SecurityHeaderType::INTEGRITY_PROTECTED_AND_CIPHERED_WITH_NEW_CONTEXT:
        return "INTEGRITY_PROTECTED_AND_CIPHERED_WITH_NEW_CONTEXT";
    }
    return "UNKNOWN";
}

std::array<uint8_t, 16> DeriveKnasInt(const std::array<uint8_t, 32> &kasme, IntegrityAlgorithm algorithm)
{
    return DeriveNasKey(kasme, KdfDistinguisherInt, static_cast<uint8_t>(algorithm));
}

std::array<uint8_t, 16> DeriveKnasEnc(const std::array<uint8_t, 32> &kasme, CipheringAlgorithm algorithm)
{
    return DeriveNasKey(kasme, KdfDistinguisherEnc, static_cast<uint8_t>(algorithm));
}

bool StartsNewContext(SecurityHeaderType headerType)
{
    return IsNewContextHeader(headerType);
}

bool IsCiphered(SecurityHeaderType headerType)
{
    return IsCipheredHeader(headerType);
}

std::vector<uint8_t> Protect(const SecurityContext &context, bool uplink, bool newContext,
                             const std::vector<uint8_t> &plain)
{
    if (!context.valid || !context.keysDerived)
        throw SecurityError("Attempted to protect NAS without a derived security context");
    if (!IsSupported(context.integrity))
        throw SecurityError("Attempted to protect NAS with an unsupported integrity algorithm");
    if (!IsSupported(context.ciphering))
        throw SecurityError("Attempted to protect NAS with an unsupported ciphering algorithm");
    if (plain.empty())
        throw SecurityError("Refusing to protect an empty NAS message");

    SecurityHeaderType headerType;
    if (newContext)
        headerType = SecurityHeaderType::INTEGRITY_PROTECTED_AND_CIPHERED_WITH_NEW_CONTEXT;
    else
        headerType = SecurityHeaderType::INTEGRITY_PROTECTED_AND_CIPHERED;

    // A fresh context starts both COUNTs at zero; otherwise the caller has
    // already advanced the COUNT for this message.
    uint32_t count = newContext ? 0U : (uplink ? context.ulNasCount : context.dlNasCount);
    count &= 0xFFFFFFU;

    OctetString body = ToOctets(plain.data(), plain.size());
    if (IsCipheredHeader(headerType))
        Cipher(context, uplink, count, body);

    uint8_t sequenceNumber = static_cast<uint8_t>(count & 0xFFU);

    // MAC covers sequenceNumber || (ciphered) plain NAS message.
    OctetString macInput;
    macInput.appendOctet(sequenceNumber);
    macInput.append(body);
    uint32_t mac = ComputeMac(context, uplink, count, macInput);

    std::vector<uint8_t> out;
    out.reserve(6U + static_cast<size_t>(body.length()));
    out.push_back(static_cast<uint8_t>((static_cast<uint8_t>(headerType) << 4U) | 0x07U));
    out.push_back(static_cast<uint8_t>((mac >> 24U) & 0xFFU));
    out.push_back(static_cast<uint8_t>((mac >> 16U) & 0xFFU));
    out.push_back(static_cast<uint8_t>((mac >> 8U) & 0xFFU));
    out.push_back(static_cast<uint8_t>(mac & 0xFFU));
    out.push_back(sequenceNumber);
    out.insert(out.end(), body.data(), body.data() + body.length());
    return out;
}

ProtectedNas ParseProtectedHeader(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < 6)
        throw SecurityError("NAS message is shorter than the security header");
    uint8_t first = data[0];
    if ((first & 0x0FU) != 0x07U)
        throw SecurityError("NAS protocol discriminator is not EPS mobility management");
    uint8_t rawType = static_cast<uint8_t>(first >> 4U);
    if (rawType > static_cast<uint8_t>(SecurityHeaderType::INTEGRITY_PROTECTED_AND_CIPHERED_WITH_NEW_CONTEXT))
        throw SecurityError("Unknown EPS NAS security header type");

    ProtectedNas result{};
    result.headerType = static_cast<SecurityHeaderType>(rawType);
    std::copy(data + 1, data + 5, result.mac.begin());
    result.sequenceNumber = data[5];
    result.plain.assign(data + 6, data + size);
    return result;
}

std::vector<uint8_t> UnprotectBody(const SecurityContext &context, bool uplink, SecurityHeaderType headerType,
                                   uint8_t sequenceNumber, const std::array<uint8_t, 4> &mac, std::vector<uint8_t> body)
{
    if (!context.valid || !context.keysDerived)
        throw SecurityError("Attempted to unprotect NAS without a derived security context");
    if (headerType == SecurityHeaderType::PLAIN)
        throw SecurityError("UnprotectBody requires a security-protected header");
    if (!IsSupported(context.integrity))
        throw SecurityError("Attempted to unprotect NAS with an unsupported integrity algorithm");
    if (!IsSupported(context.ciphering))
        throw SecurityError("Attempted to unprotect NAS with an unsupported ciphering algorithm");

    // A new-context header restarts this direction's COUNT at zero; otherwise
    // the 24-bit COUNT is rebuilt from the running overflow and the received
    // 8-bit sequence number (TS 24.301 4.4.3.1).
    uint32_t count;
    if (IsNewContextHeader(headerType))
        count = sequenceNumber;
    else
        count = EstimateNasCount(uplink ? context.ulNasCount : context.dlNasCount, sequenceNumber);

    OctetString bodyOctets = ToOctets(body.data(), body.size());
    OctetString macInput;
    macInput.appendOctet(sequenceNumber);
    macInput.append(bodyOctets);
    uint32_t computed = ComputeMac(context, uplink, count, macInput);
    uint32_t received = (static_cast<uint32_t>(mac[0]) << 24U) | (static_cast<uint32_t>(mac[1]) << 16U) |
                        (static_cast<uint32_t>(mac[2]) << 8U) | static_cast<uint32_t>(mac[3]);
    if (computed != received)
        throw SecurityError("EPS NAS integrity verification failed");

    if (IsCipheredHeader(headerType))
        Decipher(context, uplink, count, bodyOctets);

    return std::vector<uint8_t>(bodyOctets.data(), bodyOctets.data() + bodyOctets.length());
}

uint32_t EstimateNasCount(uint32_t lastCount, uint8_t sequenceNumber)
{
    lastCount &= 0xFFFFFFU;
    uint8_t lastSequence = static_cast<uint8_t>(lastCount & 0xFFU);
    uint32_t overflow = lastCount >> 8U;
    if (sequenceNumber < lastSequence)
        overflow = (overflow + 1U) & 0xFFFFU;
    return ((overflow << 8U) | sequenceNumber) & 0xFFFFFFU;
}

} // namespace lte::ue::nas
