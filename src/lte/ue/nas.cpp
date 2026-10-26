//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#include "nas.hpp"
#include "security.hpp"

#include <algorithm>
#include <cstring>

#include <lib/crypt/crypt.hpp>
#include <lib/crypt/milenage.hpp>
#include <lte/enb/codec.hpp>
#include <utils/octet_string.hpp>

namespace lte::ue::nas
{
namespace
{
constexpr uint8_t EpsEmm = 0x07;
constexpr uint8_t Esm = 0x02;
constexpr uint8_t AttachRequest = 0x41;
constexpr uint8_t AttachAcceptType = 0x42;
constexpr uint8_t AttachCompleteType = 0x43;
constexpr uint8_t AttachRejectType = 0x44;
constexpr uint8_t DetachRequestType = 0x45;
constexpr uint8_t DetachAcceptType = 0x46;
constexpr uint8_t TauRequestType = 0x48;
constexpr uint8_t TauAcceptType = 0x49;
constexpr uint8_t TauCompleteType = 0x4A;
constexpr uint8_t TauRejectType = 0x4B;
constexpr uint8_t ServiceRejectType = 0x4E;
constexpr uint8_t AuthenticationRequestType = 0x52;
constexpr uint8_t AuthenticationResponseType = 0x53;
constexpr uint8_t AuthenticationFailureType = 0x5C;
constexpr uint8_t SecurityModeCommandType = 0x5D;
constexpr uint8_t SecurityModeCompleteType = 0x5E;
constexpr uint8_t PdnConnectivityRequestType = 0xD0;
constexpr uint8_t EsmInformationRequestType = 0xD9;
constexpr uint8_t EsmInformationResponseType = 0xDA;
constexpr uint8_t ActivateDefaultEpsBearerRequestType = 0xC1;
constexpr uint8_t ActivateDefaultEpsBearerAcceptType = 0xC2;

constexpr uint8_t IeiImeisvRequest = 0xC0;
constexpr uint8_t IeiHashMme = 0x4F;
constexpr uint8_t IeiReplayedNonceUe = 0x55;
constexpr uint8_t IeiNonceMme = 0x56;
constexpr uint8_t IeiReplayedUeAdditionalSecurityCapability = 0x6F;
constexpr uint8_t IeiImeisv = 0x23;
constexpr uint8_t IeiGuti = 0x50;
constexpr uint8_t IeiTaiList = 0x54;
constexpr uint8_t IeiBearerContextStatus = 0x57;
constexpr uint8_t IeiT3412 = 0x5A;
constexpr uint8_t IeiApn = 0x28;
constexpr uint8_t IeiPco = 0x27;

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
        throw std::runtime_error("Unexpected cryptographic output length");
    std::array<uint8_t, N> result{};
    std::copy(value.data(), value.data() + N, result.begin());
    return result;
}

uint8_t PdnType(const std::string &type)
{
    if (type == "IPv4") return 1;
    if (type == "IPv6") return 2;
    if (type == "IPv4v6") return 3;
    throw std::runtime_error("Unsupported LTE PDN type");
}

uint64_t ToInteger(const std::array<uint8_t, 6> &sqn)
{
    uint64_t result{};
    for (uint8_t octet : sqn)
        result = (result << 8U) | octet;
    return result;
}

std::vector<uint8_t> EncodeApn(const std::string &apn)
{
    if (apn.empty() || apn.size() > 100)
        throw std::runtime_error("Invalid APN");
    std::vector<uint8_t> out;
    size_t start{};
    while (start < apn.size())
    {
        size_t end = apn.find('.', start);
        if (end == std::string::npos) end = apn.size();
        size_t length = end - start;
        if (length == 0 || length > 63)
            throw std::runtime_error("Invalid APN label");
        out.push_back(static_cast<uint8_t>(length));
        out.insert(out.end(), apn.begin() + static_cast<std::ptrdiff_t>(start), apn.begin() + static_cast<std::ptrdiff_t>(end));
        start = end + 1;
    }
    return out;
}

std::string DecodeApn(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0)
        throw DecodeError("Empty APN");
    std::string apn;
    size_t offset{};
    while (offset < size)
    {
        size_t label = data[offset++];
        if (label == 0 || label > 63 || offset + label > size)
            throw DecodeError("Malformed APN label");
        if (!apn.empty())
            apn.push_back('.');
        apn.append(reinterpret_cast<const char *>(data + offset), label);
        offset += label;
    }
    return apn;
}

// TS 24.008 10.5.1.4 mobile identity, used for the synthetic IMEISV.
// `digits` holds 16 packed BCD digits (two per octet, high nibble first).
std::vector<uint8_t> EncodeImeisv(const std::array<uint8_t, 8> &digits)
{
    auto digitAt = [&](size_t index) -> uint8_t {
        // Digits are 1-based on the wire; index 0 is digit 1.
        const uint8_t octet = digits[index / 2U];
        return ((index % 2U) == 0) ? static_cast<uint8_t>(octet >> 4U) : static_cast<uint8_t>(octet & 0x0FU);
    };
    std::vector<uint8_t> out;
    // Octet 1: digit 1 in bits 8-5, even (0) in bit 4, type 011 (IMEISV) in bits 3-1.
    out.push_back(static_cast<uint8_t>((digitAt(0) << 4U) | 0x03U));
    // Octets 2..8: digit pairs (odd digit high, even digit low).
    for (size_t i = 1; i < 15; i += 2)
        out.push_back(static_cast<uint8_t>((digitAt(i + 1) << 4U) | digitAt(i)));
    // Final octet: end mark 1111 in bits 8-5, last digit in bits 4-1.
    out.push_back(static_cast<uint8_t>(0xF0U | digitAt(15)));
    return out;
}

bool IsOptionalIei(const uint8_t *data, size_t size, size_t offset, uint8_t iei)
{
    return offset < size && data[offset] == iei;
}

// Parses the ESM container carried inside Attach Accept. Only the default
// bearer activation is handled; anything else is reported as OTHER.
void DecodeEsmContainer(const std::vector<uint8_t> &esm, DownlinkMessage &result)
{
    // An ESM message is at least EPS bearer identity / PD, PTI and message type.
    if (esm.size() < 3)
        throw DecodeError("Truncated ESM message container");
    const uint8_t ebi = static_cast<uint8_t>(esm[0] >> 4U);
    const uint8_t pti = esm[1];
    const uint8_t messageType = esm[2];
    if (messageType != ActivateDefaultEpsBearerRequestType)
        return;

    result.type = DownlinkEmm::OTHER;
    ActivateDefaultEpsBearerContextRequest bearer{};
    bearer.epsBearerIdentity = ebi;
    bearer.procedureTransactionId = pti;
    bearer.raw = esm;

    size_t offset = 3;
    // Mandatory: EPS quality of service (LV).
    if (offset >= esm.size())
        throw DecodeError("Activate Default EPS Bearer Context Request is missing EPS QoS");
    const size_t qosLength = esm[offset];
    if (qosLength < 1 || offset + 1 + qosLength > esm.size())
        throw DecodeError("Malformed EPS QoS in Activate Default EPS Bearer Context Request");
    if (qosLength >= 1)
        bearer.qci = esm[offset + 1];
    offset += 1 + qosLength;

    // Mandatory: access point name (LV).
    if (offset >= esm.size())
        throw DecodeError("Activate Default EPS Bearer Context Request is missing the APN");
    const size_t apnLength = esm[offset];
    if (apnLength == 0 || offset + 1 + apnLength > esm.size())
        throw DecodeError("Malformed APN in Activate Default EPS Bearer Context Request");
    bearer.apn = DecodeApn(esm.data() + offset + 1, apnLength);
    offset += 1 + apnLength;

    // Mandatory: PDN address (LV).
    if (offset >= esm.size())
        throw DecodeError("Activate Default EPS Bearer Context Request is missing the PDN address");
    const size_t pdnLength = esm[offset];
    if (pdnLength < 2 || offset + 1 + pdnLength > esm.size())
        throw DecodeError("Malformed PDN address in Activate Default EPS Bearer Context Request");
    if (esm[offset + 1] == 1 && pdnLength >= 5)
        std::copy(esm.begin() + static_cast<std::ptrdiff_t>(offset + 2),
                  esm.begin() + static_cast<std::ptrdiff_t>(offset + 6), bearer.pdnAddress.begin());
    offset += 1 + pdnLength;

    result.attachAccept.bearer = bearer;
    result.type = DownlinkEmm::ATTACH_ACCEPT;
}

} // namespace

std::vector<uint8_t> EncodeImsi(const std::string &imsi)
{
    if (imsi.size() < 5 || imsi.size() > 15 || !std::all_of(imsi.begin(), imsi.end(), [](unsigned char c) { return c >= '0' && c <= '9'; }))
        throw std::runtime_error("IMSI must contain 5..15 decimal digits");
    std::vector<uint8_t> identity;
    const bool odd = (imsi.size() % 2U) != 0;
    // TS 24.008 10.5.1.4: the first IMSI digit occupies bits 8..5;
    // bits 4..1 are odd/even, type of identity (IMSI = 001).
    identity.push_back(static_cast<uint8_t>(((imsi[0] - '0') << 4U) | (odd ? 0x08U : 0x00U) | 0x01U));
    for (size_t i = 1; i < imsi.size(); i += 2)
    {
        uint8_t low = static_cast<uint8_t>(imsi[i] - '0');
        uint8_t high = (i + 1U < imsi.size()) ? static_cast<uint8_t>(imsi[i + 1U] - '0') : 0x0FU;
        identity.push_back(static_cast<uint8_t>(low | (high << 4U)));
    }
    return identity;
}

std::vector<uint8_t> EncodeAttachRequest(const Config &config)
{
    auto imsi = EncodeImsi(config.imsi);
    if (imsi.size() > 255)
        throw std::runtime_error("IMSI mobile identity is too long");

    std::vector<uint8_t> esm{Esm, 0x01, PdnConnectivityRequestType,
                             static_cast<uint8_t>(0x10U | PdnType(config.pdnType))};
    if (config.apn.has_value())
    {
        auto apn = EncodeApn(*config.apn);
        esm.push_back(IeiApn); // Access point name
        esm.push_back(static_cast<uint8_t>(apn.size()));
        esm.insert(esm.end(), apn.begin(), apn.end());
    }

    std::vector<uint8_t> out{EpsEmm, AttachRequest, 0x71}; // EPS attach, no native security context
    out.push_back(static_cast<uint8_t>(imsi.size()));
    out.insert(out.end(), imsi.begin(), imsi.end());
    out.push_back(static_cast<uint8_t>(config.networkCapability.size()));
    out.insert(out.end(), config.networkCapability.begin(), config.networkCapability.end());
    if (esm.size() > 0xFFFFU)
        throw std::runtime_error("ESM message container is too large");
    out.push_back(static_cast<uint8_t>(esm.size() >> 8U));
    out.push_back(static_cast<uint8_t>(esm.size()));
    out.insert(out.end(), esm.begin(), esm.end());
    return out;
}

AuthenticationRequest DecodeAuthenticationRequest(const uint8_t *data, size_t size)
{
    // Initial EPS AKA authentication messages are plain EMM NAS. Protected messages are intentionally not accepted
    // until the Phase 2 NAS security procedure exists.
    if (data == nullptr || size != 36 || data[0] != EpsEmm || data[1] != AuthenticationRequestType || data[19] != 16)
        throw DecodeError("Malformed EPS Authentication Request");
    AuthenticationRequest result{};
    result.ksi = static_cast<uint8_t>(data[2] & 0x07U);
    std::copy(data + 3, data + 19, result.rand.begin());
    std::copy(data + 20, data + 36, result.autn.begin());
    return result;
}

std::vector<uint8_t> EncodeAuthenticationResponse(const std::array<uint8_t, 8> &res)
{
    std::vector<uint8_t> out{EpsEmm, AuthenticationResponseType, static_cast<uint8_t>(res.size())};
    out.insert(out.end(), res.begin(), res.end());
    return out;
}

std::vector<uint8_t> EncodeAuthenticationFailureMac()
{
    return {EpsEmm, AuthenticationFailureType, 0x14}; // MAC failure; no fabricated AUTS is ever emitted.
}

bool IsSecurityModeCommand(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < 2 || (data[0] & 0x0FU) != EpsEmm)
        return false;

    const uint8_t securityHeaderType = static_cast<uint8_t>(data[0] >> 4U);
    if (securityHeaderType == 0)
        return data[1] == SecurityModeCommandType;

    // TS 24.301 security-protected EMM NAS: outer header, 4-byte MAC,
    // sequence number, then the plain EMM message.
    if (securityHeaderType > 4 || size < 8)
        return false;
    return data[6] == EpsEmm && data[7] == SecurityModeCommandType;
}

bool IsEsmInformationRequest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < 3)
        return false;
    if ((data[0] & 0x0FU) != Esm)
        return false;
    return data[2] == EsmInformationRequestType;
}

AkaResult Authenticate(const Config &config, const AuthenticationRequest &request)
{
    AkaResult result{};
    try
    {
        const auto opc = config.opc.has_value() ? ToOctets(*config.opc)
                                                : crypto::milenage::CalculateOpC(ToOctets(*config.op), ToOctets(config.key));
        // f5 derives AK from RAND. AUTN contains SQN xor AK || AMF || MAC-A.
        auto preliminary = crypto::milenage::Calculate(opc, ToOctets(config.key), ToOctets(request.rand),
                                                        ToOctets(config.initialSqn), ToOctets(config.amf));
        std::array<uint8_t, 6> receivedSqn{};
        for (size_t i = 0; i < receivedSqn.size(); ++i)
            receivedSqn[i] = static_cast<uint8_t>(request.autn[i] ^ preliminary.ak.get(static_cast<int>(i)));
        std::array<uint8_t, 2> receivedAmf{{request.autn[6], request.autn[7]}};
        auto milenage = crypto::milenage::Calculate(opc, ToOctets(config.key), ToOctets(request.rand), ToOctets(receivedSqn),
                                                    ToOctets(receivedAmf));
        if (!std::equal(milenage.mac_a.data(), milenage.mac_a.data() + 8, request.autn.begin() + 8))
        {
            result.failure = AkaFailure::MAC_FAILURE;
            return result;
        }
        // This phase deliberately fails closed when HSS SQN is behind the configured USIM SQN. A valid AUTS exchange
        // needs persistent USIM state and is explicitly out of scope here.
        if (ToInteger(receivedSqn) < ToInteger(config.initialSqn))
        {
            result.failure = AkaFailure::SYNCHRONIZATION_FAILURE;
            return result;
        }
        auto ck = ToArray<16>(milenage.ck);
        auto ik = ToArray<16>(milenage.ik);
        OctetString ckIk = OctetString::Concat(milenage.ck, milenage.ik);
        auto sn = enb::s1ap::EncodePlmn(config.plmn);
        OctetString parameters[2] = {ToOctets(sn.data(), sn.size()), ToOctets(request.autn.data(), 6)};
        auto kasme = crypto::CalculateKdfKey(ckIk, 0x10, parameters, 2);
        result.failure = AkaFailure::NONE;
        result.res = ToArray<8>(milenage.res);
        result.context.ck = ck;
        result.context.ik = ik;
        result.context.sqn = receivedSqn;
        result.context.kasme = ToArray<32>(kasme);
        result.context.valid = true;
    }
    catch (const std::exception &)
    {
        result.failure = AkaFailure::MALFORMED;
    }
    return result;
}

SecurityModeCommand DecodeSecurityModeCommand(const uint8_t *data, size_t size)
{
    // Plain body: EMM PD, message type, selected algorithms, KSI, replayed caps (LV),
    // then optional IEs.
    if (data == nullptr || size < 6 || data[0] != EpsEmm || data[1] != SecurityModeCommandType)
        throw DecodeError("Malformed EPS Security Mode Command");

    SecurityModeCommand result{};
    // TS 24.301 9.9.3.23: bits 8-5 type of ciphering algorithm,
    // bits 4-1 type of integrity protection algorithm.
    const uint8_t algorithms = data[2];
    result.integrity = static_cast<IntegrityAlgorithm>(algorithms & 0x0FU);
    result.ciphering = static_cast<CipheringAlgorithm>((algorithms >> 4U) & 0x0FU);

    // TS 24.301 9.9.3.2a: KSI is the low three bits, TSC is bit 4.
    const uint8_t ksiOctet = data[3];
    result.ksi = static_cast<uint8_t>(ksiOctet & 0x07U);
    result.nativeContext = (ksiOctet & 0x08U) == 0;

    const size_t capsLength = data[4];
    if (capsLength < 2 || size < 5U + capsLength)
        throw DecodeError("Security Mode Command has a malformed replayed UE security capability");
    result.replayedCapabilities.assign(data + 5, data + 5 + capsLength);

    size_t offset = 5U + capsLength;
    while (offset < size)
    {
        const uint8_t iei = data[offset];
        // IMEISV request is a TV IE: the high nibble is the IEI 0xC and the low
        // nibble carries the requested flag (TS 24.301 9.9.3.25).
        if ((iei & 0xF0U) == IeiImeisvRequest)
        {
            result.imeisvRequested = (iei & 0x0FU) == 0x1U;
            ++offset;
        }
        else if (iei == IeiHashMme)
        {
            // TS 24.301 9.9.3.50: HashMME is O TLV 10, i.e. 8 value octets.
            constexpr size_t HashMmeLength = 8;
            if (offset + 2 > size || data[offset + 1] != HashMmeLength)
                throw DecodeError("Malformed HASHMME in Security Mode Command");
            if (offset + 2 + HashMmeLength > size)
                throw DecodeError("Truncated HASHMME in Security Mode Command");
            std::copy(data + offset + 2, data + offset + 2 + HashMmeLength, result.hashMme.begin());
            result.hashMmePresent = true;
            offset += 2 + HashMmeLength;
        }
        else if (iei == IeiReplayedNonceUe || iei == IeiNonceMme)
        {
            if (offset + 5 > size)
                throw DecodeError("Truncated nonce in Security Mode Command");
            offset += 5;
        }
        else if (iei == IeiReplayedUeAdditionalSecurityCapability)
        {
            if (offset + 1 > size)
                throw DecodeError("Truncated additional security capability");
            const size_t length = data[offset + 1];
            if (offset + 2 + length > size)
                throw DecodeError("Truncated additional security capability");
            offset += 2 + length;
        }
        else
        {
            // Unknown optional IE: TS 24.301 6.1.1 says IEs the UE does not
            // understand must be ignored where the criticality is not reject.
            break;
        }
    }
    return result;
}

void ValidateSecurityModeCommand(const Config &config, const SecurityModeCommand &command, SecurityContext &context)
{
    if (!context.valid)
        throw DecodeError("Security Mode Command arrived before a valid EPS AKA context");

    // EIA0 is never accepted for an ordinary authenticated EPS Attach.
    if (command.integrity == IntegrityAlgorithm::EIA0)
        throw DecodeError("Security Mode Command selected EIA0, which is not permitted for an authenticated EPS Attach");
    if (!IsSupported(command.integrity))
        throw DecodeError("Security Mode Command selected an unsupported integrity algorithm");
    if (!IsSupported(command.ciphering))
        throw DecodeError("Security Mode Command selected an unsupported ciphering algorithm");

    // The selected algorithms must be among those the UE actually advertised.
    const uint8_t integrityBit = static_cast<uint8_t>(0x80U >> static_cast<unsigned>(command.integrity));
    const uint8_t cipheringBit = static_cast<uint8_t>(0x80U >> static_cast<unsigned>(command.ciphering));
    if ((config.networkCapability[1] & integrityBit) == 0)
        throw DecodeError("Security Mode Command selected an integrity algorithm the UE did not advertise");
    if ((config.networkCapability[0] & cipheringBit) == 0)
        throw DecodeError("Security Mode Command selected a ciphering algorithm the UE did not advertise");

    // The KSI must identify a usable native EPS security context.
    if (command.ksi == 7 && !command.nativeContext)
        throw DecodeError("Security Mode Command selected an unusable KSI");

    // TS 24.301 5.4.3.3: the replayed UE security capabilities must match the
    // octets the UE sent in the Attach Request, bit for bit.
    const auto &advertised = context.advertisedSecurityCapabilities;
    if (advertised.empty())
        throw DecodeError("No advertised UE security capabilities are available for the replay check");
    if (command.replayedCapabilities.size() < advertised.size())
        throw DecodeError("Security Mode Command replayed a truncated UE security capability");
    if (!std::equal(advertised.begin(), advertised.end(), command.replayedCapabilities.begin()))
        throw DecodeError("Security Mode Command replayed UE security capabilities do not match the UE advertisement");

    context.integrity = command.integrity;
    context.ciphering = command.ciphering;
    context.ksi = command.ksi;
}

std::vector<uint8_t> EncodeSecurityModeComplete(const Config &config, bool includeImeisv)
{
    std::vector<uint8_t> out{EpsEmm, SecurityModeCompleteType};
    if (includeImeisv)
    {
        auto imeisv = EncodeImeisv(config.imeisv);
        out.push_back(IeiImeisv);
        out.push_back(static_cast<uint8_t>(imeisv.size()));
        out.insert(out.end(), imeisv.begin(), imeisv.end());
    }
    return out;
}

DownlinkMessage DecodeDownlink(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < 2)
        throw DecodeError("Empty NAS message");

    DownlinkMessage result{};

    if ((data[0] & 0x0FU) == Esm && size >= 3 && (data[2] == 0xC5 || data[2] == 0xCD))
    {
        result.messageType = data[2];
        const auto bearerIdentity = static_cast<uint8_t>(data[0] >> 4U);
        const uint8_t pti = data[1];

        if (data[2] == 0xC5)
        {
            if (size < 6)
                throw DecodeError("Truncated Activate Dedicated EPS Bearer Context Request");
            ActivateDedicatedEpsBearerContextRequest request;
            request.epsBearerIdentity = bearerIdentity;
            request.procedureTransactionId = pti;
            request.linkedEpsBearerIdentity = static_cast<uint8_t>(data[3] & 0x0FU);
            const size_t qosLength = data[4];
            if (qosLength < 1 || 5U + qosLength > size)
                throw DecodeError("Invalid EPS QoS in Activate Dedicated EPS Bearer Context Request");
            request.qci = data[5];
            size_t offset = 5U + qosLength;
            // The TFT is a type 4 information element: a single length octet
            // followed by the value field, not the two-octet LV-E form.
            if (offset + 1U > size)
                throw DecodeError("Missing TFT in Activate Dedicated EPS Bearer Context Request");
            const size_t tftLength = data[offset];
            offset += 1U;
            if (offset + tftLength > size)
                throw DecodeError("Truncated TFT in Activate Dedicated EPS Bearer Context Request");
            request.tft.assign(data + offset, data + offset + tftLength);
            offset += tftLength;
            request.raw.assign(data, data + offset);
            result.type = DownlinkEmm::ACTIVATE_DEDICATED_EPS_BEARER_CONTEXT;
            result.dedicatedBearer = std::move(request);
            return result;
        }

        if (data[2] == 0xCD)
        {
            if (size < 4)
                throw DecodeError("Truncated Deactivate EPS Bearer Context Request");
            DeactivateEpsBearerContextRequest request;
            request.epsBearerIdentity = bearerIdentity;
            request.procedureTransactionId = pti;
            // The ESM cause is an LV whose length octet precedes the value.
            if (size >= 5 && data[3] >= 1)
                request.esmCause = data[4];
            result.type = DownlinkEmm::DEACTIVATE_EPS_BEARER_CONTEXT;
            result.deactivateBearer = request;
            return result;
        }

    }

    if ((data[0] & 0x0FU) == EpsEmm)
    {
        result.messageType = data[1];
        switch (data[1])
        {
        case SecurityModeCommandType:
            result.type = DownlinkEmm::SECURITY_MODE_COMMAND;
            result.securityModeCommand = DecodeSecurityModeCommand(data, size);
            return result;
        case AttachAcceptType:
        {
            result.type = DownlinkEmm::ATTACH_ACCEPT;
            if (size < 6)
                throw DecodeError("Truncated EPS Attach Accept");
            result.attachAccept.attachResult = static_cast<uint8_t>(data[2] & 0x0FU);
            result.attachAccept.t3412 = data[3];
            const size_t taiLength = data[4];
            if (size < 5U + taiLength + 2)
                throw DecodeError("Truncated EPS Attach Accept TAI list");
            result.attachAccept.taiList.assign(data + 5, data + 5 + taiLength);
            size_t offset = 5U + taiLength;
            const size_t esmLength = (static_cast<size_t>(data[offset]) << 8U) | data[offset + 1];
            offset += 2;
            if (esmLength == 0 || size < offset + esmLength)
                throw DecodeError("Truncated EPS Attach Accept ESM container");
            result.attachAccept.esmContainer.assign(data + offset, data + offset + esmLength);
            offset += esmLength;
            DecodeEsmContainer(result.attachAccept.esmContainer, result);
            while (offset < size)
            {
                const uint8_t iei = data[offset++];
                if (iei == IeiT3412)
                {
                    if (offset >= size) throw DecodeError("Truncated Attach Accept T3412");
                    result.attachAccept.t3412 = data[offset++];
                    continue;
                }
                // Type-1 optional IEs carry their value in the IEI octet.
                if ((iei & 0x80U) != 0) continue;
                // The remaining optional Attach Accept fields are not needed
                // by this lifecycle slice. Stop without rejecting a valid
                // message whose IE representation is outside our parser.
                if (iei != IeiGuti) break;
                if (offset >= size) throw DecodeError("Truncated optional Attach Accept IE");
                const size_t length = data[offset++];
                if (offset + length > size) throw DecodeError("Truncated optional Attach Accept value");
                if (iei == IeiGuti)
                {
                    if (length != 11) throw DecodeError("Invalid GUTI length in Attach Accept");
                    std::array<uint8_t, 11> guti{};
                    std::copy(data + offset, data + offset + length, guti.begin());
                    result.attachAccept.guti = guti;
                }
                offset += length;
            }
            return result;
        }
        case AttachRejectType:
            result.type = DownlinkEmm::ATTACH_REJECT;
            if (size >= 3)
                result.emmCause = data[2];
            return result;
        case DetachAcceptType:
            if (size != 2) throw DecodeError("Malformed EPS Detach Accept");
            result.type = DownlinkEmm::DETACH_ACCEPT;
            return result;
        case ServiceRejectType:
            if (size < 3) throw DecodeError("Truncated EPS Service Reject");
            result.type = DownlinkEmm::SERVICE_REJECT;
            result.emmCause = data[2];
            return result;
        case TauRejectType:
            if (size < 3) throw DecodeError("Truncated Tracking Area Update Reject");
            result.type = DownlinkEmm::TAU_REJECT;
            result.emmCause = data[2];
            return result;
        case TauAcceptType:
        {
            if (size < 3) throw DecodeError("Truncated Tracking Area Update Accept");
            result.type = DownlinkEmm::TAU_ACCEPT;
            result.tauAccept.updateResult = static_cast<uint8_t>(data[2] & 0x07U);
            size_t offset = 3;
            while (offset < size)
            {
                const uint8_t iei = data[offset++];
                if (iei == IeiT3412)
                {
                    if (offset >= size) throw DecodeError("Truncated TAU Accept T3412");
                    result.tauAccept.t3412 = data[offset++];
                    continue;
                }
                // Unknown type-1 optional IEs are comprehension-skippable and
                // carry their value in the IEI octet itself.
                if ((iei & 0x80U) != 0) continue;
                if (offset >= size) throw DecodeError("Truncated optional TAU Accept IE");
                const size_t length = data[offset++];
                if (offset + length > size) throw DecodeError("Truncated optional TAU Accept value");
                if (iei == IeiGuti)
                {
                    if (length != 11) throw DecodeError("Invalid GUTI length in TAU Accept");
                    std::array<uint8_t, 11> guti{};
                    std::copy(data + offset, data + offset + length, guti.begin());
                    result.tauAccept.guti = guti;
                }
                else if (iei == IeiTaiList)
                    result.tauAccept.taiList = std::vector<uint8_t>(data + offset, data + offset + length);
                else if (iei == IeiBearerContextStatus)
                {
                    if (length != 2) throw DecodeError("Invalid EPS bearer context status length");
                    result.tauAccept.bearerContextStatus =
                        static_cast<uint16_t>(data[offset]) |
                        static_cast<uint16_t>(static_cast<uint16_t>(data[offset + 1]) << 8U);
                }
                offset += length;
            }
            return result;
        }
        default:
            result.type = DownlinkEmm::OTHER;
            return result;
        }
    }

    if ((data[0] & 0x0FU) == Esm)
    {
        if (size < 3)
            throw DecodeError("Truncated ESM message");
        result.messageType = data[2];
        if (data[2] == EsmInformationRequestType)
        {
            result.type = DownlinkEmm::ESM_INFORMATION_REQUEST;
            result.esmInformationRequest.procedureTransactionId = data[1];
            if (IsOptionalIei(data, size, 3, IeiApn) && size > 5)
            {
                const size_t apnLength = data[4];
                if (5 + apnLength <= size)
                    result.esmInformationRequest.apn = DecodeApn(data + 5, apnLength);
            }
            return result;
        }
        result.type = DownlinkEmm::OTHER;
        return result;
    }

    throw DecodeError("NAS message is neither EPS mobility management nor EPS session management");
}

std::vector<uint8_t> EncodeActivateDefaultEpsBearerContextAccept(uint8_t epsBearerIdentity, uint8_t procedureTransactionId)
{
    return {static_cast<uint8_t>((epsBearerIdentity << 4U) | Esm), procedureTransactionId,
            ActivateDefaultEpsBearerAcceptType};
}

std::vector<uint8_t> EncodeAttachComplete(const std::vector<uint8_t> &esmAccept)
{
    if (esmAccept.empty() || esmAccept.size() > 0xFFFFU)
        throw DecodeError("Invalid ESM container for Attach Complete");
    std::vector<uint8_t> out{EpsEmm, AttachCompleteType};
    out.push_back(static_cast<uint8_t>(esmAccept.size() >> 8U));
    out.push_back(static_cast<uint8_t>(esmAccept.size()));
    out.insert(out.end(), esmAccept.begin(), esmAccept.end());
    return out;
}

std::vector<uint8_t> EncodeEsmInformationResponse(uint8_t procedureTransactionId, const std::optional<std::string> &apn)
{
    std::vector<uint8_t> out{Esm, procedureTransactionId, EsmInformationResponseType};
    if (apn.has_value())
    {
        auto encoded = EncodeApn(*apn);
        out.push_back(IeiApn);
        out.push_back(static_cast<uint8_t>(encoded.size()));
        out.insert(out.end(), encoded.begin(), encoded.end());
    }
    return out;
}

std::vector<uint8_t> EncodeActivateDedicatedEpsBearerContextAccept(uint8_t epsBearerIdentity,
                                                                   uint8_t procedureTransactionId)
{
    if (epsBearerIdentity < 5 || epsBearerIdentity > 15)
        throw DecodeError("Invalid EPS bearer identity for dedicated bearer acceptance");
    return {static_cast<uint8_t>((epsBearerIdentity << 4U) | Esm), procedureTransactionId, 0xC6};
}

std::vector<uint8_t> EncodeActivateDedicatedEpsBearerContextReject(uint8_t epsBearerIdentity,
                                                                   uint8_t procedureTransactionId, uint8_t esmCause)
{
    if (epsBearerIdentity < 5 || epsBearerIdentity > 15)
        throw DecodeError("Invalid EPS bearer identity for dedicated bearer rejection");
    // The ESM cause is mandatory and carried as an LV with a length of one.
    return {static_cast<uint8_t>((epsBearerIdentity << 4U) | Esm), procedureTransactionId, 0xC7, 0x01, esmCause};
}

std::vector<uint8_t> EncodeDeactivateEpsBearerContextAccept(uint8_t epsBearerIdentity,
                                                            uint8_t procedureTransactionId)
{
    if (epsBearerIdentity < 5 || epsBearerIdentity > 15)
        throw DecodeError("Invalid EPS bearer identity for bearer deactivation");
    return {static_cast<uint8_t>((epsBearerIdentity << 4U) | Esm), procedureTransactionId, 0xCE};
}

std::vector<uint8_t> EncodeDetachRequest(uint8_t ksi, const std::array<uint8_t, 11> &guti, bool switchOff)
{
    if (ksi > 6 || (guti[0] & 0x07U) != 0x06U)
        throw DecodeError("Detach Request requires a native EPS KSI and GUTI");
    const uint8_t detachType = static_cast<uint8_t>((ksi << 4U) | (switchOff ? 0x08U : 0U) | 0x01U);
    std::vector<uint8_t> out{EpsEmm, DetachRequestType, detachType, static_cast<uint8_t>(guti.size())};
    out.insert(out.end(), guti.begin(), guti.end());
    return out;
}

std::vector<uint8_t> EncodeTauRequest(uint8_t ksi, const std::array<uint8_t, 11> &guti,
                                      uint8_t defaultEbi, bool periodic)
{
    if (ksi > 6 || (guti[0] & 0x07U) != 0x06U || defaultEbi < 5 || defaultEbi > 15)
        throw DecodeError("TAU Request requires a native EPS KSI, GUTI and default EBI");
    // EPS update type 0 is normal TAU; 3 is periodic TAU. Active flag remains
    // clear so the procedure itself does not claim a bearer restoration.
    const uint8_t updateType = periodic ? 0x03U : 0x00U;
    std::vector<uint8_t> out{EpsEmm, TauRequestType, static_cast<uint8_t>((ksi << 4U) | updateType),
                             static_cast<uint8_t>(guti.size())};
    out.insert(out.end(), guti.begin(), guti.end());
    // TS 24.301 9.9.2.1: octet 3 carries EBI 0..7 and octet 4 carries
    // EBI 8..15, with bit n representing EBI n within its octet.
    std::array<uint8_t, 2> status{};
    status[defaultEbi / 8U] = static_cast<uint8_t>(1U << (defaultEbi % 8U));
    out.insert(out.end(), {IeiBearerContextStatus, 0x02, status[0], status[1]});
    return out;
}

std::vector<uint8_t> EncodeTauComplete()
{
    return {EpsEmm, TauCompleteType};
}

} // namespace lte::ue::nas
