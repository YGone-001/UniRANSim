//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#include "nas.hpp"

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
constexpr uint8_t AuthenticationRequestType = 0x52;
constexpr uint8_t AuthenticationResponseType = 0x53;
constexpr uint8_t AuthenticationFailureType = 0x5C;
constexpr uint8_t SecurityModeCommandType = 0x5D;
constexpr uint8_t PdnConnectivityRequestType = 0xD0;

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
        esm.push_back(0x28); // Access point name
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
    // sequence number, then the plain EMM message. Phase 1 recognizes this
    // authoritative post-AKA signal but intentionally defers MAC verification
    // and Security Mode Complete to Phase 2.
    if (securityHeaderType > 4 || size < 8)
        return false;
    return data[6] == EpsEmm && data[7] == SecurityModeCommandType;
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

} // namespace lte::ue::nas
