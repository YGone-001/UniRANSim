//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#include "kdf.hpp"

#include <algorithm>
#include <stdexcept>

#include <lib/crypt/crypt.hpp>
#include <utils/octet_string.hpp>

namespace lte::security
{

ByteString EncodeKdfInput(uint8_t fc, const std::vector<ByteString> &parameters)
{
    ByteString input;
    input.reserve(1 + parameters.size() * 4);
    input.push_back(fc);
    for (const auto &parameter : parameters)
    {
        if (parameter.size() > 0xFFFFU)
            throw std::length_error("KDF parameter does not fit a two-byte length");
        input.insert(input.end(), parameter.begin(), parameter.end());
        input.push_back(static_cast<uint8_t>((parameter.size() >> 8U) & 0xFFU));
        input.push_back(static_cast<uint8_t>(parameter.size() & 0xFFU));
    }
    return input;
}

Key256 Kdf(const Key256 &key, uint8_t fc, const std::vector<ByteString> &parameters)
{
    // The parameters are handed to the project KDF as OctetStrings; it performs
    // the same FC/length framing and the HMAC-SHA-256 itself.
    std::vector<OctetString> encoded;
    encoded.reserve(parameters.size());
    for (const auto &parameter : parameters)
        encoded.push_back(OctetString(ByteString(parameter)));

    auto result = crypto::CalculateKdfKey(OctetString::FromArray(key.data(), key.size()), fc,
                                          encoded.empty() ? nullptr : encoded.data(),
                                          static_cast<int>(encoded.size()));
    if (result.length() != static_cast<int>(key.size()))
        throw std::runtime_error("3GPP KDF returned an unexpected length");

    Key256 out{};
    std::copy(result.data(), result.data() + out.size(), out.begin());
    return out;
}

} // namespace lte::security
