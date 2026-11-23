//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//

#include "s1ap_security_capabilities.hpp"

namespace lte::enb::s1ap
{
namespace
{

uint16_t ReverseBits(uint16_t value)
{
    uint16_t out = 0;
    for (int i = 0; i < 16; i++)
    {
        if ((value & (1U << i)) != 0)
            out = static_cast<uint16_t>(out | (1U << (15 - i)));
    }
    return out;
}

uint16_t ReadWord(const std::array<uint8_t, 2> &octets)
{
    return static_cast<uint16_t>((static_cast<uint16_t>(octets[0]) << 8U) | octets[1]);
}

} // namespace

lte::security::UeAlgorithmCapabilities MapUeSecurityCapabilities(const std::array<uint8_t, 2> &encryption,
                                                               const std::array<uint8_t, 2> &integrity)
{
    lte::security::UeAlgorithmCapabilities capabilities;
    capabilities.present = true;
    capabilities.ciphering = ReverseBits(ReadWord(encryption));
    capabilities.integrity = ReverseBits(ReadWord(integrity));
    return capabilities;
}

std::array<uint8_t, 2> EncodeUeAlgorithmBitmap(uint16_t bitmap)
{
    const uint16_t raw = ReverseBits(bitmap);
    return {static_cast<uint8_t>((raw >> 8U) & 0xFFU), static_cast<uint8_t>(raw & 0xFFU)};
}

} // namespace lte::enb::s1ap
