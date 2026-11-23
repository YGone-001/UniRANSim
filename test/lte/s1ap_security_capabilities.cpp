//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//

// Phase 18-F-B6-C: the TS 36.413 UESecurityCapabilities bit order.
#include <ext/doctest/doctest.h>

#include <lte/enb/s1ap_security_capabilities.hpp>

using namespace lte;
using namespace lte::enb::s1ap;
using namespace lte::security;

TEST_CASE("lte/s1ap-capabilities/the bit string is read msb first with eea0 in bit 0")
{
    // Open5GS advertises EEA0/EEA1/EEA2 and EIA0/EIA1/EIA2: the first three
    // bits of each string, which is 0xE0 in the first octet.
    const auto open5gs = MapUeSecurityCapabilities({0xE0, 0x00}, {0xE0, 0x00});
    CHECK(open5gs.present);
    CHECK(open5gs.ciphering == 0x0007);
    CHECK(open5gs.integrity == 0x0007);
    CHECK((open5gs.ciphering & 1U) != 0);  // EEA0
    CHECK((open5gs.ciphering & 4U) != 0);  // EEA2
    CHECK((open5gs.ciphering & 2U) != 0);  // EEA1

    // EEA0 and EEA2 only: bits 0 and 2, first octet 1010 0000.
    const auto eea0eea2 = MapUeSecurityCapabilities({0xA0, 0x00}, {0xA0, 0x00});
    CHECK(eea0eea2.ciphering == 0x0005);
    CHECK(eea0eea2.integrity == 0x0005);

    // Only EEA0/EIA0: the single most significant bit.
    const auto nullOnly = MapUeSecurityCapabilities({0x80, 0x00}, {0x80, 0x00});
    CHECK(nullOnly.ciphering == 0x0001);
    CHECK(nullOnly.integrity == 0x0001);

    // A capability string with a bit in the second octet must land in the
    // corresponding identity, not in the first octet.
    const auto late = MapUeSecurityCapabilities({0x00, 0x40}, {0x00, 0x00});
    CHECK(late.ciphering == (1U << 9));  // second octet bit 1 -> identity 9
}

TEST_CASE("lte/s1ap-capabilities/no capability still means no algorithm, never a default")
{
    const auto none = MapUeSecurityCapabilities({0x00, 0x00}, {0x00, 0x00});
    CHECK(none.present);
    CHECK(none.ciphering == 0);
    CHECK(none.integrity == 0);

    AsAlgorithmConfiguration configuration;
    configuration.ciphering.ordered = {2, 0};
    configuration.integrity.ordered = {2, 0};
    configuration.nasIntegrityAlgorithm = 2;
    try
    {
        (void)SelectAsAlgorithms(none, configuration, 0);
        FAIL("an empty capability set selected an algorithm");
    }
    catch (const SelectionException &error)
    {
        // A present but all-zero capability string has no algorithm to choose.
        CHECK(error.Reason() == SelectionError::UE_CAPABILITIES_MALFORMED);
    }
}

TEST_CASE("lte/s1ap-capabilities/the mapping cannot promote an unadvertised algorithm")
{
    AsAlgorithmConfiguration configuration;
    configuration.ciphering.ordered = {3, 2, 0};  // EEA3 first, then EEA2, then EEA0
    configuration.integrity.ordered = {3, 2, 0};
    configuration.nasIntegrityAlgorithm = 2;

    // The UE advertises EEA0 and EEA2 only. EEA3 is the first allowlist entry
    // and must not be selected.
    const auto aes = MapUeSecurityCapabilities({0xA0, 0x00}, {0xA0, 0x00});
    const auto selection = SelectAsAlgorithms(aes, configuration, 0);
    CHECK(selection.ciphering == 2);
    CHECK(selection.integrity == 2);
    CHECK_FALSE(selection.cipheringNull);

    // A UE that advertises only the null algorithms must get the null one, not
    // an algorithm it never listed - and only when NAS integrity is also null.
    const auto nullOnly = MapUeSecurityCapabilities({0x80, 0x00}, {0x80, 0x00});
    try
    {
        (void)SelectAsAlgorithms(nullOnly, configuration, 0);
        FAIL("EIA0 was selected while NAS integrity was EIA2");
    }
    catch (const SelectionException &error)
    {
        CHECK(error.Reason() == SelectionError::EIA0_WITHOUT_NULL_NAS_INTEGRITY);
    }

    configuration.nasIntegrityAlgorithm = 0;
    const auto nullSelection = SelectAsAlgorithms(nullOnly, configuration, 0);
    CHECK(nullSelection.ciphering == 0);
    CHECK(nullSelection.cipheringNull);
    CHECK(nullSelection.integrityNull);
}

TEST_CASE("lte/s1ap-capabilities/the inverse encoding round trips")
{
    for (uint16_t bitmap : {0x0000, 0x0001, 0x0005, 0x0007, 0x00FF, 0xFF00, 0xFFFF})
    {
        const auto octets = EncodeUeAlgorithmBitmap(bitmap);
        const auto mapped = MapUeSecurityCapabilities(octets, octets);
        CHECK(mapped.ciphering == bitmap);
    }
    CHECK(EncodeUeAlgorithmBitmap(0x0007) == std::array<uint8_t, 2>{0xE0, 0x00});
    CHECK(EncodeUeAlgorithmBitmap(0x0005) == std::array<uint8_t, 2>{0xA0, 0x00});
}
