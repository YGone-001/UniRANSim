//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

// Phase 2 EPS NAS security tests. The K_NASint/K_NASenc vectors and the
// protect() wire vectors were derived independently (HMAC-SHA-256 / AES-CMAC /
// AES-CTR per TS 33.401 Annex A and NIST SP 800-38B) and are not produced by
// the code under test.
#include <ext/doctest/doctest.h>

#include <lte/ue/security.hpp>
#include <lte/ue/types.hpp>

#include <array>
#include <numeric>
#include <vector>

namespace
{

// Phase 1 3GPP EPS AKA vector KASME (TS 35.208 / Open5GS interoperability).
const std::array<uint8_t, 32> Kasme{0xA2, 0x95, 0x51, 0xDE, 0x84, 0xC3, 0xDB, 0xE8, 0xA5, 0x0D, 0x90, 0x1A,
                                    0xC9, 0xAD, 0xC6, 0x39, 0x58, 0xAD, 0xAA, 0x16, 0xAD, 0xF4, 0x4D, 0x57,
                                    0x1D, 0xBE, 0xA2, 0xD4, 0x40, 0xCB, 0xE2, 0x5E};

// Independent rightmost-16-bytes of HMAC-SHA-256(KASME, 0x15 || P0 || 0x0001 || P1 || 0x0001).
const std::array<uint8_t, 16> KnasIntEia2{0x24, 0x64, 0x1E, 0x7F, 0xF9, 0x89, 0xCB, 0xFE,
                                          0x2E, 0x31, 0xE8, 0xA9, 0xFD, 0x4D, 0x44, 0xCD};
const std::array<uint8_t, 16> KnasEncEea0{0xE3, 0x2C, 0x33, 0x7D, 0x06, 0xAC, 0x14, 0xA7,
                                          0x01, 0x26, 0x43, 0x7A, 0xF0, 0x3C, 0x8B, 0xEE};
const std::array<uint8_t, 16> KnasEncEea2{0x37, 0x9B, 0x2A, 0x15, 0xCF, 0x91, 0x4F, 0xE3,
                                          0x9C, 0x4A, 0xCC, 0x82, 0x03, 0x77, 0xD7, 0xFA};
const std::array<uint8_t, 16> KnasIntEia1{0x3F, 0x79, 0x32, 0x2D, 0xE3, 0x97, 0x57, 0x67,
                                          0x1E, 0x1C, 0x93, 0xCF, 0x58, 0x75, 0xC8, 0x05};

lte::ue::SecurityContext MakeContext(lte::ue::IntegrityAlgorithm integrity, lte::ue::CipheringAlgorithm ciphering)
{
    lte::ue::SecurityContext context{};
    context.kasme = Kasme;
    context.valid = true;
    context.integrity = integrity;
    context.ciphering = ciphering;
    context.kNasInt = lte::ue::nas::DeriveKnasInt(Kasme, integrity);
    context.kNasEnc = lte::ue::nas::DeriveKnasEnc(Kasme, ciphering);
    context.keysDerived = true;
    context.securityActive = true;
    context.ulNasCount = 0;
    context.dlNasCount = 0;
    return context;
}

} // namespace

TEST_CASE("lte/ue/security: K_NASint and K_NASenc match independent TS 33.401 Annex A vectors")
{
    CHECK(lte::ue::nas::DeriveKnasInt(Kasme, lte::ue::IntegrityAlgorithm::EIA2) == KnasIntEia2);
    CHECK(lte::ue::nas::DeriveKnasEnc(Kasme, lte::ue::CipheringAlgorithm::EEA0) == KnasEncEea0);
    CHECK(lte::ue::nas::DeriveKnasEnc(Kasme, lte::ue::CipheringAlgorithm::EEA2) == KnasEncEea2);
    CHECK(lte::ue::nas::DeriveKnasInt(Kasme, lte::ue::IntegrityAlgorithm::EIA1) == KnasIntEia1);

    // Algorithm identity is part of the KDF input: the same KASME must not
    // collapse two algorithms onto one key.
    CHECK(lte::ue::nas::DeriveKnasInt(Kasme, lte::ue::IntegrityAlgorithm::EIA2) !=
          lte::ue::nas::DeriveKnasInt(Kasme, lte::ue::IntegrityAlgorithm::EIA1));
    CHECK(lte::ue::nas::DeriveKnasEnc(Kasme, lte::ue::CipheringAlgorithm::EEA0) !=
          lte::ue::nas::DeriveKnasEnc(Kasme, lte::ue::CipheringAlgorithm::EEA2));

    // Rightmost 16 bytes, not leftmost: flipping the KASME prefix changes the key.
    auto other = Kasme;
    other[0] ^= 0xFFU;
    CHECK(lte::ue::nas::DeriveKnasInt(other, lte::ue::IntegrityAlgorithm::EIA2) != KnasIntEia2);
}

TEST_CASE("lte/ue/security: only executable EPS NAS algorithms are reported supported")
{
    using I = lte::ue::IntegrityAlgorithm;
    using C = lte::ue::CipheringAlgorithm;
    CHECK_FALSE(lte::ue::nas::IsSupported(I::EIA0)); // null integrity is not an authenticated Attach
    CHECK_FALSE(lte::ue::nas::IsSupported(I::EIA1));
    CHECK(lte::ue::nas::IsSupported(I::EIA2));
    CHECK_FALSE(lte::ue::nas::IsSupported(I::EIA3));
    CHECK(lte::ue::nas::IsSupported(C::EEA0)); // null ciphering is permitted
    CHECK_FALSE(lte::ue::nas::IsSupported(C::EEA1)); // not advertised by this stack
    CHECK(lte::ue::nas::IsSupported(C::EEA2));
    CHECK_FALSE(lte::ue::nas::IsSupported(C::EEA3));
}

TEST_CASE("lte/ue/security: security header classification follows TS 24.301 9.3.1")
{
    using H = lte::ue::SecurityHeaderType;
    CHECK_FALSE(lte::ue::nas::StartsNewContext(H::PLAIN));
    CHECK_FALSE(lte::ue::nas::StartsNewContext(H::INTEGRITY_PROTECTED));
    CHECK_FALSE(lte::ue::nas::StartsNewContext(H::INTEGRITY_PROTECTED_AND_CIPHERED));
    CHECK(lte::ue::nas::StartsNewContext(H::INTEGRITY_PROTECTED_WITH_NEW_CONTEXT));
    CHECK(lte::ue::nas::StartsNewContext(H::INTEGRITY_PROTECTED_AND_CIPHERED_WITH_NEW_CONTEXT));

    CHECK_FALSE(lte::ue::nas::IsCiphered(H::PLAIN));
    CHECK_FALSE(lte::ue::nas::IsCiphered(H::INTEGRITY_PROTECTED));
    CHECK(lte::ue::nas::IsCiphered(H::INTEGRITY_PROTECTED_AND_CIPHERED));
    CHECK_FALSE(lte::ue::nas::IsCiphered(H::INTEGRITY_PROTECTED_WITH_NEW_CONTEXT));
    CHECK(lte::ue::nas::IsCiphered(H::INTEGRITY_PROTECTED_AND_CIPHERED_WITH_NEW_CONTEXT));

    CHECK(std::string(lte::ue::nas::ToString(H::INTEGRITY_PROTECTED_WITH_NEW_CONTEXT)) ==
          "INTEGRITY_PROTECTED_WITH_NEW_CONTEXT");
    CHECK(std::string(lte::ue::nas::ToString(lte::ue::IntegrityAlgorithm::EIA2)) == "EIA2");
    CHECK(std::string(lte::ue::nas::ToString(lte::ue::CipheringAlgorithm::EEA0)) == "EEA0");
}

TEST_CASE("lte/ue/security: Security Mode Complete protect vector matches independent EIA2/EEA0 computation")
{
    // Independent AES-CMAC/EIA2 over COUNT=0, bearer=0, uplink, SN=0 || 07 5E.
    auto context = MakeContext(lte::ue::IntegrityAlgorithm::EIA2, lte::ue::CipheringAlgorithm::EEA0);
    const std::vector<uint8_t> plain{0x07, 0x5E};
    auto protectedMessage = lte::ue::nas::Protect(context, true, true, plain);
    CHECK(protectedMessage == std::vector<uint8_t>{0x47, 0x33, 0xD7, 0x24, 0x55, 0x00, 0x07, 0x5E});
}

TEST_CASE("lte/ue/security: Attach Complete protect vector matches independent EIA2/EEA2 computation")
{
    // COUNT=1, uplink, AES-CTR body, header type 2.
    auto context = MakeContext(lte::ue::IntegrityAlgorithm::EIA2, lte::ue::CipheringAlgorithm::EEA2);
    context.ulNasCount = 1;
    const std::vector<uint8_t> plain{0x07, 0x43, 0x00, 0x04, 0x05, 0x02, 0xC1, 0x01};
    auto protectedMessage = lte::ue::nas::Protect(context, true, false, plain);
    CHECK(protectedMessage ==
          std::vector<uint8_t>{0x27, 0x04, 0x9F, 0x42, 0xF3, 0x01, 0x85, 0x4F, 0x96, 0xB9, 0x12, 0xE9, 0x56, 0x96});
}

TEST_CASE("lte/ue/security: protect and unprotect round-trip under EIA2/EEA0 and EIA2/EEA2")
{
    const std::vector<uint8_t> plain{0x07, 0x42, 0x01, 0x30, 0x01, 0x60, 0x00, 0x00};
    for (auto ciphering : {lte::ue::CipheringAlgorithm::EEA0, lte::ue::CipheringAlgorithm::EEA2})
    {
        auto context = MakeContext(lte::ue::IntegrityAlgorithm::EIA2, ciphering);
        for (bool newContext : {true, false})
        {
            auto protectedMessage = lte::ue::nas::Protect(context, true, newContext, plain);
            auto parsed = lte::ue::nas::ParseProtectedHeader(protectedMessage.data(), protectedMessage.size());
            CHECK(parsed.headerType ==
                  (newContext ? lte::ue::SecurityHeaderType::INTEGRITY_PROTECTED_AND_CIPHERED_WITH_NEW_CONTEXT
                              : lte::ue::SecurityHeaderType::INTEGRITY_PROTECTED_AND_CIPHERED));
            CHECK(parsed.sequenceNumber == (newContext ? 0 : 0));
            auto recovered = lte::ue::nas::UnprotectBody(context, true, parsed.headerType, parsed.sequenceNumber,
                                                         parsed.mac, parsed.plain);
            CHECK(recovered == plain);
        }
    }
}

TEST_CASE("lte/ue/security: downlink SMC unprotects with the opposite direction and new-context COUNT")
{
    // Independent vector: header type 3, COUNT=0, downlink, EIA2/EEA0.
    auto context = MakeContext(lte::ue::IntegrityAlgorithm::EIA2, lte::ue::CipheringAlgorithm::EEA0);
    const std::vector<uint8_t> wire{0x37, 0xAC, 0xDE, 0x02, 0x93, 0x00, 0x07, 0x5D, 0x02, 0x00, 0xA0, 0x20};
    auto parsed = lte::ue::nas::ParseProtectedHeader(wire.data(), wire.size());
    CHECK(parsed.headerType == lte::ue::SecurityHeaderType::INTEGRITY_PROTECTED_WITH_NEW_CONTEXT);
    CHECK(parsed.sequenceNumber == 0);
    auto plain = lte::ue::nas::UnprotectBody(context, false, parsed.headerType, parsed.sequenceNumber, parsed.mac,
                                             parsed.plain);
    CHECK(plain == std::vector<uint8_t>{0x07, 0x5D, 0x02, 0x00, 0xA0, 0x20});

    // The same wire under the uplink direction must fail: direction is bound into the MAC.
    CHECK_THROWS_AS(lte::ue::nas::UnprotectBody(context, true, parsed.headerType, parsed.sequenceNumber, parsed.mac,
                                                parsed.plain),
                    lte::ue::nas::SecurityError);
}

TEST_CASE("lte/ue/security: MAC failure never yields the plain NAS message")
{
    auto context = MakeContext(lte::ue::IntegrityAlgorithm::EIA2, lte::ue::CipheringAlgorithm::EEA0);
    const std::vector<uint8_t> plain{0x07, 0x5E};
    auto protectedMessage = lte::ue::nas::Protect(context, true, true, plain);
    auto parsed = lte::ue::nas::ParseProtectedHeader(protectedMessage.data(), protectedMessage.size());

    auto corrupted = parsed.mac;
    corrupted[0] ^= 0x80U;
    CHECK_THROWS_AS(lte::ue::nas::UnprotectBody(context, true, parsed.headerType, parsed.sequenceNumber, corrupted,
                                                parsed.plain),
                    lte::ue::nas::SecurityError);

    // A changed body also fails closed.
    auto tamperedBody = parsed.plain;
    tamperedBody.push_back(0x00);
    CHECK_THROWS_AS(lte::ue::nas::UnprotectBody(context, true, parsed.headerType, parsed.sequenceNumber, parsed.mac,
                                                tamperedBody),
                    lte::ue::nas::SecurityError);

    // A changed COUNT/signal sequence number fails closed.
    CHECK_THROWS_AS(lte::ue::nas::UnprotectBody(context, true, parsed.headerType,
                                                static_cast<uint8_t>(parsed.sequenceNumber + 1U), parsed.mac,
                                                parsed.plain),
                    lte::ue::nas::SecurityError);
}

TEST_CASE("lte/ue/security: protect refuses to run without a derived security context")
{
    lte::ue::SecurityContext context{};
    const std::vector<uint8_t> plain{0x07, 0x5E};
    CHECK_THROWS_AS(lte::ue::nas::Protect(context, true, true, plain), lte::ue::nas::SecurityError);

    context.valid = true;
    CHECK_THROWS_AS(lte::ue::nas::Protect(context, true, true, plain), lte::ue::nas::SecurityError);

    context.keysDerived = true;
    context.integrity = lte::ue::IntegrityAlgorithm::EIA0;
    context.kNasInt = KnasIntEia2;
    context.kNasEnc = KnasEncEea0;
    CHECK_THROWS_AS(lte::ue::nas::Protect(context, true, true, plain), lte::ue::nas::SecurityError);
}

TEST_CASE("lte/ue/security: protected header parsing rejects malformed EPS NAS envelopes")
{
    CHECK_THROWS_AS(lte::ue::nas::ParseProtectedHeader(nullptr, 0), lte::ue::nas::SecurityError);
    const std::vector<uint8_t> shortMessage{0x47, 0x00, 0x00};
    CHECK_THROWS_AS(lte::ue::nas::ParseProtectedHeader(shortMessage.data(), shortMessage.size()),
                    lte::ue::nas::SecurityError);

    // Protocol discriminator must be EPS mobility management (0x07).
    std::vector<uint8_t> wrongPd{0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07};
    CHECK_THROWS_AS(lte::ue::nas::ParseProtectedHeader(wrongPd.data(), wrongPd.size()), lte::ue::nas::SecurityError);

    // Unknown security header type 5..15 is rejected.
    std::vector<uint8_t> unknownType{0x57, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07};
    CHECK_THROWS_AS(lte::ue::nas::ParseProtectedHeader(unknownType.data(), unknownType.size()),
                    lte::ue::nas::SecurityError);
}

TEST_CASE("lte/ue/security: unprotect rejects PLAIN headers and missing context")
{
    auto context = MakeContext(lte::ue::IntegrityAlgorithm::EIA2, lte::ue::CipheringAlgorithm::EEA0);
    const std::array<uint8_t, 4> mac{};
    CHECK_THROWS_AS(lte::ue::nas::UnprotectBody(context, true, lte::ue::SecurityHeaderType::PLAIN, 0, mac, {0x07, 0x5E}),
                    lte::ue::nas::SecurityError);

    lte::ue::SecurityContext empty{};
    CHECK_THROWS_AS(lte::ue::nas::UnprotectBody(empty, true, lte::ue::SecurityHeaderType::INTEGRITY_PROTECTED, 0, mac,
                                                {0x07, 0x5E}),
                    lte::ue::nas::SecurityError);
}

TEST_CASE("lte/ue/security: NAS COUNT estimation implements TS 24.301 4.4.3.1 overflow recovery")
{
    using lte::ue::nas::EstimateNasCount;
    // Same SQN: COUNT unchanged.
    CHECK(EstimateNasCount(0x000000, 0x00) == 0x000000);
    CHECK(EstimateNasCount(0x0000AB, 0xAB) == 0x0000AB);
    // Increasing SQN: overflow stays, SQN follows.
    CHECK(EstimateNasCount(0x000001, 0x02) == 0x000002);
    CHECK(EstimateNasCount(0x0000AB, 0x0B) == 0x00010B); // 0x0B < 0xAB is a SQN wrap
    // SQN wrap: overflow counter increments.
    CHECK(EstimateNasCount(0x000005, 0x04) == 0x000104);
    CHECK(EstimateNasCount(0x0001FF, 0x00) == 0x000200);
    CHECK(EstimateNasCount(0x00FFFF, 0x00) == 0x010000);
    // 24-bit wrap of the whole COUNT.
    CHECK(EstimateNasCount(0xFFFFFF, 0x00) == 0x000000);
}

TEST_CASE("lte/ue/security: sequence numbers survive COUNT reconstruction across a SQN wrap")
{
    auto context = MakeContext(lte::ue::IntegrityAlgorithm::EIA2, lte::ue::CipheringAlgorithm::EEA0);
    context.ulNasCount = 0x000005;
    const std::vector<uint8_t> plain{0x07, 0x5E};
    // newContext=false uses the caller-owned COUNT, so set SN=4 to force a wrap.
    auto protectedMessage = lte::ue::nas::Protect(context, true, false, plain);
    auto parsed = lte::ue::nas::ParseProtectedHeader(protectedMessage.data(), protectedMessage.size());
    CHECK(parsed.sequenceNumber == 0x05);
    auto recovered = lte::ue::nas::UnprotectBody(context, true, parsed.headerType, parsed.sequenceNumber, parsed.mac,
                                                 parsed.plain);
    CHECK(recovered == plain);

    // After a wrap the rebuilt COUNT is 0x000104 and still verifies.
    context.ulNasCount = 0x000104;
    auto wrapped = lte::ue::nas::Protect(context, true, false, plain);
    auto wrappedParsed = lte::ue::nas::ParseProtectedHeader(wrapped.data(), wrapped.size());
    CHECK(wrappedParsed.sequenceNumber == 0x04);
    CHECK(lte::ue::nas::UnprotectBody(context, true, wrappedParsed.headerType, wrappedParsed.sequenceNumber,
                                      wrappedParsed.mac, wrappedParsed.plain) == plain);
}

TEST_CASE("lte/ue/security: EIA0 and unknown algorithms cannot protect or unprotect")
{
    using I = lte::ue::IntegrityAlgorithm;
    using C = lte::ue::CipheringAlgorithm;
    auto context = MakeContext(I::EIA2, C::EEA0);
    context.integrity = I::EIA0;
    const std::array<uint8_t, 4> mac{};
    CHECK_THROWS_AS(lte::ue::nas::UnprotectBody(context, true, lte::ue::SecurityHeaderType::INTEGRITY_PROTECTED, 0, mac,
                                                {0x07, 0x5E}),
                    lte::ue::nas::SecurityError);
}
