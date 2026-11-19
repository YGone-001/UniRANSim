//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

// Phase 18-F-B5-R1: AS algorithm negotiation, the SecurityMode procedure over
// the SRB1 PDCP profile, and the two LTE PDCP bearer profiles of TS 36.323.
//
// The RRC vectors are UPER encodings of TS 36.331 structures. Every PDCP MAC-I
// and ciphertext below was computed independently with OpenSSL AES-128-CMAC and
// AES-128-CTR over the TS 33.401 inputs, never by the code under test.
#include <ext/doctest/doctest.h>

#include <lte/security/as_algorithm_selection.hpp>
#include <lte/security/as_security.hpp>
#include <lte/security/as_security_codec.hpp>
#include <lte/security/as_security_procedure.hpp>
#include <lte/security/pdcp_security.hpp>

#include <algorithm>
#include <functional>
#include <string>
#include <type_traits>
#include <vector>

namespace
{

std::vector<uint8_t> Hex(const std::string &text)
{
    std::vector<uint8_t> out;
    for (size_t i = 0; i + 1 < text.size(); i += 2)
        out.push_back(static_cast<uint8_t>(std::stoul(text.substr(i, 2), nullptr, 16)));
    return out;
}

lte::security::Key256 Key(const std::string &text)
{
    auto bytes = Hex(text);
    lte::security::Key256 out{};
    REQUIRE(bytes.size() == out.size());
    std::copy(bytes.begin(), bytes.end(), out.begin());
    return out;
}

lte::security::Key128 Key16(const std::string &text)
{
    auto bytes = Hex(text);
    lte::security::Key128 out{};
    REQUIRE(bytes.size() == out.size());
    std::copy(bytes.begin(), bytes.end(), out.begin());
    return out;
}

const std::string KasmeAHex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const std::string KasmeBHex = "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f";
const char *KenbCount0Hex = "e6267359de012d9bda173d1b6fae57dec0e04e01cfcf57cb33a7573f142b8b95";
const char *KRrcIntEia2Hex = "2f6e105d4dda7c910c988fcadc7b4844";
const char *KRrcEncEea2Hex = "ae14c26e3ba014f8e4279841fb8ade28";
const char *KUpEncEea1Hex = "34213661a0f7b726bf64faa986f6e280";

// SRB1, COUNT 0, BEARER 0, DIRECTION 0, data 2800:
//   MAC-I = OpenSSL CMAC over COUNT||BEARER||DIR||0^26||(00 2800) -> 7527c93b
//   data||MAC-I ciphered with EEA2 (COUNT 0, BEARER 0, DIR 0)   -> 2b39107a6b9d
const char *SrbMacHex = "7527c93b";
const char *SrbCipherHex = "2b39107a6b9d";
// DIRECTION 1: MAC-I = c159e70a over COUNT||BEARER 0||DIR 1||0^26||(00 2800),
// and data||MAC-I ciphered with the DIRECTION 1 keystream -> 803d834dcc49.
const char *SrbCipherDownlinkHex = "803d834dcc49";
// DRB RB identity 3 -> BEARER 2 (bits 32-36 of the IV, so the octet is 0x10),
// COUNT 0, DIR 0, data 2800, EEA2 -> f81f
const char *DrbCipherHex = "f81f";

lte::security::AsSecurityContext MakeContext(uint32_t ueId, const std::string &kasme = KasmeAHex)
{
    lte::security::AsAlgorithmSet set;
    set.negotiated = false;
    return lte::security::AsSecurityContext::Create(ueId, Key(kasme), 0, 1, set);
}

lte::security::UeAlgorithmCapabilities Capabilities(uint16_t ciphering = 0x000F, uint16_t integrity = 0x000F)
{
    lte::security::UeAlgorithmCapabilities caps;
    caps.present = true;
    caps.ciphering = ciphering;
    caps.integrity = integrity;
    return caps;
}

lte::security::AsAlgorithmConfiguration Configuration(std::vector<uint8_t> order = {2, 1, 3}, uint64_t generation = 5)
{
    lte::security::AsAlgorithmConfiguration config;
    config.ciphering.ordered = order;
    config.integrity.ordered = order;
    config.ciphering.generation = generation;
    config.integrity.generation = generation;
    config.nasIntegrityAlgorithm = 2;
    return config;
}

constexpr lte::security::SelectionError NoSelectionRefusal = static_cast<lte::security::SelectionError>(0xFF);
constexpr lte::security::ProcedureError NoProcedureRefusal = static_cast<lte::security::ProcedureError>(0xFF);
constexpr lte::security::PdcpSecurityError NoPdcpRefusal = static_cast<lte::security::PdcpSecurityError>(0xFF);

template <typename E, E Sentinel, typename Fn> E RefusalOf(Fn &&action)
{
    try
    {
        action();
    }
    catch (const lte::security::SelectionException &error)
    {
        if constexpr (std::is_same_v<E, lte::security::SelectionError>)
            return error.Reason();
    }
    catch (const lte::security::ProcedureException &error)
    {
        if constexpr (std::is_same_v<E, lte::security::ProcedureError>)
            return error.Reason();
    }
    catch (const lte::security::PdcpSecurityException &error)
    {
        if constexpr (std::is_same_v<E, lte::security::PdcpSecurityError>)
            return error.Reason();
    }
    return Sentinel;
}

lte::security::PdcpSecurityEntity MakeSrb(bool uplink, uint8_t integrity = 2, uint8_t ciphering = 2)
{
    return lte::security::PdcpSecurityEntity::Create(lte::security::PdcpProfile::SRB,
                                                     lte::security::RadioBearerIdentity::Srb1(), uplink, integrity,
                                                     ciphering, Key16(KRrcIntEia2Hex), Key16(KRrcEncEea2Hex));
}

} // namespace

// --- Algorithm selection ----------------------------------------------------

TEST_CASE("lte/as-sec5r1/selection is the first common algorithm in operator order")
{
    using namespace lte::security;

    // Every algorithm advertised: the allowlist order decides, not the identity.
    auto selection = SelectAsAlgorithms(Capabilities(), Configuration({1, 2, 3}), 5);
    CHECK(selection.ciphering == 1);
    CHECK(selection.integrity == 1);

    // UE advertises EEA0 and EEA2 only. EEA1 is first in the allowlist but is
    // NOT in the UE set, so the answer is EEA2 - the B5 report's example said
    // EEA1 here and was wrong.
    auto second = SelectAsAlgorithms(Capabilities(0x0005, 0x0005), Configuration({1, 2, 3}), 5);
    CHECK(second.ciphering == 2);
    CHECK(second.integrity == 2);

    // A policy that permits only an algorithm the UE lacks has no intersection.
    CHECK(RefusalOf<SelectionError, NoSelectionRefusal>(
              [&] { (void)SelectAsAlgorithms(Capabilities(0x0005, 0x0005), Configuration({1}), 5); }) ==
          SelectionError::NO_COMMON_ALGORITHM);

    // Deterministic.
    CHECK(SelectAsAlgorithms(Capabilities(0x0005, 0x0005), Configuration({1, 2, 3}), 5).ciphering == 2);
}

TEST_CASE("lte/as-sec5r1/selection fails closed")
{
    using namespace lte::security;

    CHECK(RefusalOf<SelectionError, NoSelectionRefusal>(
              [&] { (void)SelectAsAlgorithms(UeAlgorithmCapabilities{}, Configuration(), 5); }) ==
          SelectionError::UE_CAPABILITIES_MISSING);
    CHECK(RefusalOf<SelectionError, NoSelectionRefusal>(
              [&] { (void)SelectAsAlgorithms(Capabilities(0, 0x000F), Configuration(), 5); }) ==
          SelectionError::UE_CAPABILITIES_MALFORMED);
    CHECK(RefusalOf<SelectionError, NoSelectionRefusal>(
              [&] { (void)SelectAsAlgorithms(Capabilities(), Configuration({}), 5); }) ==
          SelectionError::ALLOWLIST_EMPTY);
    CHECK(RefusalOf<SelectionError, NoSelectionRefusal>(
              [&] { (void)SelectAsAlgorithms(Capabilities(0x0001, 0x0001), Configuration({1, 2}), 5); }) ==
          SelectionError::NO_COMMON_ALGORITHM);
    CHECK(RefusalOf<SelectionError, NoSelectionRefusal>(
              [&] { (void)SelectAsAlgorithms(Capabilities(), Configuration({2}), 4); }) ==
          SelectionError::STALE_CONFIGURATION);
    CHECK(RefusalOf<SelectionError, NoSelectionRefusal>(
              [&] { (void)SelectAsAlgorithms(Capabilities(), Configuration({16}), 5); }) ==
          SelectionError::INVALID_ALGORITHM_IDENTITY);
}

TEST_CASE("lte/as-sec5r1/null algorithms stay classified and EIA0 stays restricted")
{
    using namespace lte::security;

    auto config = Configuration({0, 1});
    config.nasIntegrityAlgorithm = 0;  // NAS is also null
    auto selection = SelectAsAlgorithms(Capabilities(0x0001, 0x0003), config, 5);
    CHECK(selection.ciphering == 0);
    CHECK(selection.cipheringNull);
    CHECK(selection.Describe().find("no confidentiality") != std::string::npos);
    CHECK_FALSE(ProvidesProtection(AsAlgorithmDirection::CIPHERING, 0));

    auto nullFirst = Configuration({0, 2});
    nullFirst.nasIntegrityAlgorithm = 2;
    CHECK(RefusalOf<SelectionError, NoSelectionRefusal>(
              [&] { (void)SelectAsAlgorithms(Capabilities(0x0001, 0x0003), nullFirst, 5); }) ==
          SelectionError::EIA0_WITHOUT_NULL_NAS_INTEGRITY);
}

// --- RRC codec --------------------------------------------------------------

TEST_CASE("lte/as-sec5r1/security mode messages keep their pinned encodings")
{
    using namespace lte::security;

    SecurityModeCommandMessage command;
    command.transactionId = 0;
    command.cipheringAlgorithm = 2;
    command.integrityAlgorithm = 2;
    CHECK(EncodeSecurityModeCommand(command) == Hex("300220"));

    SecurityModeCompleteMessage complete;
    complete.transactionId = 0;
    CHECK(EncodeSecurityModeComplete(complete) == Hex("2800"));

    SecurityModeFailureMessage failure;
    failure.transactionId = 0;
    CHECK(EncodeSecurityModeFailure(failure) == Hex("3000"));

    for (uint8_t tx = 0; tx <= MaxRrcTransactionId; tx++)
    {
        command.transactionId = tx;
        auto bytes = EncodeSecurityModeCommand(command);
        SecurityModeCommandMessage decoded;
        REQUIRE(DecodeSecurityModeCommand(bytes.data(), bytes.size(), decoded));
        CHECK(decoded.transactionId == tx);
    }

    auto failureBytes = EncodeSecurityModeFailure(failure);
    SecurityModeCompleteMessage wrong;
    CHECK_FALSE(DecodeSecurityModeComplete(failureBytes.data(), failureBytes.size(), wrong));
}

// --- Bearer identity --------------------------------------------------------

TEST_CASE("lte/as-sec5r1/bearer identity maps to the algorithm BEARER field")
{
    using namespace lte::security;

    CHECK(RadioBearerIdentity::Srb1().rbId == 1);
    CHECK(RadioBearerIdentity::Srb1().BearerField() == 0);
    CHECK(RadioBearerIdentity::Srb2().BearerField() == 1);
    CHECK(RadioBearerIdentity::Drb(3).BearerField() == 2);
    CHECK_FALSE(RadioBearerIdentity{0}.Valid());

    // The SRB profile refuses a DRB identity and vice versa.
    CHECK(RefusalOf<PdcpSecurityError, NoPdcpRefusal>([&] {
              (void)PdcpSecurityEntity::Create(PdcpProfile::SRB, RadioBearerIdentity::Drb(3), true, 2, 2,
                                               Key16(KRrcIntEia2Hex), Key16(KRrcEncEea2Hex));
          }) == PdcpSecurityError::UNSUPPORTED_BEARER);
    CHECK(RefusalOf<PdcpSecurityError, NoPdcpRefusal>([&] {
              (void)PdcpSecurityEntity::Create(PdcpProfile::DRB12, RadioBearerIdentity::Srb1(), true, 0, 2,
                                               Key16(KRrcIntEia2Hex), Key16(KRrcEncEea2Hex));
          }) == PdcpSecurityError::UNSUPPORTED_BEARER);
}

// --- SRB1 profile -----------------------------------------------------------

TEST_CASE("lte/as-sec5r1/srb1 uses a five-bit header, ciphers data and MAC-I, and leaves the header clear")
{
    using namespace lte::security;

    // Integrity only: header 00, data 2800, MAC-I 7527c93b.
    auto integrityOnly = MakeSrb(true, 2, 0);
    integrityOnly.ActivateIntegrity();
    CHECK(integrityOnly.Protect(Hex("2800")) == Hex(std::string("00") + "2800" + SrbMacHex));

    // Integrity and ciphering: the header stays 00, data+MAC-I are ciphered.
    auto both = MakeSrb(true, 2, 2);
    both.ActivateIntegrity();
    both.ActivateCiphering();
    CHECK(both.Protect(Hex("2800")) == Hex(std::string("00") + SrbCipherHex));

    // Downlink uses DIRECTION = 1 and therefore a different keystream.
    auto downlink = MakeSrb(false, 2, 2);
    downlink.ActivateIntegrity();
    downlink.ActivateCiphering();
    CHECK(downlink.Protect(Hex("2800")) == Hex(std::string("00") + SrbCipherDownlinkHex));
}

TEST_CASE("lte/as-sec5r1/srb1 round trips and rejects tamper, replay and a wrong bearer field")
{
    using namespace lte::security;

    auto tx = MakeSrb(true);
    auto rx = MakeSrb(true);
    tx.ActivateIntegrity();
    tx.ActivateCiphering();
    rx.ActivateIntegrity();
    rx.ActivateCiphering();

    const auto plain = Hex("280011223344");
    const auto pdu = tx.Protect(plain);
    CHECK(rx.Unprotect(pdu) == plain);

    // The header is not ciphered: the first octet is the SN.
    CHECK(pdu[0] == 0x00);

    auto tampered = pdu;
    tampered[2] ^= 0x01;
    CHECK(RefusalOf<PdcpSecurityError, NoPdcpRefusal>(
              [&] { (void)rx.Unprotect(tampered); }) == PdcpSecurityError::INTEGRITY_FAILURE);
    CHECK(RefusalOf<PdcpSecurityError, NoPdcpRefusal>(
              [&] { (void)rx.Unprotect(pdu); }) == PdcpSecurityError::REPLAY_DETECTED);

    // SRB2 is a different BEARER field (1), so the MAC-I cannot verify.
    auto srb2 = PdcpSecurityEntity::Create(PdcpProfile::SRB, RadioBearerIdentity::Srb2(), true, 2, 2,
                                           Key16(KRrcIntEia2Hex), Key16(KRrcEncEea2Hex));
    srb2.ActivateIntegrity();
    srb2.ActivateCiphering();
    CHECK(RefusalOf<PdcpSecurityError, NoPdcpRefusal>(
              [&] { (void)srb2.Unprotect(pdu); }) == PdcpSecurityError::INTEGRITY_FAILURE);
}

TEST_CASE("lte/as-sec5r1/srb1 rejects reserved header bits")
{
    using namespace lte::security;

    auto rx = MakeSrb(true);
    rx.ActivateIntegrity();
    rx.ActivateCiphering();

    // A header with a reserved bit set is malformed, not a different SN.
    auto pdu = Hex("e0" + std::string("00112233445566778899aabb"));
    CHECK(RefusalOf<PdcpSecurityError, NoPdcpRefusal>(
              [&] { (void)rx.Unprotect(pdu); }) == PdcpSecurityError::MALFORMED_HEADER);
}

TEST_CASE("lte/as-sec5r1/srb1 COUNT rolls the 27-bit HFN over a 5-bit SN")
{
    using namespace lte::security;

    auto tx = MakeSrb(true, 2, 0);
    auto rx = MakeSrb(true, 2, 0);
    tx.ActivateIntegrity();
    rx.ActivateIntegrity();

    // 32 PDUs take the SN from 0 to 31; the 33rd reuses SN 0 with HFN 1.
    for (int i = 0; i < 32; i++)
        CHECK(rx.Unprotect(tx.Protect(Hex("aa"))) == Hex("aa"));
    CHECK(rx.LastRxCount() == 31);
    CHECK(rx.Unprotect(tx.Protect(Hex("aa"))) == Hex("aa"));
    CHECK(rx.LastRxCount() == 32);
}

// --- DRB profile ------------------------------------------------------------

TEST_CASE("lte/as-sec5r1/drb12 carries no MAC-I, ciphers data only, and keeps the header clear")
{
    using namespace lte::security;

    auto drb = PdcpSecurityEntity::Create(PdcpProfile::DRB12, RadioBearerIdentity::Drb(3), true, 0, 2,
                                          Key16(KUpEncEea1Hex), Key16(KRrcEncEea2Hex));
    drb.ActivateCiphering();
    const auto pdu = drb.Protect(Hex("2800"));

    // Header 8000 (D/C = 1, SN 0), then the ciphered data. No MAC-I.
    CHECK(pdu == Hex(std::string("8000") + DrbCipherHex));
    CHECK(pdu.size() == 2 + 2);

    // The header is clear and the D/C bit is set.
    CHECK(pdu[0] == 0x80);
    CHECK(pdu[1] == 0x00);
}

TEST_CASE("lte/as-sec5r1/drb12 refuses integrity and round trips with a 12-bit COUNT")
{
    using namespace lte::security;

    // The ordinary UE DRB profile has no integrity protection.
    CHECK(RefusalOf<PdcpSecurityError, NoPdcpRefusal>([&] {
              (void)PdcpSecurityEntity::Create(PdcpProfile::DRB12, RadioBearerIdentity::Drb(3), true, 2, 2,
                                               Key16(KRrcIntEia2Hex), Key16(KRrcEncEea2Hex));
          }) == PdcpSecurityError::UNSUPPORTED_PROFILE);

    auto tx = PdcpSecurityEntity::Create(PdcpProfile::DRB12, RadioBearerIdentity::Drb(3), true, 0, 2,
                                         Key16(KUpEncEea1Hex), Key16(KRrcEncEea2Hex));
    auto rx = PdcpSecurityEntity::Create(PdcpProfile::DRB12, RadioBearerIdentity::Drb(3), true, 0, 2,
                                         Key16(KUpEncEea1Hex), Key16(KRrcEncEea2Hex));
    tx.ActivateCiphering();
    rx.ActivateCiphering();

    // 4096 PDUs wrap the 12-bit SN and advance the 20-bit HFN.
    for (int i = 0; i < 4096; i++)
        CHECK(rx.Unprotect(tx.Protect(Hex("0102"))) == Hex("0102"));
    CHECK(rx.LastRxCount() == 4095);
    CHECK(rx.Unprotect(tx.Protect(Hex("0102"))) == Hex("0102"));
    CHECK(rx.LastRxCount() == 4096);

    // A DRB PDU presented to an SRB entity is not the same wire format. The
    // short one is too short for header + MAC-I; the long one has the DRB
    // first octet 0x80 in the SRB header position, which sets reserved bits.
    auto srb = MakeSrb(true);
    srb.ActivateIntegrity();
    srb.ActivateCiphering();
    CHECK(RefusalOf<PdcpSecurityError, NoPdcpRefusal>(
              [&] { (void)srb.Unprotect(tx.Protect(Hex("0102"))); }) == PdcpSecurityError::PDU_TOO_SHORT);
    CHECK(RefusalOf<PdcpSecurityError, NoPdcpRefusal>(
              [&] { (void)srb.Unprotect(tx.Protect(Hex("0102030405060708"))); }) ==
          PdcpSecurityError::MALFORMED_HEADER);
}

TEST_CASE("lte/as-sec5r1/srb and drb keep independent sequence state")
{
    using namespace lte::security;

    auto srb = MakeSrb(true, 2, 0);
    auto drb = PdcpSecurityEntity::Create(PdcpProfile::DRB12, RadioBearerIdentity::Drb(3), true, 0, 2,
                                          Key16(KUpEncEea1Hex), Key16(KRrcEncEea2Hex));
    srb.ActivateIntegrity();
    drb.ActivateCiphering();

    (void)srb.Protect(Hex("aa"));
    CHECK(srb.NextTxCount() == 1);
    CHECK(drb.NextTxCount() == 0);
    (void)drb.Protect(Hex("bb"));
    CHECK(drb.NextTxCount() == 1);
    CHECK(srb.NextTxCount() == 1);
}

// --- The procedure ----------------------------------------------------------

TEST_CASE("lte/as-sec5r1/the procedure carries the command on SRB1 and completes on both sides")
{
    using namespace lte::security;

    auto enb = MakeContext(7);
    auto ue = MakeContext(7);
    auto procedure = EnbAsSecurityProcedure::Start(enb, 7, Capabilities(), Configuration({2}), 5, 0);

    CHECK(procedure.State() == AsSecurityState::COMMAND_PENDING);
    const auto command = procedure.Command();
    // One-octet SRB1 header (SN 0), the pinned command, a 4-byte MAC-I.
    CHECK(command.size() == 1 + 3 + 4);
    CHECK(command[0] == 0x00);
    CHECK(ExtractPdcpPayload(command, PdcpProfile::SRB) == Hex("300220"));
    CHECK_FALSE(procedure.CipheringActive());

    auto ueProcedure = UeAsSecurityProcedure::Listening(ue, 7);
    auto complete = ueProcedure.OnCommand(command);
    CHECK(ueProcedure.State() == AsSecurityState::COMPLETE_PENDING);
    CHECK_FALSE(ueProcedure.CipheringActive());

    procedure.OnComplete(complete);
    CHECK(procedure.State() == AsSecurityState::ACTIVE);
    CHECK(procedure.CipheringActive());

    ueProcedure.ConfirmCompleteSent();
    CHECK(ueProcedure.State() == AsSecurityState::ACTIVE);
    CHECK(ueProcedure.CipheringActive());

    // Same KASME and COUNT on both sides, same KeNB.
    CHECK(ue.ActiveKenb() == enb.ActiveKenb());
}

TEST_CASE("lte/as-sec5r1/a corrupted command is answered with a failure and activates nothing")
{
    using namespace lte::security;

    auto enb = MakeContext(7);
    auto ue = MakeContext(7);
    auto procedure = EnbAsSecurityProcedure::Start(enb, 7, Capabilities(), Configuration({2}), 5, 1);

    auto command = procedure.Command();
    command.back() ^= 0xFF;  // break the MAC-I, keep the message decodable

    auto ueProcedure = UeAsSecurityProcedure::Listening(ue, 7);
    auto response = ueProcedure.OnCommand(command);
    CHECK(ueProcedure.State() == AsSecurityState::FAILED);
    CHECK_FALSE(ueProcedure.CipheringActive());

    SecurityModeFailureMessage failure;
    CHECK(DecodeSecurityModeFailure(response.data(), response.size(), failure));
    CHECK(failure.transactionId == 1);
    CHECK(procedure.State() == AsSecurityState::COMMAND_PENDING);
    CHECK_FALSE(procedure.CipheringActive());
}

TEST_CASE("lte/as-sec5r1/an unverifiable completion leaves the eNB failed")
{
    using namespace lte::security;

    auto enb = MakeContext(7);
    auto ue = MakeContext(7);
    auto procedure = EnbAsSecurityProcedure::Start(enb, 7, Capabilities(), Configuration({2}), 5, 0);
    auto ueProcedure = UeAsSecurityProcedure::Listening(ue, 7);
    auto complete = ueProcedure.OnCommand(procedure.Command());
    complete.back() ^= 0xFF;

    CHECK(RefusalOf<ProcedureError, NoProcedureRefusal>(
              [&] { procedure.OnComplete(complete); }) == ProcedureError::INTEGRITY_FAILURE);
    CHECK(procedure.State() == AsSecurityState::FAILED);
    CHECK_FALSE(procedure.CipheringActive());
}

TEST_CASE("lte/as-sec5r1/two UEs cannot satisfy each other's transaction")
{
    using namespace lte::security;

    auto enbA = MakeContext(1, KasmeAHex);
    auto ueA = MakeContext(1, KasmeAHex);
    auto enbB = MakeContext(2, KasmeBHex);
    auto ueB = MakeContext(2, KasmeBHex);

    auto procA = EnbAsSecurityProcedure::Start(enbA, 1, Capabilities(), Configuration({2}), 5, 0);
    auto procB = EnbAsSecurityProcedure::Start(enbB, 2, Capabilities(), Configuration({2}), 5, 0);
    auto ueProcA = UeAsSecurityProcedure::Listening(ueA, 1);
    auto ueProcB = UeAsSecurityProcedure::Listening(ueB, 2);
    auto completeA = ueProcA.OnCommand(procA.Command());
    auto completeB = ueProcB.OnCommand(procB.Command());

    procA.OnComplete(completeA);
    procB.OnComplete(completeB);
    CHECK(procA.State() == AsSecurityState::ACTIVE);
    CHECK(procB.State() == AsSecurityState::ACTIVE);

    // UE A's completion replayed at a transaction for UE B fails its MAC-I.
    auto enbB2 = MakeContext(2, KasmeBHex);
    auto procB2 = EnbAsSecurityProcedure::Start(enbB2, 2, Capabilities(), Configuration({2}), 5, 0);
    CHECK(RefusalOf<ProcedureError, NoProcedureRefusal>(
              [&] { procB2.OnComplete(completeA); }) == ProcedureError::INTEGRITY_FAILURE);
    CHECK(procB2.State() == AsSecurityState::FAILED);
    CHECK(enbA.ActiveKenb() != enbB.ActiveKenb());
}

TEST_CASE("lte/as-sec5r1/the key hierarchy still matches the B4 vectors")
{
    using namespace lte::security;

    auto context = MakeContext(7);
    CHECK(context.ActiveKenb() == Key(KenbCount0Hex));

    AsAlgorithmSet set;
    set.negotiated = true;
    set.rrcIntegrity = 2;
    set.rrcCiphering = 2;
    set.upCiphering = 1;
    context.ApplyAsAlgorithms(set);
    auto keys = context.DeriveAccessKeys();
    CHECK(keys.kRrcInt == Key16(KRrcIntEia2Hex));
    CHECK(keys.kRrcEnc == Key16(KRrcEncEea2Hex));
    CHECK_FALSE(keys.kUpInt.has_value());
}
