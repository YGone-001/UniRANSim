//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

// Phase 18-F-B5: AS algorithm negotiation, the SecurityMode procedure over
// PDCP, and PDCP security composition.
//
// The RRC message vectors are the UPER encodings of TS 36.331 structures; the
// PDCP MAC-I and ciphertext vectors were computed independently with OpenSSL
// AES-128-CMAC and AES-128-CTR over the TS 33.401 inputs, not by this code.
#include <ext/doctest/doctest.h>

#include <lte/security/as_algorithm_selection.hpp>
#include <lte/security/as_security.hpp>
#include <lte/security/as_security_codec.hpp>
#include <lte/security/as_security_procedure.hpp>
#include <lte/security/pdcp_security.hpp>

#include <algorithm>
#include <array>
#include <functional>
#include <string>
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

lte::security::AsSecurityContext MakeContext(uint32_t ueId, const std::string &kasme = KasmeAHex)
{
    lte::security::AsAlgorithmSet set;
    set.negotiated = false;
    return lte::security::AsSecurityContext::Create(ueId, Key(kasme), 0, 1, set);
}

lte::security::UeAlgorithmCapabilities Capabilities(bool ciphering = true, bool integrity = true)
{
    lte::security::UeAlgorithmCapabilities caps;
    caps.present = true;
    caps.ciphering = ciphering ? 0x000FU : 0;
    caps.integrity = integrity ? 0x000FU : 0;
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

template <typename E, typename Fn, E Sentinel> E RefusalOf(Fn &&action)
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

} // namespace

// --- Algorithm selection ----------------------------------------------------

TEST_CASE("lte/as-sec5/selection honours the operator order, not the numeric one")
{
    using namespace lte::security;

    // The allowlist says EEA1 before EEA2 even though 2 > 1 numerically.
    auto selection = SelectAsAlgorithms(Capabilities(), Configuration({1, 2, 3}), 5);
    CHECK(selection.ciphering == 1);
    CHECK(selection.integrity == 1);

    // A UE that does not advertise EEA1 gets the next entry.
    UeAlgorithmCapabilities caps;
    caps.present = true;
    caps.ciphering = 0x0005;  // EEA0 and EEA2
    caps.integrity = 0x0005;
    auto second = SelectAsAlgorithms(caps, Configuration({1, 2, 3}), 5);
    CHECK(second.ciphering == 2);
    CHECK(second.integrity == 2);

    // Deterministic: same request, same answer.
    CHECK(SelectAsAlgorithms(caps, Configuration({1, 2, 3}), 5).ciphering == second.ciphering);
}

TEST_CASE("lte/as-sec5/selection fails closed")
{
    using namespace lte::security;

    CHECK(RefusalOf<SelectionError, std::function<void()>, NoSelectionRefusal>(
              [&] { (void)SelectAsAlgorithms(UeAlgorithmCapabilities{}, Configuration(), 5); }) ==
          SelectionError::UE_CAPABILITIES_MISSING);

    auto zero = Capabilities();
    zero.ciphering = 0;
    CHECK(RefusalOf<SelectionError, std::function<void()>, NoSelectionRefusal>(
              [&] { (void)SelectAsAlgorithms(zero, Configuration(), 5); }) == SelectionError::UE_CAPABILITIES_MALFORMED);

    CHECK(RefusalOf<SelectionError, std::function<void()>, NoSelectionRefusal>(
              [&] { (void)SelectAsAlgorithms(Capabilities(), Configuration({}), 5); }) ==
          SelectionError::ALLOWLIST_EMPTY);

    UeAlgorithmCapabilities onlyZero;
    onlyZero.present = true;
    onlyZero.ciphering = 0x0001;
    onlyZero.integrity = 0x0001;
    CHECK(RefusalOf<SelectionError, std::function<void()>, NoSelectionRefusal>(
              [&] { (void)SelectAsAlgorithms(onlyZero, Configuration({1, 2}), 5); }) ==
          SelectionError::NO_COMMON_ALGORITHM);

    CHECK(RefusalOf<SelectionError, std::function<void()>, NoSelectionRefusal>(
              [&] { (void)SelectAsAlgorithms(Capabilities(), Configuration({2}), 4); }) ==
          SelectionError::STALE_CONFIGURATION);

    CHECK(RefusalOf<SelectionError, std::function<void()>, NoSelectionRefusal>(
              [&] { (void)SelectAsAlgorithms(Capabilities(), Configuration({16}), 5); }) ==
          SelectionError::INVALID_ALGORITHM_IDENTITY);
}

TEST_CASE("lte/as-sec5/null algorithms are classified honestly and EIA0 is restricted")
{
    using namespace lte::security;

    UeAlgorithmCapabilities caps;
    caps.present = true;
    caps.ciphering = 0x0001;  // EEA0 only
    caps.integrity = 0x0003;  // EIA0 and EIA1

    auto config = Configuration({0, 1});
    config.nasIntegrityAlgorithm = 0;  // NAS is also null
    auto selection = SelectAsAlgorithms(caps, config, 5);
    CHECK(selection.ciphering == 0);
    CHECK(selection.cipheringNull);
    CHECK_FALSE(ProvidesProtection(AsAlgorithmDirection::CIPHERING, 0));
    CHECK(selection.Describe().find("no confidentiality") != std::string::npos);

    // EIA0 is refused when NAS integrity is not null, even though it is listed.
    auto nullFirst = Configuration({0, 2});
    nullFirst.nasIntegrityAlgorithm = 2;
    CHECK(RefusalOf<SelectionError, std::function<void()>, NoSelectionRefusal>(
              [&] { (void)SelectAsAlgorithms(caps, nullFirst, 5); }) ==
          SelectionError::EIA0_WITHOUT_NULL_NAS_INTEGRITY);

    // There is no automatic downgrade: a UE that supports EEA1/EIA1 only, and
    // a policy that offers EEA2/EIA2 only, is a refusal - not a silent
    // fallback to a null algorithm.
    UeAlgorithmCapabilities noNull;
    noNull.present = true;
    noNull.ciphering = 0x0002;
    noNull.integrity = 0x0002;
    CHECK(RefusalOf<SelectionError, std::function<void()>, NoSelectionRefusal>(
              [&] { (void)SelectAsAlgorithms(noNull, Configuration({2}), 5); }) ==
          SelectionError::NO_COMMON_ALGORITHM);
}

// --- RRC codec --------------------------------------------------------------

TEST_CASE("lte/as-sec5/security mode messages encode to the pinned TS 36.331 vectors")
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

    // Round trip through the same codec for every transaction identifier.
    for (uint8_t tx = 0; tx <= MaxRrcTransactionId; tx++)
    {
        command.transactionId = tx;
        auto bytes = EncodeSecurityModeCommand(command);
        SecurityModeCommandMessage decoded;
        REQUIRE(DecodeSecurityModeCommand(bytes.data(), bytes.size(), decoded));
        CHECK(decoded.transactionId == tx);
        CHECK(decoded.cipheringAlgorithm == 2);
        CHECK(decoded.integrityAlgorithm == 2);
    }

    // A wrong message type is not accepted as the requested one.
    auto failureBytes = EncodeSecurityModeFailure(failure);
    SecurityModeCompleteMessage wrong;
    CHECK_FALSE(DecodeSecurityModeComplete(failureBytes.data(), failureBytes.size(), wrong));

    // Truncated input does not decode.
    auto smc = EncodeSecurityModeCommand(command);
    SecurityModeCommandMessage truncated;
    CHECK_FALSE(DecodeSecurityModeCommand(smc.data(), 1, truncated));
}

// --- PDCP security ----------------------------------------------------------

TEST_CASE("lte/as-sec5/pdcp composes COUNT, bearer, direction and MAC-I as TS 33.401 defines")
{
    using namespace lte::security;

    // SRB1 uplink, EIA2, count 0, payload = SecurityModeComplete(0).
    auto entity = PdcpSecurityEntity::Create(Srb1Bearer, true, 2, 0, Key16(KRrcIntEia2Hex), Key16(KRrcEncEea2Hex));
    entity.ActivateIntegrity();
    auto pdu = entity.Protect(Hex("2800"));

    // Header 8000, payload 2800, MAC-I 6a5f5c9f. The MAC-I was computed with
    // OpenSSL from COUNT||BEARER||DIR||000000||PDU and the pinned KRRCint.
    CHECK(pdu == Hex("800028006a5f5c9f"));
    CHECK(entity.NextTxCount() == 1);

    // EEA2 only, same inputs: ciphertext 4c02 from OpenSSL AES-128-CTR with the
    // EEA2 IV (count, bearer, direction).
    auto cipherOnly = PdcpSecurityEntity::Create(Srb1Bearer, true, 0, 2, Key16(KRrcIntEia2Hex), Key16(KRrcEncEea2Hex));
    cipherOnly.ActivateCiphering();
    CHECK(cipherOnly.Protect(Hex("2800")) == Hex("80004c02"));
}

TEST_CASE("lte/as-sec5/pdcp round trips, and rejects tamper, replay and the wrong context")
{
    using namespace lte::security;

    auto tx = PdcpSecurityEntity::Create(Srb1Bearer, true, 2, 2, Key16(KRrcIntEia2Hex), Key16(KRrcEncEea2Hex));
    auto rx = PdcpSecurityEntity::Create(Srb1Bearer, true, 2, 2, Key16(KRrcIntEia2Hex), Key16(KRrcEncEea2Hex));
    tx.ActivateIntegrity();
    tx.ActivateCiphering();
    rx.ActivateIntegrity();
    rx.ActivateCiphering();

    const auto plain = Hex("2800112233445566");
    const auto pdu = tx.Protect(plain);
    CHECK(rx.Unprotect(pdu) == plain);

    // Tampering with the ciphertext is an integrity failure.
    auto tampered = pdu;
    tampered[3] ^= 0x01;
    CHECK(RefusalOf<PdcpSecurityError, std::function<void()>, NoPdcpRefusal>(
              [&] { (void)rx.Unprotect(tampered); }) == PdcpSecurityError::INTEGRITY_FAILURE);

    // Replaying an accepted PDU is refused.
    CHECK(RefusalOf<PdcpSecurityError, std::function<void()>, NoPdcpRefusal>(
              [&] { (void)rx.Unprotect(pdu); }) == PdcpSecurityError::REPLAY_DETECTED);

    // A different bearer or direction is a different context.
    auto otherBearer = PdcpSecurityEntity::Create(3, true, 2, 2, Key16(KRrcIntEia2Hex), Key16(KRrcEncEea2Hex));
    otherBearer.ActivateIntegrity();
    otherBearer.ActivateCiphering();
    CHECK(RefusalOf<PdcpSecurityError, std::function<void()>, NoPdcpRefusal>(
              [&] { (void)otherBearer.Unprotect(pdu); }) == PdcpSecurityError::INTEGRITY_FAILURE);

    auto downlink = PdcpSecurityEntity::Create(Srb1Bearer, false, 2, 2, Key16(KRrcIntEia2Hex), Key16(KRrcEncEea2Hex));
    downlink.ActivateIntegrity();
    downlink.ActivateCiphering();
    CHECK(RefusalOf<PdcpSecurityError, std::function<void()>, NoPdcpRefusal>(
              [&] { (void)downlink.Unprotect(pdu); }) == PdcpSecurityError::INTEGRITY_FAILURE);

    // A different key is a failure, not a silent pass.
    auto wrongKey = PdcpSecurityEntity::Create(Srb1Bearer, true, 2, 2, Key16(KRrcEncEea2Hex), Key16(KRrcEncEea2Hex));
    wrongKey.ActivateIntegrity();
    wrongKey.ActivateCiphering();
    CHECK(RefusalOf<PdcpSecurityError, std::function<void()>, NoPdcpRefusal>(
              [&] { (void)wrongKey.Unprotect(pdu); }) == PdcpSecurityError::INTEGRITY_FAILURE);
}

TEST_CASE("lte/as-sec5/pdcp COUNT rolls over the HFN without losing the sequence")
{
    using namespace lte::security;

    auto tx = PdcpSecurityEntity::Create(Srb1Bearer, true, 2, 0, Key16(KRrcIntEia2Hex), Key16(KRrcIntEia2Hex));
    auto rx = PdcpSecurityEntity::Create(Srb1Bearer, true, 2, 0, Key16(KRrcIntEia2Hex), Key16(KRrcIntEia2Hex));
    tx.ActivateIntegrity();
    rx.ActivateIntegrity();

    // 4096 PDUs take the SN from 0 to 4095; the 4097th reuses SN 0 with HFN 1.
    for (int i = 0; i < 4096; i++)
        CHECK(rx.Unprotect(tx.Protect(Hex("00"))) == Hex("00"));
    CHECK(rx.LastRxCount() == 4095);

    const auto next = tx.Protect(Hex("00"));
    CHECK(rx.Unprotect(next) == Hex("00"));
    CHECK(rx.LastRxCount() == 4096);
}

TEST_CASE("lte/as-sec5/ciphering is not applied before it is activated")
{
    using namespace lte::security;

    auto entity = PdcpSecurityEntity::Create(Srb1Bearer, true, 2, 2, Key16(KRrcIntEia2Hex), Key16(KRrcEncEea2Hex));
    entity.ActivateIntegrity();
    const auto pdu = entity.Protect(Hex("2800"));
    // The payload is still readable while ciphering is inactive.
    CHECK(std::vector<uint8_t>(pdu.begin() + 2, pdu.end() - 4) == Hex("2800"));
    CHECK_FALSE(entity.CipheringActive());
}

// --- The procedure ----------------------------------------------------------

TEST_CASE("lte/as-sec5/the security mode procedure completes with matching state on both sides")
{
    using namespace lte::security;

    auto enb = MakeContext(7);
    auto ue = MakeContext(7);

    auto procedure = EnbAsSecurityProcedure::Start(enb, 7, Capabilities(), Configuration({2, 1, 3}), 5, 0);
    CHECK(procedure.State() == AsSecurityState::COMMAND_PENDING);
    CHECK(procedure.Selection().ciphering == 2);
    CHECK(procedure.Selection().integrity == 2);
    CHECK_FALSE(procedure.CipheringActive());

    auto command = procedure.Command();
    // PDCP header + the pinned SecurityModeCommand + a 4-byte MAC-I.
    CHECK(command.size() == 2 + 3 + 4);
    CHECK(std::vector<uint8_t>(command.begin() + 2, command.end() - 4) == Hex("300220"));

    auto ueProcedure = UeAsSecurityProcedure::Listening(ue, 7);
    CHECK(ueProcedure.State() == AsSecurityState::KEY_PREPARED);

    auto complete = ueProcedure.OnCommand(command);
    CHECK(ueProcedure.State() == AsSecurityState::COMPLETE_PENDING);
    CHECK_FALSE(ueProcedure.CipheringActive());

    procedure.OnComplete(complete);
    CHECK(procedure.State() == AsSecurityState::ACTIVE);
    CHECK(procedure.CipheringActive());

    ueProcedure.ConfirmCompleteSent();
    CHECK(ueProcedure.State() == AsSecurityState::ACTIVE);
    CHECK(ueProcedure.CipheringActive());

    // Same KASME and COUNT on both sides produce the same KeNB and keys.
    CHECK(ue.ActiveKenb() == enb.ActiveKenb());
    CHECK(ue.ActiveNcc() == 0);
}

TEST_CASE("lte/as-sec5/a corrupted command fails closed on the UE and changes nothing")
{
    using namespace lte::security;

    auto enb = MakeContext(7);
    auto ue = MakeContext(7);
    auto procedure = EnbAsSecurityProcedure::Start(enb, 7, Capabilities(), Configuration({2}), 5, 1);

    auto command = procedure.Command();
    // Corrupt the MAC-I while leaving the message decodable: this is the case
    // the standard answers with SecurityModeFailure. A command too broken to
    // decode has no transaction identifier to answer with at all.
    command.back() ^= 0xFF;

    auto ueProcedure = UeAsSecurityProcedure::Listening(ue, 7);
    auto response = ueProcedure.OnCommand(command);

    CHECK(ueProcedure.State() == AsSecurityState::FAILED);
    CHECK_FALSE(ueProcedure.CipheringActive());
    // The UE answers with SecurityModeFailure under the protection state it
    // already had, which is none: the bytes are plain RRC, not a PDCP PDU.
    SecurityModeFailureMessage failure;
    CHECK(DecodeSecurityModeFailure(response.data(), response.size(), failure));
    CHECK(failure.transactionId == 1);

    // The eNB never leaves COMMAND_PENDING, so it may not mark the UE secure.
    CHECK(procedure.State() == AsSecurityState::COMMAND_PENDING);
    CHECK_FALSE(procedure.CipheringActive());
}

TEST_CASE("lte/as-sec5/the eNB rejects an unverifiable completion and stays failed")
{
    using namespace lte::security;

    auto enb = MakeContext(7);
    auto ue = MakeContext(7);
    auto procedure = EnbAsSecurityProcedure::Start(enb, 7, Capabilities(), Configuration({2}), 5, 0);

    auto ueProcedure = UeAsSecurityProcedure::Listening(ue, 7);
    auto complete = ueProcedure.OnCommand(procedure.Command());
    complete[complete.size() - 1] ^= 0xFF;

    CHECK(RefusalOf<ProcedureError, std::function<void()>, NoProcedureRefusal>(
              [&] { procedure.OnComplete(complete); }) == ProcedureError::INTEGRITY_FAILURE);
    CHECK(procedure.State() == AsSecurityState::FAILED);
    CHECK_FALSE(procedure.CipheringActive());

    // A second completion cannot revive a failed transaction.
    CHECK(RefusalOf<ProcedureError, std::function<void()>, NoProcedureRefusal>(
              [&] { procedure.OnComplete(complete); }) == ProcedureError::UNEXPECTED_MESSAGE);
}

TEST_CASE("lte/as-sec5/the procedure refuses a wrong transaction identifier and a foreign context")
{
    using namespace lte::security;

    auto enb = MakeContext(7);
    auto ue = MakeContext(7);
    auto procedure = EnbAsSecurityProcedure::Start(enb, 7, Capabilities(), Configuration({2}), 5, 0);

    auto ueProcedure = UeAsSecurityProcedure::Listening(ue, 7);
    (void)ueProcedure.OnCommand(procedure.Command());

    // A completion for transaction 1 arrives at a procedure started for 0. The
    // keys are the same, so integrity verifies; the transaction does not match.
    auto other = MakeContext(7);
    auto otherProcedure = EnbAsSecurityProcedure::Start(other, 7, Capabilities(), Configuration({2}), 5, 1);
    auto ueOtherContext = MakeContext(7);
    auto ueOther = UeAsSecurityProcedure::Listening(ueOtherContext, 7);
    auto foreign = ueOther.OnCommand(otherProcedure.Command());
    CHECK(RefusalOf<ProcedureError, std::function<void()>, NoProcedureRefusal>(
              [&] { procedure.OnComplete(foreign); }) == ProcedureError::TRANSACTION_MISMATCH);

    // A context owned by another UE cannot start a procedure for this UE.
    auto stranger = MakeContext(9);
    CHECK(RefusalOf<ProcedureError, std::function<void()>, NoProcedureRefusal>(
              [&] { (void)EnbAsSecurityProcedure::Start(stranger, 7, Capabilities(), Configuration({2}), 5, 0); }) ==
          ProcedureError::CONTEXT_MISMATCH);
}

TEST_CASE("lte/as-sec5/two UEs run independent procedures without sharing keys")
{
    using namespace lte::security;

    auto enbA = MakeContext(1, KasmeAHex);
    auto ueA = MakeContext(1, KasmeAHex);
    auto enbB = MakeContext(2, KasmeBHex);
    auto ueB = MakeContext(2, KasmeBHex);

    auto procA = EnbAsSecurityProcedure::Start(enbA, 1, Capabilities(), Configuration({2}), 5, 0);
    auto procB = EnbAsSecurityProcedure::Start(enbB, 2, Capabilities(), Configuration({2}), 5, 0);
    CHECK(procA.Selection().ciphering == 2);
    CHECK(procB.Selection().ciphering == 2);

    auto ueProcA = UeAsSecurityProcedure::Listening(ueA, 1);
    auto ueProcB = UeAsSecurityProcedure::Listening(ueB, 2);
    auto completeA = ueProcA.OnCommand(procA.Command());
    auto completeB = ueProcB.OnCommand(procB.Command());

    procA.OnComplete(completeA);
    procB.OnComplete(completeB);
    CHECK(procA.State() == AsSecurityState::ACTIVE);
    CHECK(procB.State() == AsSecurityState::ACTIVE);

    // UE A's completion must not satisfy a transaction for UE B: the keys
    // differ, so the MAC-I cannot verify.
    auto enbB2 = MakeContext(2, KasmeBHex);
    auto procB2 = EnbAsSecurityProcedure::Start(enbB2, 2, Capabilities(), Configuration({2}), 5, 0);
    CHECK(RefusalOf<ProcedureError, std::function<void()>, NoProcedureRefusal>(
              [&] { procB2.OnComplete(completeA); }) == ProcedureError::INTEGRITY_FAILURE);
    CHECK(procB2.State() == AsSecurityState::FAILED);

    // Different KASME means different KeNB and different keys.
    CHECK(enbA.ActiveKenb() != enbB.ActiveKenb());
    auto keysA = enbA.DeriveAccessKeys();
    auto keysB = enbB.DeriveAccessKeys();
    CHECK(keysA.kRrcInt != keysB.kRrcInt);
}

TEST_CASE("lte/as-sec5/the key hierarchy still matches the B4 vectors")
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
