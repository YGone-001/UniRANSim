//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//

// Phase 18-F-B6-C: the eNB KeNB-only AS security context and its agreement with
// the UE context that derives the same KeNB from KASME.
#include <ext/doctest/doctest.h>

#include <lte/security/as_security_procedure.hpp>
#include <lte/security/enb_as_security_context.hpp>

#include <array>
#include <string>

using namespace lte::security;

namespace
{

constexpr uint32_t UeId = 7;
constexpr uint32_t UlNasCount = 11;
constexpr uint64_t NasGeneration = 3;
constexpr uint64_t S1Generation = 9;

Key256 Kasme()
{
    Key256 kasme{};
    for (size_t i = 0; i < kasme.size(); i++)
        kasme[i] = static_cast<uint8_t>(0x30 + i);
    return kasme;
}

UeAlgorithmCapabilities Capabilities()
{
    UeAlgorithmCapabilities capabilities;
    capabilities.present = true;
    capabilities.ciphering = 0x0007;   // EEA0, EEA1, EEA2
    capabilities.integrity = 0x0007;   // EIA0, EIA1, EIA2
    return capabilities;
}

AsAlgorithmConfiguration Configuration()
{
    AsAlgorithmConfiguration configuration;
    configuration.ciphering.ordered = {2, 1, 0};
    configuration.integrity.ordered = {2, 1, 0};
    configuration.ciphering.generation = 5;
    configuration.integrity.generation = 5;
    configuration.nasIntegrityAlgorithm = 2;
    return configuration;
}

AsAlgorithmSet SelectedAlgorithms()
{
    AsAlgorithmSet algorithms;
    algorithms.negotiated = true;
    algorithms.rrcIntegrity = 2;
    algorithms.rrcCiphering = 2;
    algorithms.upCiphering = 2;
    return algorithms;
}

} // namespace

TEST_CASE("lte/enb-as-context/the enb derives the same rrc keys from the mme kenb as the ue from kasme")
{
    // The MME's derivation, as S1AP delivers it.
    const Key256 mmeKenb = DeriveKenb(Kasme(), UlNasCount);

    auto ue = AsSecurityContext::Create(UeId, Kasme(), UlNasCount, NasGeneration, AsAlgorithmSet{});
    auto enb = EnbAsSecurityContext::Create(UeId, mmeKenb, S1Generation);

    // Receiving a key is not negotiating algorithms: neither side may derive
    // before the AS SecurityModeCommand selected one.
    CHECK_THROWS_AS((void)ue.DeriveAccessKeys(), AsSecurityException);
    CHECK_THROWS_AS((void)enb.DeriveAccessKeys(), AsSecurityException);

    ue.ApplyAsAlgorithms(SelectedAlgorithms());
    enb.ApplyAsAlgorithms(SelectedAlgorithms());

    CHECK(ue.ActiveKenb() == enb.ActiveKenb());
    const AsKeys ueKeys = ue.DeriveAccessKeys();
    const AsKeys enbKeys = enb.DeriveAccessKeys();
    CHECK(ueKeys.kRrcInt == enbKeys.kRrcInt);
    CHECK(ueKeys.kRrcEnc == enbKeys.kRrcEnc);
    CHECK(ueKeys.kUpEnc == enbKeys.kUpEnc);
    CHECK_FALSE(ueKeys.IsAllZero());
    CHECK_FALSE(enbKeys.IsAllZero());
}

TEST_CASE("lte/enb-as-context/the enb context cannot hold a kasme and refuses an empty key")
{
    Key256 zero{};
    CHECK_THROWS_AS(EnbAsSecurityContext::Create(UeId, zero, S1Generation), AsSecurityException);
    CHECK_THROWS_AS(EnbAsSecurityContext::Create(0, DeriveKenb(Kasme(), UlNasCount), S1Generation),
                    AsSecurityException);

    auto enb = EnbAsSecurityContext::Create(UeId, DeriveKenb(Kasme(), UlNasCount), S1Generation);
    CHECK(enb.IsActive());
    CHECK(enb.OwnerUeId() == UeId);
    CHECK(enb.S1Generation() == S1Generation);
    // The type has no KASME input and no NAS generation: the only key it accepts
    // is the KeNB the MME sends.
    CHECK(enb.Describe().find("kasme") == std::string::npos);
    CHECK(enb.Describe().find("active") != std::string::npos);
}

TEST_CASE("lte/enb-as-context/a replacement key is generation checked and clears the algorithms")
{
    auto enb = EnbAsSecurityContext::Create(UeId, DeriveKenb(Kasme(), UlNasCount), S1Generation);
    enb.ApplyAsAlgorithms(SelectedAlgorithms());
    const AsKeys before = enb.DeriveAccessKeys();

    // A newer Initial Context Setup carries a newer KeNB.
    Key256 nextKasme = Kasme();
    nextKasme[0] ^= 0xFF;
    const Key256 nextKenb = DeriveKenb(nextKasme, UlNasCount + 1);
    enb.ReplaceKenb(UeId, nextKenb, S1Generation + 1);
    CHECK(enb.S1Generation() == S1Generation + 1);
    // The negotiated algorithms belong to the old key.
    CHECK_FALSE(enb.Algorithms().negotiated);
    CHECK_THROWS_AS((void)enb.DeriveAccessKeys(), AsSecurityException);
    enb.ApplyAsAlgorithms(SelectedAlgorithms());
    CHECK(enb.DeriveAccessKeys().kRrcInt != before.kRrcInt);

    // An older generation cannot replace a newer context.
    CHECK_THROWS_AS(enb.ReplaceKenb(UeId, DeriveKenb(Kasme(), UlNasCount), S1Generation), AsSecurityException);
}

TEST_CASE("lte/enb-as-context/reset wipes the context")
{
    auto enb = EnbAsSecurityContext::Create(UeId, DeriveKenb(Kasme(), UlNasCount), S1Generation);
    enb.ApplyAsAlgorithms(SelectedAlgorithms());
    enb.Reset();
    CHECK_FALSE(enb.IsActive());
    CHECK_THROWS_AS((void)enb.DeriveAccessKeys(), AsSecurityException);
    CHECK_THROWS_AS(enb.ApplyAsAlgorithms(SelectedAlgorithms()), AsSecurityException);
}

TEST_CASE("lte/enb-as-context/the security mode procedure runs over an enb-owned kenb context")
{
    const Key256 mmeKenb = DeriveKenb(Kasme(), UlNasCount);
    auto ue = AsSecurityContext::Create(UeId, Kasme(), UlNasCount, NasGeneration, AsAlgorithmSet{});
    auto enb = EnbAsSecurityContext::Create(UeId, mmeKenb, S1Generation);

    auto procedure = EnbAsSecurityProcedure::Start(enb, UeId, Capabilities(), Configuration(), 5, 0);
    CHECK(procedure.State() == AsSecurityState::COMMAND_PENDING);
    CHECK(procedure.Selection().ciphering == 2);
    CHECK(procedure.Selection().integrity == 2);
    CHECK_FALSE(procedure.CipheringActive());

    auto ueProcedure = UeAsSecurityProcedure::Listening(ue, UeId);
    const auto complete = ueProcedure.OnCommand(procedure.Command());
    CHECK(ueProcedure.State() == AsSecurityState::COMPLETE_PENDING);
    CHECK_FALSE(ueProcedure.CipheringActive());

    procedure.OnComplete(complete);
    CHECK(procedure.State() == AsSecurityState::ACTIVE);
    CHECK(procedure.CipheringActive());

    ueProcedure.ConfirmCompleteSent();
    CHECK(ueProcedure.State() == AsSecurityState::ACTIVE);
    CHECK(ueProcedure.CipheringActive());

    // Both sides hold the same KeNB and derive the same RRC keys, even though
    // only one of them ever saw KASME.
    CHECK(enb.ActiveKenb() == ue.ActiveKenb());
    CHECK(enb.DeriveAccessKeys().kRrcInt == ue.DeriveAccessKeys().kRrcInt);
    CHECK(enb.DeriveAccessKeys().kRrcEnc == ue.DeriveAccessKeys().kRrcEnc);
}
