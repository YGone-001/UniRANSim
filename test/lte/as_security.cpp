//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

// Phase 18-F-B4 LTE AS key-hierarchy tests.
//
// Every expected value in this file was produced by an independent reference
// implementation (Python hmac/hashlib, TS 33.401 Annex A) that shares no code
// with the implementation under test. The inputs are synthetic and test-only;
// no real subscriber key is used.
#include <ext/doctest/doctest.h>

#include <lte/security/as_security.hpp>
#include <lte/security/kdf.hpp>

#include <algorithm>
#include <array>
#include <cctype>
#include <functional>
#include <string>
#include <vector>

namespace
{

std::vector<uint8_t> Hex(const std::string &text)
{
    std::vector<uint8_t> out;
    out.reserve(text.size() / 2);
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

lte::security::Key128 Key16Of(const std::string &text)
{
    auto bytes = Hex(text);
    lte::security::Key128 out{};
    REQUIRE(bytes.size() == out.size());
    std::copy(bytes.begin(), bytes.end(), out.begin());
    return out;
}

// Sentinel that no refusal code can take, so an unexpected success fails the
// check with a readable value instead of passing silently.
constexpr lte::security::AsSecurityError NoRefusal = static_cast<lte::security::AsSecurityError>(0xFF);

lte::security::AsSecurityError RefusalOf(const std::function<void()> &action)
{
    try
    {
        action();
    }
    catch (const lte::security::AsSecurityException &error)
    {
        return error.Reason();
    }
    return NoRefusal;
}

// --- Synthetic fixtures, independent reference (see gen_vectors.py) ---------
const std::string KasmeAHex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const std::string KasmeBHex = "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f";

const char *KenbCount0Hex = "e6267359de012d9bda173d1b6fae57dec0e04e01cfcf57cb33a7573f142b8b95";
const char *KenbCountAltHex = "b51e8232ff0734bcfd5dda1674216d5c599a183eed0045f592ed17a85f4fdf1a";
const char *Nh1Hex = "09aba1730b0aaeee84feac6bc03f66b9aa90d45309b719114a90be777b24b74c";
const char *Nh2Hex = "9b6efffa0cccff877e89572bfcaa77a62fe98e062bbf11dbd7658136df926c93";
const char *Nh3Hex = "26c1c16de6a22132c3285a31fcc60530025596c2eaa6660d875f9b19a435acae";
const char *KenbStarHorizontalHex = "00b7ff856e4940b75023c61aa3f817285f2149080ce0e4908983253c591fe8f3";
const char *KenbStarVerticalHex = "7860f6d80bed16ea2e98e2da107df855f74f6f712139c523d73eb965d1575ae4";
const char *KenbStarThreeByteHex = "e332450303cbcaf8dbc09dff12ed0785c4a07d3e57352880f94fe402432dbb85";
const char *KenbStarHorizontal2Hex = "07cfaed6c999a541176ed3a997e8e4c3d62a6bee79c1336364204e063ef49d18";
const char *KenbStarNh2Hex = "f31fa434136a4b3beca58cc2bb7618f526f423b841d53b30de2231258b17238a";
const char *KenbStarNh10Hex = "940d47c65cf5684271f30b7a6356cc2c49fbfa25602ba233a024bb70fba8f1ef";
const char *KRrcIntEia2Hex = "2f6e105d4dda7c910c988fcadc7b4844";
const char *KRrcEncEea2Hex = "ae14c26e3ba014f8e4279841fb8ade28";
const char *KUpEncEea1Hex = "34213661a0f7b726bf64faa986f6e280";
const char *KUpIntEia1Hex = "122c75d3c14f1a758b5d1d9800af796a";
const char *KdfTwoParamHex = "706524101ad173f44057a3a076bf5d4b2c012e290cefbaeeeea970abf55d9458";

constexpr uint16_t TargetPci = 317;
constexpr uint32_t TargetEarfcn2 = 1650;
constexpr uint32_t TargetEarfcn3 = 100000;

lte::security::AsAlgorithmSet Algorithms()
{
    lte::security::AsAlgorithmSet set;
    set.negotiated = true;
    set.rrcIntegrity = 2;  // EIA2
    set.rrcCiphering = 2;  // EEA2
    set.upCiphering = 1;   // EEA1
    return set;
}

lte::security::AsSecurityContext MakeContext(uint32_t ueId = 7, uint32_t count = 0, uint64_t nasGeneration = 1)
{
    return lte::security::AsSecurityContext::Create(ueId, Key(KasmeAHex), count, nasGeneration, Algorithms());
}

} // namespace

TEST_CASE("lte/as-sec/kdf-encoding")
{
    using namespace lte::security;

    const ByteString count0{0x00, 0x00, 0x00, 0x00};
    CHECK(EncodeKdfInput(0x11, {count0}) == ByteString({0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04}));

    const ByteString pci{0x01, 0x3D};
    const ByteString earfcn{0x06, 0x72};
    CHECK(EncodeKdfInput(0x13, {pci, earfcn}) ==
          ByteString({0x13, 0x01, 0x3D, 0x00, 0x02, 0x06, 0x72, 0x00, 0x02}));

    // Three-byte EARFCN keeps its own length field.
    CHECK(EncodeKdfInput(0x13, {pci, EncodeEarfcnDl(70000)}) ==
          ByteString({0x13, 0x01, 0x3D, 0x00, 0x02, 0x01, 0x11, 0x70, 0x00, 0x03}));

    // The generic KDF vector exercises the same encoding through the hash.
    CHECK(Kdf(Key(KasmeBHex), 0x42, {ByteString{0x01, 0x02}, ByteString{0xAA}}) == Key(KdfTwoParamHex));
}

TEST_CASE("lte/as-sec/kenb")
{
    const auto kasme = Key(KasmeAHex);
    CHECK(lte::security::DeriveKenb(kasme, 0) == Key(KenbCount0Hex));
    CHECK(lte::security::DeriveKenb(kasme, 0x00ABCDEF) == Key(KenbCountAltHex));

    // The count is an input: a different one yields a different key.
    CHECK(lte::security::DeriveKenb(kasme, 0) != lte::security::DeriveKenb(kasme, 1));
    // The key is an input: the same count under another KASME differs.
    CHECK(lte::security::DeriveKenb(kasme, 0) != lte::security::DeriveKenb(Key(KasmeBHex), 0));
}

TEST_CASE("lte/as-sec/nh-chain")
{
    const auto kasme = Key(KasmeAHex);
    const auto kenb = Key(KenbCount0Hex);
    const auto nh1 = lte::security::DeriveNh(kasme, kenb);
    CHECK(nh1 == Key(Nh1Hex));
    const auto nh2 = lte::security::DeriveNh(kasme, nh1);
    CHECK(nh2 == Key(Nh2Hex));
    CHECK(lte::security::DeriveNh(kasme, nh2) == Key(Nh3Hex));

    // NCC is not an input to the NH KDF: the same sync input always yields the
    // same NH, whatever chaining index it is being used at.
    CHECK(lte::security::DeriveNh(kasme, nh1) == nh2);
}

TEST_CASE("lte/as-sec/kenb-star")
{
    const auto kenb = Key(KenbCount0Hex);
    CHECK(lte::security::DeriveKenbStar(kenb, TargetPci, TargetEarfcn2) == Key(KenbStarHorizontalHex));

    const auto nh1 = Key(Nh1Hex);
    CHECK(lte::security::DeriveKenbStar(nh1, TargetPci, TargetEarfcn2) == Key(KenbStarVerticalHex));

    const auto nh2 = Key(Nh2Hex);
    CHECK(lte::security::DeriveKenbStar(nh2, TargetPci, TargetEarfcn3) == Key(KenbStarThreeByteHex));

    // PCI and EARFCN-DL both move the result.
    CHECK(lte::security::DeriveKenbStar(nh1, TargetPci + 1, TargetEarfcn2) != Key(KenbStarVerticalHex));
    CHECK(lte::security::DeriveKenbStar(nh1, TargetPci, TargetEarfcn2 + 1) != Key(KenbStarVerticalHex));
}

TEST_CASE("lte/as-sec/earfcn-encoding")
{
    using namespace lte::security;
    CHECK(EncodeEarfcnDl(0) == ByteString({0x00, 0x00}));
    CHECK(EncodeEarfcnDl(65535) == ByteString({0xFF, 0xFF}));
    CHECK(EncodeEarfcnDl(65536) == ByteString({0x01, 0x00, 0x00}));
    CHECK(EncodeEarfcnDl(262143) == ByteString({0x03, 0xFF, 0xFF}));

    CHECK(RefusalOf([] { (void)EncodeEarfcnDl(262144); }) == AsSecurityError::INVALID_EARFCN_DL);
    CHECK(RefusalOf([] { ValidatePci(504); }) == AsSecurityError::INVALID_PCI);
    CHECK(RefusalOf([] { ValidateNcc(8); }) == AsSecurityError::INVALID_NCC);
    CHECK(RefusalOf([] { ValidateAlgorithmIdentity(16); }) == AsSecurityError::INVALID_ALGORITHM_ID);
}

TEST_CASE("lte/as-sec/algorithm-keys")
{
    using namespace lte::security;
    const auto kenb = Key(KenbCount0Hex);

    CHECK(DeriveAlgorithmKey(kenb, AsAlgorithmType::RRC_INTEGRITY, 2) == Key16Of(KRrcIntEia2Hex));
    CHECK(DeriveAlgorithmKey(kenb, AsAlgorithmType::RRC_ENCRYPTION, 2) == Key16Of(KRrcEncEea2Hex));
    CHECK(DeriveAlgorithmKey(kenb, AsAlgorithmType::UP_ENCRYPTION, 1) == Key16Of(KUpEncEea1Hex));
    CHECK(DeriveAlgorithmKey(kenb, AsAlgorithmType::UP_INTEGRITY, 1) == Key16Of(KUpIntEia1Hex));

    // The distinguishers are distinct: the same algorithm identity under
    // different types yields different keys.
    CHECK(DeriveAlgorithmKey(kenb, AsAlgorithmType::RRC_INTEGRITY, 2) !=
          DeriveAlgorithmKey(kenb, AsAlgorithmType::RRC_ENCRYPTION, 2));

    // A context with no UP integrity algorithm derives no K_UPint.
    auto context = MakeContext();
    auto keys = context.DeriveAccessKeys();
    CHECK(keys.kRrcInt == Key16Of(KRrcIntEia2Hex));
    CHECK(keys.kRrcEnc == Key16Of(KRrcEncEea2Hex));
    CHECK(keys.kUpEnc == Key16Of(KUpEncEea1Hex));
    CHECK_FALSE(keys.kUpInt.has_value());
    CHECK_FALSE(keys.IsAllZero());
}

TEST_CASE("lte/as-sec/algorithms-not-negotiated")
{
    using namespace lte::security;

    // The runtime has no AS security mode procedure, so it cannot name a
    // selected AS algorithm. The key hierarchy still exists; the RRC/UP keys
    // do not, and asking for them is refused rather than guessed.
    auto algorithms = Algorithms();
    algorithms.negotiated = false;
    auto context = AsSecurityContext::Create(7, Key(KasmeAHex), 0, 1, algorithms);

    CHECK(context.IsActive());
    CHECK(context.ActiveKenb() == Key(KenbCount0Hex));
    CHECK(context.ActiveNcc() == 0);
    CHECK(RefusalOf([&] { (void)context.DeriveAccessKeys(); }) == AsSecurityError::UNSUPPORTED_ALGORITHM);

    // Handover derivation does not depend on the algorithm set and still works.
    context.PrepareHandover(7, 1, 1, TargetPci, TargetEarfcn2);
    context.CommitHandover();
    CHECK(context.ActiveKenb() == Key(KenbStarVerticalHex));
}

TEST_CASE("lte/as-sec/ncc-lifecycle")
{
    using namespace lte::security;

    auto context = MakeContext();
    CHECK(context.IsActive());
    CHECK(context.ActiveNcc() == 0);
    CHECK(context.NhChainIndex() == 1);

    // Vertical handover to NCC 1 uses the already derived NH_1.
    context.PrepareHandover(7, 1, 1, TargetPci, TargetEarfcn2);
    CHECK(context.HasPendingHandover());
    CHECK(context.ActiveKenb() == Key(KenbCount0Hex));  // not committed yet
    context.CommitHandover();
    CHECK_FALSE(context.HasPendingHandover());
    CHECK(context.ActiveNcc() == 1);
    CHECK(context.ActiveKenb() == Key(KenbStarVerticalHex));
    CHECK(context.AsGeneration() == 2);

    // Horizontal handover: same NCC, derived from the active KeNB.
    context.PrepareHandover(7, 1, 1, TargetPci, TargetEarfcn2);
    context.CommitHandover();
    CHECK(context.ActiveNcc() == 1);
    CHECK(context.ActiveKenb() == Key(KenbStarHorizontal2Hex));
    CHECK(context.NhChainIndex() == 1);  // horizontal does not move the chain

    // A discarded candidate leaves the active key untouched.
    const auto active = context.ActiveKenb();
    const auto generation = context.AsGeneration();
    context.PrepareHandover(7, 1, 3, TargetPci, TargetEarfcn2);
    context.DiscardHandover();
    CHECK(context.ActiveKenb() == active);
    CHECK(context.AsGeneration() == generation);
    CHECK(context.ActiveNcc() == 1);
}

TEST_CASE("lte/as-sec/ncc-wrap-around")
{
    using namespace lte::security;

    auto context = MakeContext();
    // Eight successive vertical handovers walk NCC 1..7, then wrap to 0.
    std::vector<uint8_t> seen;
    for (int step = 1; step <= 8; step++)
    {
        const uint8_t ncc = static_cast<uint8_t>(step & 0x7);
        context.PrepareHandover(7, 1, ncc, TargetPci, TargetEarfcn2);
        context.CommitHandover();
        seen.push_back(context.ActiveNcc());
        CHECK(context.NhChainIndex() == static_cast<uint64_t>(step));
    }
    CHECK(seen == std::vector<uint8_t>({1, 2, 3, 4, 5, 6, 7, 0}));

    // The 3-bit NCC repeats at position 8, but the key does not: the chain
    // position, not the three-bit label, decides the key.
    CHECK(context.ActiveKenb() != Key(KenbStarVerticalHex));
    CHECK(context.NhChainIndex() == 8);

    // A request that names a position already passed walks forward to the next
    // occurrence, never backwards to the stale NH. From position 8 (NCC 0) a
    // request for NCC 2 lands on position 10, not position 2.
    context.PrepareHandover(7, 1, 2, TargetPci, TargetEarfcn2);
    context.CommitHandover();
    CHECK(context.NhChainIndex() == 10);
    CHECK(context.ActiveKenb() == Key(KenbStarNh10Hex));
    CHECK(context.ActiveKenb() != Key(KenbStarNh2Hex));
}

TEST_CASE("lte/as-sec/ue-target-equality")
{
    using namespace lte::security;

    // The UE walks its own NH chain; the target reads the NH and NCC the MME
    // sends. Neither shares a precomputed KeNB*.
    auto ue = MakeContext();
    ue.PrepareHandover(7, 1, 1, TargetPci, TargetEarfcn2);
    ue.CommitHandover();

    TargetRadioConfig radio;
    radio.available = true;
    radio.pci = TargetPci;
    radio.earfcnDl = TargetEarfcn2;
    const auto target = DeriveTargetKenbStar(Hex(Nh1Hex), 1, radio);

    CHECK(target.kenbStar == ue.ActiveKenb());
    CHECK(target.ncc == ue.ActiveNcc());

    // The algorithm keys follow the committed KeNB on both sides.
    const auto ueKeys = ue.DeriveAccessKeys();
    CHECK(ueKeys.kRrcInt == DeriveAlgorithmKey(target.kenbStar, AsAlgorithmType::RRC_INTEGRITY, 2));
}

TEST_CASE("lte/as-sec/negative--inputs")
{
    using namespace lte::security;
    const auto kasme = Key(KasmeAHex);
    const auto kenb = Key(KenbCount0Hex);

    // Missing and malformed KASME.
    CHECK(RefusalOf([] { (void)DeriveKenb(Key256{}, 0); }) == AsSecurityError::MISSING_KASME);
    CHECK(RefusalOf([&] { AsSecurityContext::Create(1, Key256{}, 0, 1, Algorithms()); }) ==
          AsSecurityError::MISSING_KASME);

    // The COUNT must be a real 24-bit value.
    CHECK(RefusalOf([&] { (void)DeriveKenb(kasme, 0x01000000U); }) == AsSecurityError::INVALID_UL_NAS_COUNT);
    CHECK(RefusalOf([&] { AsSecurityContext::Create(1, kasme, 0x01000000U, 1, Algorithms()); }) ==
          AsSecurityError::INVALID_UL_NAS_COUNT);

    // NH length and presence.
    CHECK(RefusalOf([&] { ValidateSecurityKey(ByteString{}, AsSecurityError::INVALID_NH_LENGTH); }) ==
          AsSecurityError::MISSING_NH);
    CHECK(RefusalOf([&] { ValidateSecurityKey(Hex("00112233"), AsSecurityError::INVALID_NH_LENGTH); }) ==
          AsSecurityError::INVALID_NH_LENGTH);

    TargetRadioConfig radio;
    radio.available = true;
    radio.pci = TargetPci;
    radio.earfcnDl = TargetEarfcn2;
    CHECK(RefusalOf([&] { (void)DeriveTargetKenbStar(Hex("00112233"), 1, radio); }) ==
          AsSecurityError::INVALID_NH_LENGTH);
    CHECK(RefusalOf([&] { (void)DeriveTargetKenbStar(Hex(Nh1Hex), 9, radio); }) == AsSecurityError::INVALID_NCC);

    // No verified target radio configuration means no derivation.
    TargetRadioConfig unavailable;
    CHECK(RefusalOf([&] { (void)DeriveTargetKenbStar(Hex(Nh1Hex), 1, unavailable); }) ==
          AsSecurityError::MISSING_TARGET_RADIO_CONFIG);

    // Algorithm identity is a four-bit field.
    CHECK(RefusalOf([&] { (void)DeriveAlgorithmKey(kenb, AsAlgorithmType::RRC_INTEGRITY, 16); }) ==
          AsSecurityError::INVALID_ALGORITHM_ID);
    auto malformed = Algorithms();
    malformed.rrcIntegrity = 16;
    CHECK(RefusalOf([&] { AsSecurityContext::Create(1, kasme, 0, 1, malformed); }) ==
          AsSecurityError::INVALID_ALGORITHM_ID);
}

TEST_CASE("lte/as-sec/negative--lifecycle")
{
    using namespace lte::security;

    auto context = MakeContext();

    // Cross-UE use of one UE's context.
    CHECK(RefusalOf([&] { context.PrepareHandover(8, 1, 1, TargetPci, TargetEarfcn2); }) ==
          AsSecurityError::CROSS_UE_CONTEXT);

    // A stale NAS generation.
    CHECK(RefusalOf([&] { context.PrepareHandover(7, 99, 1, TargetPci, TargetEarfcn2); }) ==
          AsSecurityError::STALE_NAS_GENERATION);

    // Invalid target parameters.
    CHECK(RefusalOf([&] { context.PrepareHandover(7, 1, 1, 504, TargetEarfcn2); }) == AsSecurityError::INVALID_PCI);
    CHECK(RefusalOf([&] { context.PrepareHandover(7, 1, 8, TargetPci, TargetEarfcn2); }) == AsSecurityError::INVALID_NCC);
    CHECK(RefusalOf([&] { context.PrepareHandover(7, 1, 1, TargetPci, 262144); }) == AsSecurityError::INVALID_EARFCN_DL);

    // A rejected preparation leaves no partial state.
    CHECK_FALSE(context.HasPendingHandover());
    CHECK(context.ActiveNcc() == 0);

    // One candidate at a time, and a commit needs a candidate.
    CHECK(RefusalOf([&] { context.CommitHandover(); }) == AsSecurityError::NO_PENDING_HANDOVER);
    context.PrepareHandover(7, 1, 1, TargetPci, TargetEarfcn2);
    CHECK(RefusalOf([&] { context.PrepareHandover(7, 1, 2, TargetPci, TargetEarfcn2); }) ==
          AsSecurityError::HANDOVER_ALREADY_PENDING);
    context.CommitHandover();
    CHECK(RefusalOf([&] { context.CommitHandover(); }) == AsSecurityError::NO_PENDING_HANDOVER);

    // A failed (discarded) handover followed by another discard is benign and
    // the active context is unchanged.
    const auto active = context.ActiveKenb();
    context.DiscardHandover();
    CHECK(context.ActiveKenb() == active);
}

TEST_CASE("lte/as-sec/replacement-and-isolation")
{
    using namespace lte::security;

    auto first = MakeContext(1, 0, 1);
    auto second = MakeContext(2, 0, 1);
    CHECK(first.ActiveKenb() == second.ActiveKenb());  // same inputs, same key

    // Advancing one context does not move the other.
    first.PrepareHandover(1, 1, 1, TargetPci, TargetEarfcn2);
    first.CommitHandover();
    CHECK(second.ActiveNcc() == 0);
    CHECK(second.ActiveKenb() == Key(KenbCount0Hex));

    // A pending candidate is destroyed by a fresh NAS security context, and
    // the stale generation can no longer commit it.
    first.PrepareHandover(1, 1, 3, TargetPci, TargetEarfcn2);
    CHECK(first.HasPendingHandover());
    first.ReplaceNasSecurity(1, Key(KasmeBHex), 0, 2);
    CHECK_FALSE(first.HasPendingHandover());
    CHECK(first.ActiveNcc() == 0);
    CHECK(first.NhChainIndex() == 1);
    CHECK(first.ActiveKenb() != Key(KenbCount0Hex));  // new KASME, new key
    CHECK(RefusalOf([&] { first.PrepareHandover(1, 1, 1, TargetPci, TargetEarfcn2); }) ==
          AsSecurityError::STALE_NAS_GENERATION);

    // A generation cannot go backwards.
    CHECK(RefusalOf([&] { first.ReplaceNasSecurity(1, Key(KasmeAHex), 0, 2); }) ==
          AsSecurityError::STALE_NAS_GENERATION);

    // Another UE cannot replace this one's context.
    CHECK(RefusalOf([&] { first.ReplaceNasSecurity(2, Key(KasmeAHex), 0, 3); }) ==
          AsSecurityError::CROSS_UE_CONTEXT);
}

TEST_CASE("lte/as-sec/secret-handling")
{
    using namespace lte::security;

    auto context = MakeContext();
    const auto summary = context.Describe();
    CHECK(summary.find("ncc=0") != std::string::npos);

    const auto lower = [](std::string text) {
        std::transform(text.begin(), text.end(), text.begin(), [](unsigned char c) { return std::tolower(c); });
        return text;
    };
    const auto haystack = lower(summary);
    CHECK(haystack.find(lower(KenbCount0Hex)) == std::string::npos);
    CHECK(haystack.find(lower(KasmeAHex)) == std::string::npos);
    CHECK(summary.find("kenb") == std::string::npos);

    // A reset context owns nothing and refuses to hand out a key.
    context.Reset();
    CHECK_FALSE(context.IsActive());
    CHECK(RefusalOf([&] { (void)context.ActiveKenb(); }) == AsSecurityError::NO_ACTIVE_CONTEXT);
    CHECK(RefusalOf([&] { context.PrepareHandover(7, 1, 1, TargetPci, TargetEarfcn2); }) ==
          AsSecurityError::NO_ACTIVE_CONTEXT);

    // Moving a context transfers ownership and leaves the source inactive.
    auto moved = MakeContext();
    auto target = std::move(moved);
    CHECK(target.IsActive());
    CHECK_FALSE(moved.IsActive());
    CHECK(target.ActiveKenb() == Key(KenbCount0Hex));
}