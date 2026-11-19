//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

// Phase 18-F-B4: the LTE Access Stratum key hierarchy of TS 33.401 Annex A.
//
// The UE owns this context. It is created from the EPS NAS security context
// (KASME and the uplink NAS COUNT of the message that activated NAS security),
// holds the KeNB/NH/NCC chaining state, and stages handover candidates so a
// failed handover never replaces the active key.
//
// Nothing in this file executes a handover, activates RRC or PDCP security, or
// touches the live S1 path. It derives and validates keys; the live ingress
// keeps refusing to execute.
#pragma once

#include "kdf.hpp"

#include <array>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>

namespace lte::security
{

// Every refusal is typed. A caller that cannot name why it refused is a caller
// that will eventually refuse for the wrong reason.
enum class AsSecurityError : uint8_t
{
    NO_ACTIVE_CONTEXT,
    MISSING_KASME,
    INVALID_KASME_LENGTH,
    MISSING_UL_NAS_COUNT,
    INVALID_UL_NAS_COUNT,
    MISSING_NH,
    INVALID_NH_LENGTH,
    INVALID_NCC,
    INVALID_PCI,
    INVALID_EARFCN_DL,
    MISSING_TARGET_RADIO_CONFIG,
    INVALID_ALGORITHM_ID,
    UNSUPPORTED_ALGORITHM,
    STALE_NAS_GENERATION,
    STALE_NH,
    IMPOSSIBLE_NCC_TRANSITION,
    CROSS_UE_CONTEXT,
    HANDOVER_ALREADY_PENDING,
    NO_PENDING_HANDOVER,
};

const char *ToString(AsSecurityError error);

class AsSecurityException : public std::runtime_error
{
  public:
    explicit AsSecurityException(AsSecurityError reason);

    [[nodiscard]] AsSecurityError Reason() const noexcept
    {
        return reason_;
    }

  private:
    AsSecurityError reason_;
};

// TS 33.401 Annex A.7 algorithm type distinguishers.
enum class AsAlgorithmType : uint8_t
{
    RRC_ENCRYPTION = 0x03,
    RRC_INTEGRITY = 0x04,
    UP_ENCRYPTION = 0x05,
    UP_INTEGRITY = 0x06,
};

// The algorithm identities selected for this UE, as the four-bit identities of
// TS 33.401 7.2.4. The upper four bits of each identifier must be zero; the
// validation below enforces that rather than masking it away.
struct AsAlgorithmSet
{
    // True only when an actual AS security mode procedure selected these
    // identities. The LTE UE runtime in this repository has no RRC security
    // activation yet, so a runtime context is created with this false and
    // refuses to derive RRC/UP keys rather than copying the NAS selection into
    // a role the standard gives to a different procedure.
    bool negotiated{false};
    uint8_t rrcIntegrity{0};
    uint8_t rrcCiphering{0};
    uint8_t upCiphering{0};
    // Only a relay-capable profile has a UP integrity algorithm. The LTE UE
    // profile this simulator implements has none, so this stays empty and no
    // K_UPint is derived for it.
    std::optional<uint8_t> upIntegrity{};
};

struct AsKeys
{
    Key128 kRrcInt{};
    Key128 kRrcEnc{};
    Key128 kUpEnc{};
    std::optional<Key128> kUpInt{};

    // True when every key is all-zero. A caller must never treat such a set as
    // protection; it is reported so a test can prove nothing was derived.
    [[nodiscard]] bool IsAllZero() const;
};

// --- Pure derivation (TS 33.401 Annex A.3-A.7) -----------------------------

// Annex A.3: KeNB = KDF(KASME, FC 0x11, UL NAS COUNT).
[[nodiscard]] Key256 DeriveKenb(const Key256 &kasme, uint32_t ulNasCount);

// Annex A.4: NH = KDF(KASME, FC 0x12, SYNC). SYNC is the initial KeNB for the
// first NH, and the previous NH for every later one. NCC is deliberately not an
// input to this function.
[[nodiscard]] Key256 DeriveNh(const Key256 &kasme, const Key256 &syncInput);

// Annex A.5: KeNB* = KDF(base, FC 0x13, PCI, EARFCN-DL).
[[nodiscard]] Key256 DeriveKenbStar(const Key256 &baseKey, uint16_t pci, uint32_t earfcnDl);

// Annex A.7: algorithm key = the rightmost 128 bits of
// KDF(KeNB, FC 0x15, distinguisher, algorithm identity).
[[nodiscard]] Key128 DeriveAlgorithmKey(const Key256 &kenb, AsAlgorithmType type, uint8_t algorithmIdentity);

// --- Encoding and parameter validation -------------------------------------

// TS 33.401 A.5: EARFCN-DL is two bytes up to 65535 and three bytes above it.
[[nodiscard]] ByteString EncodeEarfcnDl(uint32_t earfcnDl);

void ValidateNcc(uint8_t ncc);
void ValidatePci(uint16_t pci);
void ValidateEarfcnDl(uint32_t earfcnDl);
void ValidateAlgorithmIdentity(uint8_t identity);
void ValidateSecurityKey(const ByteString &key, AsSecurityError lengthError);

// --- Target eNB side (TS 33.401 7.2.8) -------------------------------------

// The target cell's own radio parameters. This simulator's TargetContext does
// not carry a PCI or an EARFCN-DL today, so the flag is what an eNB sets when a
// verified configuration exists. A target that has none must not derive, and
// must not invent the missing values to make the call succeed.
struct TargetRadioConfig
{
    bool available{false};
    uint16_t pci{0};
    uint32_t earfcnDl{0};
};

// What a target eNB can build from the SecurityContext IE the MME sends plus
// its own verified cell configuration. It never sees KASME.
struct TargetDerivation
{
    Key256 kenbStar{};
    uint8_t ncc{0};
    uint16_t pci{0};
    uint32_t earfcnDl{0};
};

// Validates the received NH/NCC and derives KeNB* against the target's own
// radio parameters. Refuses on any invalid input; it never substitutes one.
[[nodiscard]] TargetDerivation DeriveTargetKenbStar(const ByteString &nextHopParameter, uint8_t nextHopChainingCount,
                                                    const TargetRadioConfig &radio);

// --- UE-owned AS security context ------------------------------------------

class AsSecurityContext
{
  public:
    AsSecurityContext() = default;
    ~AsSecurityContext();

    AsSecurityContext(const AsSecurityContext &) = delete;
    AsSecurityContext &operator=(const AsSecurityContext &) = delete;
    AsSecurityContext(AsSecurityContext &&other) noexcept;
    AsSecurityContext &operator=(AsSecurityContext &&other) noexcept;

    // Builds the initial context: KeNB from KASME and an explicit UL NAS COUNT,
    // NCC 0 for the initial KeNB, and the first NH already derived (the
    // standard permits eager or delayed derivation; this is the eager model).
    // Every refused input throws; a context is never returned half-built.
    static AsSecurityContext Create(uint32_t ownerUeId, const Key256 &kasme, uint32_t ulNasCount,
                                    uint64_t nasGeneration, const AsAlgorithmSet &algorithms);

    [[nodiscard]] bool IsActive() const noexcept
    {
        return active_;
    }
    [[nodiscard]] uint32_t OwnerUeId() const noexcept
    {
        return ownerUeId_;
    }
    [[nodiscard]] uint64_t NasGeneration() const noexcept
    {
        return nasGeneration_;
    }
    [[nodiscard]] uint64_t AsGeneration() const noexcept
    {
        return asGeneration_;
    }
    [[nodiscard]] uint8_t ActiveNcc() const;
    [[nodiscard]] uint64_t NhChainIndex() const;
    [[nodiscard]] bool HasPendingHandover() const noexcept
    {
        return pending_.has_value();
    }

    // Applies the AS algorithms an RRC SecurityModeCommand selected. Before this
    // the context owns the key hierarchy but no AS algorithm, and refuses to
    // derive RRC/UP keys; after it the keys exist for a procedure that has not
    // necessarily completed yet. Derivation is still not activation.
    void ApplyAsAlgorithms(const AsAlgorithmSet &algorithms);

    // The active KeNB. Returned by value because the context must stay the only
    // owner of the stored key.
    [[nodiscard]] Key256 ActiveKenb() const;
    [[nodiscard]] AsKeys DeriveAccessKeys() const;

    // Stages a handover candidate. Horizontal when the received NCC equals the
    // NCC of the active KeNB, vertical otherwise; a vertical derivation walks
    // the NH chain forward and refuses to reuse a position it has already
    // passed.
    void PrepareHandover(uint32_t ueId, uint64_t nasGeneration, uint8_t receivedNcc, uint16_t pci,
                         uint32_t earfcnDl);

    // Commits the staged candidate as the active key. The active key, its NCC
    // and the NH chain only move here, at a successful handover event.
    void CommitHandover();

    // Discards the staged candidate and leaves the active context untouched.
    void DiscardHandover() noexcept;

    // Replaces the whole context after a fresh EPS AKA or any change of KASME
    // or eKSI. Pending candidates are destroyed, and the old keys are wiped.
    void ReplaceNasSecurity(uint32_t ueId, const Key256 &kasme, uint32_t ulNasCount, uint64_t newNasGeneration);

    // Destroys all key material and returns the context to the inactive state.
    void Reset() noexcept;

    // A diagnostic string that names the lifecycle state and never contains key
    // material. Tests assert on this to prove the redaction.
    [[nodiscard]] std::string Describe() const;

  private:
    struct PendingHandover
    {
        Key256 kenbStar{};
        uint8_t ncc{0};
        Key256 nh{};
        uint64_t nhIndex{0};
        // Absolute chain position the KeNB takes on commit. A horizontal
        // handover keeps the current one; a vertical handover moves to the
        // matched NH position.
        uint64_t kenbIndex{0};
    };

    void Install(uint32_t ownerUeId, const Key256 &kasme, uint32_t ulNasCount, uint64_t nasGeneration,
                 const AsAlgorithmSet &algorithms);
    void Wipe() noexcept;
    static Key256 ChainNh(const Key256 &kasme, const Key256 &from, uint64_t fromIndex, uint64_t toIndex);

    bool active_{false};
    uint32_t ownerUeId_{0};
    uint64_t nasGeneration_{0};
    uint64_t asGeneration_{0};
    Key256 kasme_{};
    Key256 kenb_{};
    // Absolute chain position of the KeNB. 0 is the initial KeNB, which sits at
    // the virtual NH position of NCC 0; NH_1 is position 1.
    uint64_t kenbIndex_{0};
    Key256 nh_{};
    uint64_t nhIndex_{0};
    AsAlgorithmSet algorithms_{};
    std::optional<PendingHandover> pending_{};
};

} // namespace lte::security
