//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#include "as_security.hpp"

#include <algorithm>
#include <cstring>
#include <sstream>

namespace lte::security
{
namespace
{

// 24-bit NAS COUNT, TS 24.301 4.4.3.1.
constexpr uint32_t MaxNasCount = 0xFFFFFFU;
constexpr uint16_t MaxPci = 503;
constexpr uint32_t MaxEarfcnDl = 262143;
constexpr uint8_t MaxNcc = 7;
constexpr uint8_t MaxAlgorithmIdentity = 15;

bool AllZero(const uint8_t *data, size_t length)
{
    uint8_t accumulator = 0;
    for (size_t i = 0; i < length; i++)
        accumulator |= data[i];
    return accumulator == 0;
}

// Wipes a buffer in a way the optimiser may not remove. The pointer is volatile
// so each store is observable; this is the usual compiler-resistant clear.
void SecureZero(uint8_t *data, size_t length) noexcept
{
    volatile uint8_t *cursor = data;
    while (length--)
        *cursor++ = 0;
}

template <size_t N> void SecureZero(std::array<uint8_t, N> &value) noexcept
{
    SecureZero(value.data(), value.size());
}

[[noreturn]] void Fail(AsSecurityError reason)
{
    throw AsSecurityException(reason);
}

} // namespace

const char *ToString(AsSecurityError error)
{
    switch (error)
    {
    case AsSecurityError::NO_ACTIVE_CONTEXT:
        return "NO_ACTIVE_CONTEXT";
    case AsSecurityError::MISSING_KASME:
        return "MISSING_KASME";
    case AsSecurityError::INVALID_KASME_LENGTH:
        return "INVALID_KASME_LENGTH";
    case AsSecurityError::MISSING_UL_NAS_COUNT:
        return "MISSING_UL_NAS_COUNT";
    case AsSecurityError::INVALID_UL_NAS_COUNT:
        return "INVALID_UL_NAS_COUNT";
    case AsSecurityError::MISSING_NH:
        return "MISSING_NH";
    case AsSecurityError::INVALID_NH_LENGTH:
        return "INVALID_NH_LENGTH";
    case AsSecurityError::INVALID_NCC:
        return "INVALID_NCC";
    case AsSecurityError::INVALID_PCI:
        return "INVALID_PCI";
    case AsSecurityError::INVALID_EARFCN_DL:
        return "INVALID_EARFCN_DL";
    case AsSecurityError::MISSING_TARGET_RADIO_CONFIG:
        return "MISSING_TARGET_RADIO_CONFIG";
    case AsSecurityError::INVALID_ALGORITHM_ID:
        return "INVALID_ALGORITHM_ID";
    case AsSecurityError::UNSUPPORTED_ALGORITHM:
        return "UNSUPPORTED_ALGORITHM";
    case AsSecurityError::STALE_NAS_GENERATION:
        return "STALE_NAS_GENERATION";
    case AsSecurityError::STALE_NH:
        return "STALE_NH";
    case AsSecurityError::IMPOSSIBLE_NCC_TRANSITION:
        return "IMPOSSIBLE_NCC_TRANSITION";
    case AsSecurityError::CROSS_UE_CONTEXT:
        return "CROSS_UE_CONTEXT";
    case AsSecurityError::HANDOVER_ALREADY_PENDING:
        return "HANDOVER_ALREADY_PENDING";
    case AsSecurityError::NO_PENDING_HANDOVER:
        return "NO_PENDING_HANDOVER";
    }
    return "UNKNOWN";
}

AsSecurityException::AsSecurityException(AsSecurityError reason)
    : std::runtime_error(std::string("AS security refusal: ") + ToString(reason)), reason_(reason)
{
}

bool AsKeys::IsAllZero() const
{
    return AllZero(kRrcInt.data(), kRrcInt.size()) && AllZero(kRrcEnc.data(), kRrcEnc.size()) &&
           AllZero(kUpEnc.data(), kUpEnc.size()) && (!kUpInt.has_value() || AllZero(kUpInt->data(), kUpInt->size()));
}

void ValidateNcc(uint8_t ncc)
{
    if (ncc > MaxNcc)
        Fail(AsSecurityError::INVALID_NCC);
}

void ValidatePci(uint16_t pci)
{
    if (pci > MaxPci)
        Fail(AsSecurityError::INVALID_PCI);
}

void ValidateEarfcnDl(uint32_t earfcnDl)
{
    if (earfcnDl > MaxEarfcnDl)
        Fail(AsSecurityError::INVALID_EARFCN_DL);
}

void ValidateAlgorithmIdentity(uint8_t identity)
{
    // TS 33.401 7.2.4: the identity occupies the four least significant bits;
    // the reserved upper bits are zero. A value above 15 has them set.
    if (identity > MaxAlgorithmIdentity)
        Fail(AsSecurityError::INVALID_ALGORITHM_ID);
}

ByteString EncodeEarfcnDl(uint32_t earfcnDl)
{
    ValidateEarfcnDl(earfcnDl);
    // TS 33.401 A.5 backward compatibility: two bytes up to 65535, three above.
    if (earfcnDl > 0xFFFFU)
        return ByteString{static_cast<uint8_t>((earfcnDl >> 16U) & 0xFFU), static_cast<uint8_t>((earfcnDl >> 8U) & 0xFFU),
                          static_cast<uint8_t>(earfcnDl & 0xFFU)};
    return ByteString{static_cast<uint8_t>((earfcnDl >> 8U) & 0xFFU), static_cast<uint8_t>(earfcnDl & 0xFFU)};
}

void ValidateSecurityKey(const ByteString &key, AsSecurityError lengthError)
{
    if (key.empty())
        Fail(AsSecurityError::MISSING_NH);
    if (key.size() != 32)
        Fail(lengthError);
    if (AllZero(key.data(), key.size()))
        Fail(AsSecurityError::MISSING_NH);
}

Key256 DeriveKenb(const Key256 &kasme, uint32_t ulNasCount)
{
    if (AllZero(kasme.data(), kasme.size()))
        Fail(AsSecurityError::MISSING_KASME);
    if (ulNasCount > MaxNasCount)
        Fail(AsSecurityError::INVALID_UL_NAS_COUNT);

    // The count is a 24-bit value carried in four octets, TS 33.401 A.3.
    const ByteString count{static_cast<uint8_t>((ulNasCount >> 24U) & 0xFFU),
                           static_cast<uint8_t>((ulNasCount >> 16U) & 0xFFU),
                           static_cast<uint8_t>((ulNasCount >> 8U) & 0xFFU), static_cast<uint8_t>(ulNasCount & 0xFFU)};
    return Kdf(kasme, 0x11, {count});
}

Key256 DeriveNh(const Key256 &kasme, const Key256 &syncInput)
{
    if (AllZero(kasme.data(), kasme.size()))
        Fail(AsSecurityError::MISSING_KASME);
    if (AllZero(syncInput.data(), syncInput.size()))
        Fail(AsSecurityError::MISSING_NH);
    // NCC is not an input here, by design: it names the chain position, it does
    // not contribute to the derivation.
    return Kdf(kasme, 0x12, {ByteString(syncInput.begin(), syncInput.end())});
}

Key256 DeriveKenbStar(const Key256 &baseKey, uint16_t pci, uint32_t earfcnDl)
{
    ValidatePci(pci);
    ValidateEarfcnDl(earfcnDl);
    if (AllZero(baseKey.data(), baseKey.size()))
        Fail(AsSecurityError::NO_ACTIVE_CONTEXT);

    const ByteString pciBytes{static_cast<uint8_t>((pci >> 8U) & 0xFFU), static_cast<uint8_t>(pci & 0xFFU)};
    return Kdf(baseKey, 0x13, {pciBytes, EncodeEarfcnDl(earfcnDl)});
}

Key128 DeriveAlgorithmKey(const Key256 &kenb, AsAlgorithmType type, uint8_t algorithmIdentity)
{
    ValidateAlgorithmIdentity(algorithmIdentity);
    switch (type)
    {
    case AsAlgorithmType::RRC_ENCRYPTION:
    case AsAlgorithmType::RRC_INTEGRITY:
    case AsAlgorithmType::UP_ENCRYPTION:
    case AsAlgorithmType::UP_INTEGRITY:
        break;
    default:
        Fail(AsSecurityError::UNSUPPORTED_ALGORITHM);
    }

    auto full = Kdf(kenb, 0x15, {ByteString{static_cast<uint8_t>(type)}, ByteString{algorithmIdentity}});
    // TS 33.401 A.7: a 128-bit key is the least significant half of the output.
    Key128 key{};
    std::copy(full.begin() + 16, full.end(), key.begin());
    return key;
}

TargetDerivation DeriveTargetKenbStar(const ByteString &nextHopParameter, uint8_t nextHopChainingCount,
                                      const TargetRadioConfig &radio)
{
    ValidateSecurityKey(nextHopParameter, AsSecurityError::INVALID_NH_LENGTH);
    ValidateNcc(nextHopChainingCount);
    if (!radio.available)
        Fail(AsSecurityError::MISSING_TARGET_RADIO_CONFIG);
    ValidatePci(radio.pci);
    ValidateEarfcnDl(radio.earfcnDl);

    Key256 nh{};
    std::copy(nextHopParameter.begin(), nextHopParameter.end(), nh.begin());
    TargetDerivation result;
    result.kenbStar = DeriveKenbStar(nh, radio.pci, radio.earfcnDl);
    result.ncc = nextHopChainingCount;
    result.pci = radio.pci;
    result.earfcnDl = radio.earfcnDl;
    SecureZero(nh);
    return result;
}

// --- AsSecurityContext ------------------------------------------------------

AsSecurityContext::~AsSecurityContext()
{
    Wipe();
}

AsSecurityContext::AsSecurityContext(AsSecurityContext &&other) noexcept
{
    *this = std::move(other);
}

AsSecurityContext &AsSecurityContext::operator=(AsSecurityContext &&other) noexcept
{
    if (this == &other)
        return *this;
    Wipe();

    active_ = other.active_;
    ownerUeId_ = other.ownerUeId_;
    nasGeneration_ = other.nasGeneration_;
    asGeneration_ = other.asGeneration_;
    kasme_ = other.kasme_;
    kenb_ = other.kenb_;
    kenbIndex_ = other.kenbIndex_;
    nh_ = other.nh_;
    nhIndex_ = other.nhIndex_;
    algorithms_ = other.algorithms_;
    pending_ = other.pending_;

    other.Wipe();
    return *this;
}

void AsSecurityContext::Wipe() noexcept
{
    SecureZero(kasme_);
    SecureZero(kenb_);
    if (pending_)
    {
        SecureZero(pending_->kenbStar);
        SecureZero(pending_->nh);
    }
    SecureZero(nh_);
    pending_.reset();
    active_ = false;
    ownerUeId_ = 0;
    nasGeneration_ = 0;
    asGeneration_ = 0;
    kenbIndex_ = 0;
    nhIndex_ = 0;
}

void AsSecurityContext::Install(uint32_t ownerUeId, const Key256 &kasme, uint32_t ulNasCount,
                                uint64_t nasGeneration, const AsAlgorithmSet &algorithms)
{
    if (AllZero(kasme.data(), kasme.size()))
        Fail(AsSecurityError::MISSING_KASME);
    if (ulNasCount > MaxNasCount)
        Fail(AsSecurityError::INVALID_UL_NAS_COUNT);
    if (algorithms.negotiated)
    {
        ValidateAlgorithmIdentity(algorithms.rrcIntegrity);
        ValidateAlgorithmIdentity(algorithms.rrcCiphering);
        ValidateAlgorithmIdentity(algorithms.upCiphering);
        if (algorithms.upIntegrity)
            ValidateAlgorithmIdentity(*algorithms.upIntegrity);
    }

    Wipe();

    kasme_ = kasme;
    algorithms_ = algorithms;
    ownerUeId_ = ownerUeId;
    nasGeneration_ = nasGeneration;

    kenb_ = DeriveKenb(kasme_, ulNasCount);
    // The initial KeNB sits at the virtual NH position of NCC 0. The first NH
    // is derived immediately and belongs to absolute position 1 / NCC 1.
    kenbIndex_ = 0;
    nh_ = DeriveNh(kasme_, kenb_);
    nhIndex_ = 1;
    asGeneration_ = 1;
    active_ = true;
}

AsSecurityContext AsSecurityContext::Create(uint32_t ownerUeId, const Key256 &kasme, uint32_t ulNasCount,
                                            uint64_t nasGeneration, const AsAlgorithmSet &algorithms)
{
    AsSecurityContext context;
    context.Install(ownerUeId, kasme, ulNasCount, nasGeneration, algorithms);
    return context;
}

uint8_t AsSecurityContext::ActiveNcc() const
{
    if (!active_)
        Fail(AsSecurityError::NO_ACTIVE_CONTEXT);
    return static_cast<uint8_t>(kenbIndex_ & 0x7U);
}

uint64_t AsSecurityContext::NhChainIndex() const
{
    if (!active_)
        Fail(AsSecurityError::NO_ACTIVE_CONTEXT);
    return nhIndex_;
}

Key256 AsSecurityContext::ActiveKenb() const
{
    if (!active_)
        Fail(AsSecurityError::NO_ACTIVE_CONTEXT);
    return kenb_;
}

AsKeys AsSecurityContext::DeriveAccessKeys() const
{
    if (!active_)
        Fail(AsSecurityError::NO_ACTIVE_CONTEXT);
    if (!algorithms_.negotiated)
        Fail(AsSecurityError::UNSUPPORTED_ALGORITHM);

    AsKeys keys;
    keys.kRrcInt = DeriveAlgorithmKey(kenb_, AsAlgorithmType::RRC_INTEGRITY, algorithms_.rrcIntegrity);
    keys.kRrcEnc = DeriveAlgorithmKey(kenb_, AsAlgorithmType::RRC_ENCRYPTION, algorithms_.rrcCiphering);
    keys.kUpEnc = DeriveAlgorithmKey(kenb_, AsAlgorithmType::UP_ENCRYPTION, algorithms_.upCiphering);
    if (algorithms_.upIntegrity)
        keys.kUpInt = DeriveAlgorithmKey(kenb_, AsAlgorithmType::UP_INTEGRITY, *algorithms_.upIntegrity);
    return keys;
}

Key256 AsSecurityContext::ChainNh(const Key256 &kasme, const Key256 &from, uint64_t fromIndex, uint64_t toIndex)
{
    if (toIndex < fromIndex)
        Fail(AsSecurityError::IMPOSSIBLE_NCC_TRANSITION);
    if (toIndex - fromIndex > MaxNcc)
        Fail(AsSecurityError::IMPOSSIBLE_NCC_TRANSITION);

    Key256 current = from;
    for (uint64_t index = fromIndex; index < toIndex; index++)
        current = DeriveNh(kasme, current);
    return current;
}

void AsSecurityContext::PrepareHandover(uint32_t ueId, uint64_t nasGeneration, uint8_t receivedNcc, uint16_t pci,
                                        uint32_t earfcnDl)
{
    if (!active_)
        Fail(AsSecurityError::NO_ACTIVE_CONTEXT);
    if (ueId != ownerUeId_)
        Fail(AsSecurityError::CROSS_UE_CONTEXT);
    if (nasGeneration != nasGeneration_)
        Fail(AsSecurityError::STALE_NAS_GENERATION);
    if (pending_)
        Fail(AsSecurityError::HANDOVER_ALREADY_PENDING);
    ValidateNcc(receivedNcc);
    ValidatePci(pci);
    ValidateEarfcnDl(earfcnDl);

    const uint8_t activeNcc = static_cast<uint8_t>(kenbIndex_ & 0x7U);
    PendingHandover pending;

    if (receivedNcc == activeNcc)
    {
        // TS 33.401 7.2.8 horizontal: no new NH, derive from the active KeNB.
        pending.kenbStar = DeriveKenbStar(kenb_, pci, earfcnDl);
        pending.ncc = receivedNcc;
        pending.nh = nh_;
        pending.nhIndex = nhIndex_;
        pending.kenbIndex = kenbIndex_;
    }
    else
    {
        // Vertical: walk forward to the next chain position that carries the
        // received NCC. The eight positions of a wrap are distinguishable
        // because the absolute index keeps counting.
        const uint64_t delta = (static_cast<uint64_t>(receivedNcc) + 8U - activeNcc) % 8U;
        if (delta == 0)
            Fail(AsSecurityError::IMPOSSIBLE_NCC_TRANSITION);
        const uint64_t target = kenbIndex_ + delta;
        if (target < nhIndex_)
            Fail(AsSecurityError::STALE_NH);

        pending.nh = target == nhIndex_ ? nh_ : ChainNh(kasme_, nh_, nhIndex_, target);
        pending.nhIndex = target;
        pending.kenbIndex = target;
        pending.kenbStar = DeriveKenbStar(pending.nh, pci, earfcnDl);
        pending.ncc = receivedNcc;
    }

    pending_ = pending;
}

void AsSecurityContext::CommitHandover()
{
    if (!active_)
        Fail(AsSecurityError::NO_ACTIVE_CONTEXT);
    if (!pending_)
        Fail(AsSecurityError::NO_PENDING_HANDOVER);

    SecureZero(kenb_);
    SecureZero(nh_);
    kenb_ = pending_->kenbStar;
    kenbIndex_ = pending_->kenbIndex;
    nh_ = pending_->nh;
    nhIndex_ = pending_->nhIndex;
    SecureZero(pending_->kenbStar);
    SecureZero(pending_->nh);
    pending_.reset();
    asGeneration_++;
}

void AsSecurityContext::DiscardHandover() noexcept
{
    if (pending_)
    {
        SecureZero(pending_->kenbStar);
        SecureZero(pending_->nh);
        pending_.reset();
    }
}

void AsSecurityContext::ReplaceNasSecurity(uint32_t ueId, const Key256 &kasme, uint32_t ulNasCount,
                                           uint64_t newNasGeneration)
{
    if (active_ && ueId != ownerUeId_)
        Fail(AsSecurityError::CROSS_UE_CONTEXT);
    if (newNasGeneration <= nasGeneration_)
        Fail(AsSecurityError::STALE_NAS_GENERATION);
    Install(ueId, kasme, ulNasCount, newNasGeneration, algorithms_);
}

void AsSecurityContext::Reset() noexcept
{
    Wipe();
}

std::string AsSecurityContext::Describe() const
{
    std::ostringstream out;
    out << "AS context ue=" << ownerUeId_ << " active=" << (active_ ? "yes" : "no")
        << " ncc=" << (active_ ? static_cast<int>(kenbIndex_ & 0x7U) : -1)
        << " nhIndex=" << (active_ ? static_cast<long long>(nhIndex_) : -1)
        << " asGen=" << asGeneration_ << " nasGen=" << nasGeneration_
        << " pending=" << (pending_ ? "yes" : "no");
    return out.str();
}

} // namespace lte::security
