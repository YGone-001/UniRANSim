//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//

#include "enb_as_security_context.hpp"

#include <utility>

namespace lte::security
{
namespace
{

void SecureZero(Key256 &key) noexcept
{
    volatile uint8_t *bytes = key.data();
    for (size_t i = 0; i < key.size(); i++)
        bytes[i] = 0;
}

bool AllZero(const Key256 &key)
{
    for (auto byte : key)
    {
        if (byte != 0)
            return false;
    }
    return true;
}

void ValidateAlgorithms(const AsAlgorithmSet &algorithms)
{
    if (!algorithms.negotiated)
        throw AsSecurityException(AsSecurityError::UNSUPPORTED_ALGORITHM);
    ValidateAlgorithmIdentity(algorithms.rrcIntegrity);
    ValidateAlgorithmIdentity(algorithms.rrcCiphering);
    ValidateAlgorithmIdentity(algorithms.upCiphering);
    if (algorithms.upIntegrity)
        ValidateAlgorithmIdentity(*algorithms.upIntegrity);
}

} // namespace

EnbAsSecurityContext::~EnbAsSecurityContext()
{
    Wipe();
}

EnbAsSecurityContext::EnbAsSecurityContext(EnbAsSecurityContext &&other) noexcept
{
    *this = std::move(other);
}

EnbAsSecurityContext &EnbAsSecurityContext::operator=(EnbAsSecurityContext &&other) noexcept
{
    if (this == &other)
        return *this;
    Wipe();
    active_ = other.active_;
    ownerUeId_ = other.ownerUeId_;
    s1Generation_ = other.s1Generation_;
    kenb_ = other.kenb_;
    algorithms_ = other.algorithms_;
    other.Wipe();
    return *this;
}

EnbAsSecurityContext EnbAsSecurityContext::Create(uint32_t enbUeId, const Key256 &kenb, uint64_t s1Generation)
{
    if (enbUeId == 0)
        throw AsSecurityException(AsSecurityError::CROSS_UE_CONTEXT);
    if (AllZero(kenb))
        throw AsSecurityException(AsSecurityError::MISSING_KASME);

    EnbAsSecurityContext context;
    context.active_ = true;
    context.ownerUeId_ = enbUeId;
    context.s1Generation_ = s1Generation;
    context.kenb_ = kenb;
    return context;
}

Key256 EnbAsSecurityContext::ActiveKenb() const
{
    if (!active_)
        throw AsSecurityException(AsSecurityError::NO_ACTIVE_CONTEXT);
    if (!algorithms_.negotiated)
        throw AsSecurityException(AsSecurityError::UNSUPPORTED_ALGORITHM);
    return kenb_;
}

AsKeys EnbAsSecurityContext::DeriveAccessKeys() const
{
    if (!active_)
        throw AsSecurityException(AsSecurityError::NO_ACTIVE_CONTEXT);
    if (!algorithms_.negotiated)
        throw AsSecurityException(AsSecurityError::UNSUPPORTED_ALGORITHM);

    AsKeys keys;
    keys.kRrcInt = DeriveAlgorithmKey(kenb_, AsAlgorithmType::RRC_INTEGRITY, algorithms_.rrcIntegrity);
    keys.kRrcEnc = DeriveAlgorithmKey(kenb_, AsAlgorithmType::RRC_ENCRYPTION, algorithms_.rrcCiphering);
    keys.kUpEnc = DeriveAlgorithmKey(kenb_, AsAlgorithmType::UP_ENCRYPTION, algorithms_.upCiphering);
    if (algorithms_.upIntegrity)
        keys.kUpInt = DeriveAlgorithmKey(kenb_, AsAlgorithmType::UP_INTEGRITY, *algorithms_.upIntegrity);
    return keys;
}

void EnbAsSecurityContext::ApplyAsAlgorithms(const AsAlgorithmSet &algorithms)
{
    if (!active_)
        throw AsSecurityException(AsSecurityError::NO_ACTIVE_CONTEXT);
    ValidateAlgorithms(algorithms);
    algorithms_ = algorithms;
}

void EnbAsSecurityContext::ReplaceKenb(uint32_t enbUeId, const Key256 &kenb, uint64_t s1Generation)
{
    if (active_ && s1Generation < s1Generation_)
        throw AsSecurityException(AsSecurityError::STALE_NAS_GENERATION);
    if (enbUeId == 0)
        throw AsSecurityException(AsSecurityError::CROSS_UE_CONTEXT);
    if (AllZero(kenb))
        throw AsSecurityException(AsSecurityError::MISSING_KASME);

    SecureZero(kenb_);
    kenb_ = kenb;
    ownerUeId_ = enbUeId;
    s1Generation_ = s1Generation;
    active_ = true;
    // A replacement key invalidates the algorithms negotiated for the old one.
    algorithms_ = AsAlgorithmSet{};
}

void EnbAsSecurityContext::Reset() noexcept
{
    Wipe();
}

void EnbAsSecurityContext::Wipe() noexcept
{
    SecureZero(kenb_);
    active_ = false;
    ownerUeId_ = 0;
    s1Generation_ = 0;
    algorithms_ = AsAlgorithmSet{};
}

std::string EnbAsSecurityContext::Describe() const
{
    std::string out = "eNB AS context: ";
    out += active_ ? "active" : "inactive";
    out += ", ue=" + std::to_string(ownerUeId_);
    out += ", s1Generation=" + std::to_string(s1Generation_);
    out += ", algorithms=";
    out += algorithms_.negotiated ? std::to_string(algorithms_.rrcIntegrity) + "/" +
                                        std::to_string(algorithms_.rrcCiphering) + "/" +
                                        std::to_string(algorithms_.upCiphering)
                                  : "none";
    return out;
}

} // namespace lte::security
