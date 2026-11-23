//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//

// Phase 18-F-B6-C: the eNB-side AS security context.
//
// The MME derives KeNB from the EPS security context and sends it to the eNB in
// the S1AP Initial Context Setup Request. The eNB therefore owns a context that
// starts at KeNB: it has no KASME member, no NAS COUNT and no NH chain, because
// none of those belong to it. `AsSecurityContext` remains the UE-side context
// (KASME -> KeNB -> NH/NCC) and keeps its handover guarantees.
//
// The two contexts are interchangeable only through `AsKeySource`, which is the
// subset an AS security procedure actually needs. That is what makes it
// impossible for the eNB procedure to ask for a KASME.
#pragma once

#include "as_security.hpp"

#include <cstdint>
#include <stdexcept>
#include <string>

namespace lte::security
{

class EnbAsSecurityContext : public AsKeySource
{
  public:
    EnbAsSecurityContext() = default;
    ~EnbAsSecurityContext() override;

    EnbAsSecurityContext(const EnbAsSecurityContext &) = delete;
    EnbAsSecurityContext &operator=(const EnbAsSecurityContext &) = delete;
    EnbAsSecurityContext(EnbAsSecurityContext &&other) noexcept;
    EnbAsSecurityContext &operator=(EnbAsSecurityContext &&other) noexcept;

    // The key arrives from S1AP. The generation identifies the S1 transaction
    // that produced it, so a stale request cannot replace a newer context.
    static EnbAsSecurityContext Create(uint32_t enbUeId, const Key256 &kenb, uint64_t s1Generation);

    [[nodiscard]] bool IsActive() const override
    {
        return active_;
    }
    [[nodiscard]] uint32_t OwnerUeId() const override
    {
        return ownerUeId_;
    }
    // Throws UNSUPPORTED_ALGORITHM before an AS algorithm has been selected:
    // receiving a KeNB is not the same as negotiating how to use it.
    [[nodiscard]] Key256 ActiveKenb() const override;
    [[nodiscard]] AsKeys DeriveAccessKeys() const override;
    void ApplyAsAlgorithms(const AsAlgorithmSet &algorithms) override;

    // A fresh Initial Context Setup with a different key replaces the context.
    // Refuses a generation older than the one already installed.
    void ReplaceKenb(uint32_t enbUeId, const Key256 &kenb, uint64_t s1Generation);

    [[nodiscard]] uint64_t S1Generation() const noexcept
    {
        return s1Generation_;
    }
    [[nodiscard]] AsAlgorithmSet Algorithms() const noexcept
    {
        return algorithms_;
    }

    void Reset() noexcept;

    // Names the lifecycle state and never contains key material.
    [[nodiscard]] std::string Describe() const;

  private:
    void Wipe() noexcept;

    bool active_{false};
    uint32_t ownerUeId_{0};
    uint64_t s1Generation_{0};
    Key256 kenb_{};
    AsAlgorithmSet algorithms_{};
};

} // namespace lte::security
