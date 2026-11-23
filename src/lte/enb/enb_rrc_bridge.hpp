//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//

// Phase 18-F-B6-C: the eNB composition that joins the SRB1 radio runtime to the
// existing S1AP codec.
//
// It owns no SCTP association: an S1AP PDU leaves through the sink the owner
// supplies and arrives through the two On... entry points. That keeps the
// existing S1 association epoch, sender binding and E-RAB allocation in the
// multiplexer, which is where they already live, while the NAS that S1AP
// carries reaches the UE over the real SRB1 path.
#pragma once

#include "codec.hpp"
#include "types.hpp"

#include <lte/rrc-runtime/rrc_srb1_runtime.hpp>
#include <lte/rrc-runtime/uu_transport.hpp>

#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <vector>

namespace lte::enb::s1ap
{

using lte::rrc::EnbSrb1Runtime;
using lte::rrc::RrcConnectionSetupCompleteMessage;
using lte::rrc::RrcState;

class EnbRrcBridge
{
  public:
    struct Config
    {
        EnbConfig enb{};
        EnbSrb1Runtime::Config srb1{};
        // The operator's AS algorithm policy for this cell.
        lte::security::AsAlgorithmConfiguration algorithms{};
    };

    using S1apSink = std::function<void(const std::vector<uint8_t> &pdu)>;
    // Called once the RRC connection is up so the owner can bind the S1AP UE
    // context (registry slot, E-RAB transaction) to this association.
    using SetupHandler = std::function<void(uint32_t association, uint32_t enbUeS1apId, uint32_t mmeUeS1apId,
                                            const std::vector<uint8_t> &nas)>;

    EnbRrcBridge(uu::Socket &socket, Config config, S1apSink sink);

    void Pump(int timeoutMs);
    void Tick();

    // S1AP messages that carry NAS towards the UE, or start AS security.
    void OnDownlinkNasTransport(const std::vector<uint8_t> &pdu);
    void OnInitialContextSetupRequest(const std::vector<uint8_t> &pdu);

    // Called by the owner once the E-RABs of a pending Initial Context Setup are
    // established. Nothing is reported before this, and nothing is reported at
    // all if AS security did not activate.
    void CompleteInitialContextSetup(uint32_t association, const std::vector<ErabSetupItem> &erabs);

    // The S1 association is gone: access-bound state is invalidated and no
    // pending transaction may be answered afterwards.
    void OnS1AssociationLost();

    [[nodiscard]] bool HasContext(uint32_t association) const;
    [[nodiscard]] RrcState StateOf(uint32_t association) const;
    [[nodiscard]] std::optional<uint32_t> EnbUeS1apIdOf(uint32_t association) const;
    [[nodiscard]] std::optional<uint32_t> MmeUeS1apIdOf(uint32_t association) const;
    [[nodiscard]] std::optional<uint32_t> AssociationOf(uint32_t enbUeS1apId) const;
    [[nodiscard]] bool AsSecurityActive(uint32_t association) const;
    [[nodiscard]] size_t InitialUeMessages() const
    {
        return initialUeMessages_;
    }
    [[nodiscard]] size_t UplinkNasTransports() const
    {
        return uplinkNasTransports_;
    }
    [[nodiscard]] size_t DownlinkNasTransports() const
    {
        return downlinkNasTransports_;
    }
    [[nodiscard]] size_t SetupResponses() const
    {
        return setupResponses_;
    }
    [[nodiscard]] size_t Refused() const
    {
        return refused_;
    }
    [[nodiscard]] const EnbSrb1Runtime &Runtime() const
    {
        return runtime_;
    }
    [[nodiscard]] EnbSrb1Runtime &Runtime()
    {
        return runtime_;
    }

  private:
    struct Association
    {
        uint32_t enbUeS1apId{0};
        uint32_t mmeUeS1apId{0};
        bool icsPending{false};
        bool icsCompleted{false};
        InitialContextSetupRequest request{};
    };

    void OnSetupComplete(uint32_t association, const RrcConnectionSetupCompleteMessage &message);
    void OnUplinkNas(uint32_t association, const std::vector<uint8_t> &nas);

    uu::Socket &socket_;
    Config config_;
    S1apSink sink_;
    EnbSrb1Runtime runtime_;
    std::map<uint32_t, Association> associations_{};
    std::map<uint32_t, uint32_t> byEnbId_{};
    uint32_t nextEnbUeS1apId_{1};
    size_t initialUeMessages_{0};
    size_t uplinkNasTransports_{0};
    size_t downlinkNasTransports_{0};
    size_t setupResponses_{0};
    size_t refused_{0};
};

} // namespace lte::enb::s1ap
