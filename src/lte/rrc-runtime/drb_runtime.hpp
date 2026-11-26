//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//

// Phase 18-F-B6-D6: the DRB user-plane bearer and its DTCH routing.
//
// One DrbBearer is one direction-pair of one EPS bearer:
//
//   IP packet -> PDCP (DRB 12-bit SN, EEA ciphering) -> RLC AM (DTCH)
//   RLC AM -> PDCP -> IP packet
//
// The RLC entity is the accepted LTE AM entity, unchanged; only its logical
// channel is DTCH instead of DCCH. The PDCP entity is the accepted DRB12
// profile, keyed with K_UPenc from the AS security context of the access.
//
// DrbRuntime owns the bearers of one association and implements the DTCH
// routing header:
//
//   kind(1) || drbIdentity(1) || body
//
// kind 1 is DATA and body is the RLC PDU. kind 2 is READY, an internal
// simulator control message (never 3GPP) that the UE sends once the DRBs exist
// and repeats the PDN address its own NAS assigned, exactly as the accepted
// legacy BEARER_READY and handover BearerTransportReady frames already do. The
// eNB cannot decrypt NAS, so it never invents that address.
#pragma once

#include "lte_am_bearer.hpp"
#include "rrc_drb_config.hpp"
#include "uu_transport.hpp"

#include <lte/security/pdcp_security.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <vector>

namespace lte::rrc
{

constexpr uint8_t DrbKindData = 1;
constexpr uint8_t DrbKindReady = 2;
constexpr size_t DrbRoutingHeaderSize = 2;
// A DRB SDU is an IP packet. This bound is the largest IPv4 packet this data
// path will carry; a larger one is refused and counted, never truncated.
constexpr size_t MaxDrbSduBytes = 1600;
// The AM PDU bound is the DRB's local implementation profile, not a value the
// RRC message carries. Both ends must use the same bound or one side fragments
// every IP packet into 128-octet PDUs; the DRB composer therefore normalizes it
// on both the UE and the eNB.
constexpr size_t DrbAmMaxPduBytes = 1700;

struct DrbBearerConfig
{
    uint8_t ebi{};
    uint8_t drbIdentity{};
    rlc::am::AmConfig am{};
    uint8_t cipheringAlgorithm{};
    security::Key128 kUpEnc{};
};

struct DrbReady
{
    uint8_t ebi{};
    uint32_t generation{};
    std::array<uint8_t, 4> ipv4{};
};

struct DrbCounters
{
    uint64_t uplinkPackets{};
    uint64_t uplinkBytes{};
    uint64_t downlinkPackets{};
    uint64_t downlinkBytes{};
    uint64_t oversizedDrops{};
    uint64_t malformedDrops{};
    uint64_t pdcpFailures{};
    uint64_t unknownBearerDrops{};
    uint64_t wrongFrameDrops{};
    uint64_t rlcFailures{};
    uint64_t duplicateSetups{};
    uint64_t readySent{};
    uint64_t readyReceived{};
    // RLC PDUs the simulated Uu refused to carry (a full send buffer). The
    // peer never saw them; RLC retransmission or a window stall is what the
    // layer above must show.
    uint64_t sendFailures{};
};

class DrbBearer
{
  public:
    // Sends one RLC PDU for this bearer. The owner adds the DTCH routing header.
    using Sender = std::function<bool(const std::vector<uint8_t> &rlcPdu)>;
    using Deliverer = std::function<void(uint8_t ebi, const std::vector<uint8_t> &ipPacket)>;

    DrbBearer(DrbBearerConfig config, rlc::am::EndpointRole role, uint32_t association, Sender sender,
              Deliverer deliverer);

    DrbBearer(const DrbBearer &) = delete;
    DrbBearer &operator=(const DrbBearer &) = delete;

    bool SubmitIp(const uint8_t *packet, size_t size);
    [[nodiscard]] uint32_t NextTickIn() const
    {
        return rlc_.NextTickIn();
    }
    void AdvanceTo(int64_t nowMs)
    {
        rlc_.AdvanceTo(nowMs);
    }
    void SetActivityCallback(std::function<void()> callback)
    {
        rlc_.SetActivityCallback(std::move(callback));
    }
    [[nodiscard]] int64_t LastTickMs() const
    {
        return rlc_.LastTickMs();
    }
    [[nodiscard]] uint64_t &ScheduleVersion()
    {
        return rlc_.ScheduleVersion();
    }
    // `frame` carries the RLC PDU as its payload and must be on DTCH.
    bool OnRlcFrame(const uu::Frame &frame);
    void Tick();
    void Release() noexcept;

    [[nodiscard]] uint8_t Ebi() const
    {
        return config_.ebi;
    }
    [[nodiscard]] uint8_t DrbIdentity() const
    {
        return config_.drbIdentity;
    }
    [[nodiscard]] const DrbCounters &Counters() const
    {
        return counters_;
    }
    [[nodiscard]] const rlc::am::LteAmBearer &Rlc() const
    {
        return rlc_;
    }
    // PDUs transmitted but not yet acknowledged on this bearer's uplink.
    [[nodiscard]] uint16_t OutstandingPdus() const
    {
        return rlc_.OutstandingPdus();
    }

  private:
    DrbBearerConfig config_{};
    rlc::am::EndpointRole role_{rlc::am::EndpointRole::UE};
    uint32_t association_{0};
    Deliverer deliverer_{};
    std::optional<security::PdcpSecurityEntity> pdcpTx_{};
    std::optional<security::PdcpSecurityEntity> pdcpRx_{};
    rlc::am::LteAmBearer rlc_;
    DrbCounters counters_{};
    bool released_{false};
};

class DrbRuntime
{
  public:
    // Sends one complete DTCH payload (routing header included).
    using Sender = std::function<bool(const std::vector<uint8_t> &payload)>;
    using Deliverer = std::function<void(uint8_t ebi, const std::vector<uint8_t> &ipPacket)>;
    // The UE confirmed the DRBs and restated its PDN address. Returns false when
    // the confirmation is not acceptable, and then nothing is activated.
    using ReadyHandler = std::function<bool(const DrbReady &)>;

    DrbRuntime(rlc::am::EndpointRole role, uint32_t association, Sender sender, Deliverer deliverer);

    DrbRuntime(const DrbRuntime &) = delete;
    DrbRuntime &operator=(const DrbRuntime &) = delete;

    bool AddBearer(const DrbBearerConfig &config);
    // The owner is told when a bearer's RLC creates work, so an idle runtime
    // can be scheduled again without polling every runtime every millisecond.
    void SetActivityCallback(std::function<void(uint8_t ebi)> callback);
    [[nodiscard]] DrbBearer *BearerForTick(uint8_t ebi);
    [[nodiscard]] int64_t NextDeadlineMs() const;
    void AdvanceTo(int64_t nowMs);
    [[nodiscard]] uint64_t Generation() const
    {
        return generation_;
    }
    [[nodiscard]] uint64_t &ScheduleVersion()
    {
        return scheduleVersion_;
    }
    void SetReadyHandler(ReadyHandler handler);
    // Uplink IP packet on one EPS bearer. False when the bearer is unknown.
    bool SubmitIp(uint8_t ebi, const uint8_t *packet, size_t size);
    // A DTCH frame from the peer. Validates channel, direction and routing, then
    // hands DATA to one bearer and READY to the owner.
    bool OnFrame(const uu::Frame &frame);
    // The UE announces that the DRBs are configured and restates its address.
    bool SendReady(const DrbReady &ready);
    void ReleaseBearer(uint8_t ebi);
    void Release() noexcept;
    void Tick();

    [[nodiscard]] bool HasBearer(uint8_t ebi) const;
    [[nodiscard]] size_t BearerCount() const
    {
        return bearers_.size();
    }
    [[nodiscard]] const DrbCounters &Counters() const
    {
        return counters_;
    }
    [[nodiscard]] const DrbBearer *Bearer(uint8_t ebi) const;
    // The largest in-flight PDU count over this runtime's bearers. The UE uses
    // it as the downlink-free uplink backpressure signal: when it is at the
    // high watermark the TUN reader pauses, and when it falls to the low
    // watermark it resumes.
    [[nodiscard]] uint16_t MaxOutstandingPdus() const;
    [[nodiscard]] bool Congested(uint16_t highWatermark) const
    {
        return MaxOutstandingPdus() >= highWatermark;
    }

  private:
    bool SendPayload(uint8_t kind, uint8_t drbIdentity, const std::vector<uint8_t> &body);

    rlc::am::EndpointRole role_{rlc::am::EndpointRole::UE};
    uint32_t association_{0};
    Sender sender_{};
    Deliverer deliverer_{};
    ReadyHandler readyHandler_{};
    std::map<uint8_t, std::unique_ptr<DrbBearer>> bearers_{};
    std::function<void(uint8_t)> onActivity_{};
    uint64_t generation_{0};
    uint64_t scheduleVersion_{0};
    DrbCounters counters_{};
};

// The two routing-header helpers. They are bounded and refuse anything else.
std::vector<uint8_t> EncodeDrbData(uint8_t drbIdentity, const std::vector<uint8_t> &rlcPdu);
std::vector<uint8_t> EncodeDrbReady(const DrbReady &ready);
bool DecodeDrbRouting(const std::vector<uint8_t> &payload, uint8_t &kind, uint8_t &drbIdentity,
                      size_t &bodyOffset);
// `routingEbi` is the DRB identity the routing header named; the body itself is
// generation(4) || ipv4(4) and carries no second copy of it.
bool DecodeDrbReady(const uint8_t *data, size_t size, uint8_t routingEbi, DrbReady &out);

} // namespace lte::rrc
