//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//

// Phase 18-F-B6-D2 Commit B: the transport the production UE application uses
// for connected-mode NAS.
//
// It owns one UeSrb1Runtime and its socket, decides whether a NAS message is the
// initial one (carried in RRCConnectionSetupComplete) or a later one (carried in
// ULInformationTransfer), and hands downlink NAS back through one callback. The
// application keeps its NAS state machine; only this transport changes.
#pragma once

#include <lte/rrc-runtime/rrc_srb1_runtime.hpp>
#include <lte/rrc-runtime/uu_transport.hpp>
#include <lte/security/as_security.hpp>

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace lte::ue
{

struct UuEndpoint
{
    std::string localAddress{};
    uint16_t localPort{0};
    std::string enbAddress{};
    uint16_t enbPort{0};
};

class UuNasTransport
{
  public:
    using NasHandler = std::function<void(const std::vector<uint8_t> &)>;
    // The network released the RRC connection; the application keeps EMM and
    // the NAS security context and decides when to request access again.
    using ReleaseHandler = std::function<void()>;
    using PagingHandler = std::function<void(uint8_t mmec, uint32_t mTmsi)>;
    // Phase 18-F-B6-D6: a DTCH frame from the eNB. The owner demultiplexes it to
    // the DRB runtime; it is user plane and never RRC.
    using UserPlaneHandler = std::function<void(const uu::Frame &)>;
    // A decoded RRCConnectionReconfiguration that configures DRBs.
    using DrbReconfigurationHandler = std::function<void(const rrc::DrbReconfiguration &)>;

    UuNasTransport(UuEndpoint endpoint, rrc::UeSrb1Runtime::Config config);
    ~UuNasTransport();

    UuNasTransport(const UuNasTransport &) = delete;
    UuNasTransport &operator=(const UuNasTransport &) = delete;

    // Binds the configured endpoint and starts RRCConnectionRequest. Throws when
    // the endpoint cannot be bound: the transport never falls back to another
    // address or to the legacy link.
    void Start();
    void SetNasHandler(NasHandler handler);
    void SetReleaseHandler(ReleaseHandler handler);
    void SetPagingHandler(PagingHandler handler);
    void SetUserPlaneHandler(UserPlaneHandler handler);
    void SetDrbReconfigurationHandler(DrbReconfigurationHandler handler);

    // Starts a new RRC connection after a network release. The transport keeps
    // its socket, its NAS handler and the UE identity; only the radio state is
    // rebuilt, so the next SendNas travels in RRCConnectionSetupComplete.
    void ResumeAccess();

    // The S-TMSI assigned by the network. It is used by the next RRC access and
    // by paging identity matching while the UE is idle.
    void SetIdentity(uint8_t mmec, uint32_t mTmsi);

    // The initial NAS message travels in SetupComplete; every later one in
    // ULInformationTransfer. Returns false when the RRC connection is not yet
    // established or the bearer refused the message - the caller must not retry
    // it over another transport.
    bool SendNas(const std::vector<uint8_t> &nas);

    // One uplink DTCH payload (routing header included). Refused unless the RRC
    // connection is established; it never falls back to the legacy link.
    bool SendUserPlane(const std::vector<uint8_t> &payload);
    // The DL-DCCH RRCConnectionReconfigurationComplete for a configuration the
    // callback above delivered.
    void SubmitReconfigurationComplete(uint8_t transactionId);

    // The AS security context of the current access, or null before the
    // SecurityMode procedure completed. Its K_UPenc keys the DRBs.
    [[nodiscard]] const security::AsSecurityContext *SecurityContext() const;
    [[nodiscard]] uint32_t Association() const
    {
        return config_.association;
    }

    // Bounded: at most one frame, and never blocks longer than timeoutMs.
    void Pump(int timeoutMs);
    void Tick();

    [[nodiscard]] const rrc::UeSrb1Runtime &Runtime() const
    {
        return *runtime_;
    }

    // Told by the NAS layer once NAS security is active, so the next downlink
    // SRB1 PDU is expected to carry the RRC SecurityModeCommand.
    void PrepareAsSecurity(const security::Key256 &kasme, uint32_t ulNasCount, uint64_t nasGeneration);

    [[nodiscard]] rrc::RrcState State() const;
    [[nodiscard]] bool Connected() const;
    [[nodiscard]] bool AsSecurityActive() const;
    [[nodiscard]] bool SetupCompleteSent() const noexcept
    {
        return setupCompleteSent_;
    }
    [[nodiscard]] uint16_t LocalPort() const;

    void Release();

  private:
    UuEndpoint endpoint_{};
    rrc::UeSrb1Runtime::Config config_{};
    std::unique_ptr<uu::Socket> socket_{};
    std::unique_ptr<rrc::UeSrb1Runtime> runtime_{};
    NasHandler handler_{};
    ReleaseHandler releaseHandler_{};
    PagingHandler pagingHandler_{};
    UserPlaneHandler userPlaneHandler_{};
    DrbReconfigurationHandler drbReconfigurationHandler_{};
    bool setupCompleteSent_{false};
    bool released_{false};
};

} // namespace lte::ue
