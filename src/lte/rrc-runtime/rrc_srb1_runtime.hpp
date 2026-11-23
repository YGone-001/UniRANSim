//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//

// Phase 18-F-B6-B2: the LTE RRC connection runtime on SRB1.
//
// One UE and one eNB endpoint, each owning its RRC state, its SRB1 RLC AM
// entity and its SRB1 PDCP entity, exchanging real bytes over the simulated Uu:
//
//   RRC SDU -> PDCP -> RLC AM -> Uu -> RLC AM -> PDCP -> RRC decoder
//
// SRB0 (RRCConnectionRequest / Setup) still travels through RLC TM on CCCH; the
// same socket carries it, because the endpoint dispatches on the logical
// channel. No security is active on this path: the SRB1 PDCP entity is the
// pre-SecurityMode profile.
#pragma once

#include "lte_am_bearer.hpp"
#include "rlc_tm.hpp"
#include "rrc_connection_setup_complete.hpp"
#include "rrc_initial_access.hpp"
#include "srb1_pdcp.hpp"
#include "srb1_rlc_config.hpp"
#include "uu_transport.hpp"

#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace lte::rrc
{

using rlc::am::EndpointRole;
using rlc::am::LteAmBearer;

enum class Srb1RuntimeError : uint8_t
{
    NOT_ESTABLISHED,
    NO_SETUP_CONFIGURED,
    UNEXPECTED_STATE,
    ENCODE_FAILED,
};

const char *ToString(Srb1RuntimeError error);

class Srb1RuntimeException : public std::runtime_error
{
  public:
    explicit Srb1RuntimeException(Srb1RuntimeError reason);

    [[nodiscard]] Srb1RuntimeError Reason() const noexcept
    {
        return reason_;
    }

  private:
    Srb1RuntimeError reason_;
};

// What the UE saw and did, so a test can state the wire facts instead of
// guessing them.
struct Srb1Evidence
{
    std::vector<uint8_t> lastPdcpPdu{};
    std::vector<uint8_t> lastRrcPdu{};
    uint8_t lastPdcpSn{0};
    size_t pdcpPdus{0};
    size_t rrcMessages{0};
};

class UeSrb1Runtime
{
  public:
    struct Config
    {
        uint32_t association{0};
        uint8_t mmec{0};
        uint32_t mTmsi{0};
        uint8_t selectedPlmnIdentity{1};
    };

    UeSrb1Runtime(uu::Socket &socket, uint16_t enbPort, Config config);

    // Sends RRCConnectionRequest over SRB0 and moves to REQUEST_PENDING.
    void StartAccess();

    // Receives at most one frame and dispatches it by logical channel.
    void Pump(int timeoutMs);
    void Tick();

    // Encodes RRCConnectionSetupComplete, runs it through SRB1 PDCP and hands
    // the result to RLC AM. The state moves to COMPLETE_PENDING and reaches
    // CONNECTED only when RLC acknowledges the PDU.
    void SubmitSetupComplete(const std::vector<uint8_t> &nas);

    [[nodiscard]] RrcState State() const
    {
        return state_;
    }
    [[nodiscard]] bool Srb1Established() const
    {
        return bearer_ != nullptr;
    }
    [[nodiscard]] const std::optional<RrcConnectionSetupMessage> &Setup() const
    {
        return setup_;
    }
    [[nodiscard]] const Srb1ResolvedConfig &Configuration() const
    {
        return resolved_;
    }
    [[nodiscard]] const pdcp::SrbPdcpEntity &Pdcp() const
    {
        return pdcp_;
    }
    [[nodiscard]] const LteAmBearer *Srb1() const
    {
        return bearer_.get();
    }
    [[nodiscard]] const Srb1Evidence &Evidence() const
    {
        return evidence_;
    }
    [[nodiscard]] size_t RefusedFrames() const
    {
        return refused_;
    }
    void Release();

  private:
    void OnAccessAnswer(const uu::Frame &frame);
    void EstablishSrb1(const RrcConnectionSetupMessage &setup);

    uu::Socket &socket_;
    uint16_t enbPort_{0};
    Config config_{};
    // SRB0 is RLC TM: the SDU is the PDU. It is a real TM entity, not a
    // pass-through call, so the size limit applies here too.
    rlc::TmEntity srb0_;
    UeInitialAccess access_;
    RrcState state_{RrcState::RRC_IDLE};
    std::optional<RrcConnectionSetupMessage> setup_{};
    Srb1ResolvedConfig resolved_{};
    pdcp::SrbPdcpEntity pdcp_{};
    std::unique_ptr<LteAmBearer> bearer_{};
    Srb1Evidence evidence_{};
    uint16_t expectedAck_{0};
    size_t refused_{0};
};

// The eNB side keeps one pending context per association and refuses anything
// that does not belong to one.
class EnbSrb1Runtime
{
  public:
    struct Config
    {
        uint8_t expectedPlmnIdentity{1};
        uint8_t setupTransactionId{0};
        // The SRB1 AM configuration the eNB offers. It is mapped through the
        // same conversion the UE applies to the received message.
        RrcConnectionSetupMessage setup{};
    };

    using NasCallback = std::function<void(uint32_t association, const RrcConnectionSetupCompleteMessage &message)>;

    EnbSrb1Runtime(uu::Socket &socket, Config config, NasCallback onNas);

    void Pump(int timeoutMs);
    void Tick();

    [[nodiscard]] bool HasContext(uint32_t association) const;
    [[nodiscard]] size_t ContextCount() const
    {
        return contexts_.size();
    }
    [[nodiscard]] RrcState StateOf(uint32_t association) const;
    [[nodiscard]] size_t Deliveries(uint32_t association) const;
    [[nodiscard]] const std::vector<uint8_t> &DeliveredNas(uint32_t association) const;
    [[nodiscard]] const std::optional<RrcConnectionSetupCompleteMessage> &ReceivedOf(uint32_t association) const;
    [[nodiscard]] const Srb1ResolvedConfig &ConfigurationOf(uint32_t association) const;
    [[nodiscard]] const pdcp::SrbPdcpEntity *PdcpOf(uint32_t association) const;
    [[nodiscard]] const std::vector<std::vector<uint8_t>> &PdcpPdusOf(uint32_t association) const;
    [[nodiscard]] size_t RefusedFrames() const
    {
        return refused_;
    }
    [[nodiscard]] size_t RefusedSetupComplete() const
    {
        return refusedSetupComplete_;
    }

    void Release(uint32_t association) noexcept;

  private:
    struct Context
    {
        RrcState state{RrcState::RRC_IDLE};
        uint16_t peerPort{0};
        uint8_t transactionId{0};
        Srb1ResolvedConfig resolved{};
        pdcp::SrbPdcpEntity pdcp{};
        std::unique_ptr<LteAmBearer> bearer{};
        std::vector<std::vector<uint8_t>> pdcpPdus{};
        std::optional<RrcConnectionSetupCompleteMessage> received{};
        std::vector<uint8_t> deliveredNas{};
        size_t deliveries{0};
    };

    void OnRequestFrame(uint32_t association, const uu::Frame &frame, uint16_t sourcePort);
    void OnSrb1Frame(uint32_t association, const uu::Frame &frame);
    void OnPdcpPdu(Context &context, uint32_t association, const std::vector<uint8_t> &pdu);

    uu::Socket &socket_;
    Config config_{};
    NasCallback onNas_;
    // TM keeps no per-UE state, so one instance serves every association; the
    // association is checked by the runtime before this is reached.
    rlc::TmEntity srb0_;
    EnbInitialAccess access_{};
    std::map<uint32_t, Context> contexts_{};
    size_t refused_{0};
    size_t refusedSetupComplete_{0};
};

} // namespace lte::rrc
