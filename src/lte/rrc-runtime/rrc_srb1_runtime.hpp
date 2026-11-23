//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//

// Phase 18-F-B6-B2/B6-C: the LTE RRC connection runtime on SRB1.
//
// One UE and one eNB endpoint, each owning its RRC state, its SRB1 RLC AM
// entity and its SRB1 PDCP entity, exchanging real bytes over the simulated Uu:
//
//   RRC SDU -> PDCP -> RLC AM -> Uu -> RLC AM -> PDCP -> RRC decoder
//
// SRB0 (RRCConnectionRequest / Setup) still travels through RLC TM on CCCH. The
// SRB1 PDCP starts on the pre-security profile and switches to the B5 security
// profile when the AS Security Mode procedure runs; the entities that carry the
// SecurityModeCommand and the SecurityModeComplete are the ones that continue
// afterwards, so their COUNT is never reset.
#pragma once

#include "lte_am_bearer.hpp"
#include "rlc_tm.hpp"
#include "rrc_connection_setup_complete.hpp"
#include "rrc_information_transfer.hpp"
#include "rrc_initial_access.hpp"
#include "srb1_pdcp.hpp"
#include "srb1_rlc_config.hpp"
#include "uu_transport.hpp"

#include <lte/security/as_security_procedure.hpp>
#include <lte/security/enb_as_security_context.hpp>

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
    SECURITY_NOT_PREPARED,
    SECURITY_ALREADY_ACTIVE,
    SECURITY_REQUIRED,
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
    size_t uplinkNas{0};
    size_t downlinkNas{0};
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

    using NasCallback = std::function<void(const std::vector<uint8_t> &)>;

    UeSrb1Runtime(uu::Socket &socket, uint16_t enbPort, Config config);

    void StartAccess();
    void Pump(int timeoutMs);
    void Tick();

    // Encodes RRCConnectionSetupComplete, runs it through SRB1 PDCP and hands
    // the result to RLC AM. Reaches RRC_CONNECTED only when RLC acknowledges it.
    void SubmitSetupComplete(const std::vector<uint8_t> &nas);

    // Connected-mode NAS uplink: ULInformationTransfer through the current PDCP
    // profile (pre-security or secured).
    void SubmitNas(const std::vector<uint8_t> &nas);

    // The NAS layer telling the RRC layer that NAS security is active: the next
    // downlink SRB1 PDU is expected to carry an RRC SecurityModeCommand.
    void PrepareAsSecurity(const security::Key256 &kasme, uint32_t ulNasCount, uint64_t nasGeneration);

    [[nodiscard]] RrcState State() const
    {
        return state_;
    }
    [[nodiscard]] bool Srb1Established() const
    {
        return bearer_ != nullptr;
    }
    [[nodiscard]] bool AsSecurityActive() const;
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
    [[nodiscard]] const security::UeAsSecurityProcedure *SecurityProcedure() const
    {
        return procedure_.has_value() ? &*procedure_ : nullptr;
    }
    [[nodiscard]] const security::AsSecurityContext *SecurityContext() const
    {
        return asContext_.has_value() ? &*asContext_ : nullptr;
    }
    void SetNasCallback(NasCallback callback);
    void Release();

  private:
    void OnAccessAnswer(const uu::Frame &frame);
    void EstablishSrb1(const RrcConnectionSetupMessage &setup);
    void OnSrb1Pdu(std::vector<uint8_t> pdu);
    void OnRrc(const std::vector<uint8_t> &rrc);
    std::vector<uint8_t> Protect(const std::vector<uint8_t> &rrc);
    std::vector<uint8_t> Unprotect(const std::vector<uint8_t> &pdu);

    uu::Socket &socket_;
    uint16_t enbPort_{0};
    Config config_{};
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

    std::optional<security::AsSecurityContext> asContext_{};
    std::optional<security::UeAsSecurityProcedure> procedure_{};
    std::optional<security::PdcpSecurityEntity> secureTx_{};
    std::optional<security::PdcpSecurityEntity> secureRx_{};
    bool secured_{false};
    bool expectingCommand_{false};
    NasCallback onNas_{};
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
        RrcConnectionSetupMessage setup{};
    };

    using NasCallback = std::function<void(uint32_t association, const RrcConnectionSetupCompleteMessage &message)>;
    // Opaque connected-mode NAS, exactly as it arrives from the UE.
    using UplinkNasCallback = std::function<void(uint32_t association, const std::vector<uint8_t> &nas)>;

    EnbSrb1Runtime(uu::Socket &socket, Config config, NasCallback onNas);

    void Pump(int timeoutMs);
    void Tick();

    // DLInformationTransfer carrying an opaque NAS PDU, protected with whatever
    // profile the context is using.
    void SendDownlinkNas(uint32_t association, const std::vector<uint8_t> &nas);

    // Starts the RRC AS security procedure from the KeNB the MME sent. The
    // command is emitted on SRB1 and the context waits for the completion.
    void StartAsSecurity(uint32_t association, const security::Key256 &kenb,
                         const security::UeAlgorithmCapabilities &capabilities,
                         const security::AsAlgorithmConfiguration &configuration, uint64_t s1Generation,
                         uint8_t transactionId);

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
    [[nodiscard]] bool AsSecurityActive(uint32_t association) const;
    [[nodiscard]] const security::EnbAsSecurityContext *SecurityContextOf(uint32_t association) const;
    [[nodiscard]] security::AsSecurityState AsSecurityStateOf(uint32_t association) const;
    [[nodiscard]] size_t UplinkNasCount(uint32_t association) const;
    [[nodiscard]] size_t DownlinkNasCount(uint32_t association) const;
    [[nodiscard]] const std::vector<std::vector<uint8_t>> &UplinkNasOf(uint32_t association) const;
    [[nodiscard]] size_t RefusedFrames() const
    {
        return refused_;
    }
    [[nodiscard]] size_t RefusedSetupComplete() const
    {
        return refusedSetupComplete_;
    }
    [[nodiscard]] size_t RefusedRrc() const
    {
        return refusedRrc_;
    }
    void SetUplinkNasCallback(UplinkNasCallback callback);

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
        std::vector<std::vector<uint8_t>> uplinkNas{};
        size_t deliveries{0};
        size_t downlinkNas{0};

        std::optional<security::EnbAsSecurityContext> asContext{};
        std::optional<security::EnbAsSecurityProcedure> procedure{};
        std::optional<security::PdcpSecurityEntity> secureTx{};
        std::optional<security::PdcpSecurityEntity> secureRx{};
        bool secured{false};
    };

    void OnRequestFrame(uint32_t association, const uu::Frame &frame, uint16_t sourcePort);
    void OnSrb1Frame(uint32_t association, const uu::Frame &frame);
    void OnPdcpPdu(Context &context, uint32_t association, const std::vector<uint8_t> &pdu);
    void OnRrc(Context &context, uint32_t association, const std::vector<uint8_t> &rrc);
    std::vector<uint8_t> Protect(Context &context, const std::vector<uint8_t> &rrc);
    std::vector<uint8_t> Unprotect(Context &context, const std::vector<uint8_t> &pdu);

    uu::Socket &socket_;
    Config config_{};
    NasCallback onNas_;
    UplinkNasCallback onUplinkNas_;
    rlc::TmEntity srb0_;
    EnbInitialAccess access_{};
    std::map<uint32_t, Context> contexts_{};
    size_t refused_{0};
    size_t refusedSetupComplete_{0};
    size_t refusedRrc_{0};
};

} // namespace lte::rrc
