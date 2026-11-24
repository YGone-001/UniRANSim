//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#include "app.hpp"

#include "runtime_policy.hpp"

#include "lifecycle.hpp"
#include "bearer_runtime.hpp"
#include "nas.hpp"
#include "paging.hpp"
#include "radio_link.hpp"
#include "security.hpp"
#include "trigger.hpp"
#include "tun.hpp"
#include "uu_transport.hpp"

#include <algorithm>
#include <deque>
#include <chrono>
#include <iomanip>
#include <iostream>
#include <memory>
#include <optional>
#include <sstream>

#include <lte/enb/codec.hpp>
#include <lte/ip_packet.hpp>
#include <lte/rrc-runtime/drb_runtime.hpp>
#include <lte/security/as_security.hpp>
#include <lte/tft.hpp>

#include <lib/udp/server.hpp>

namespace lte::ue
{
namespace
{
void Log(const char *level, const std::string &message)
{
    std::cout << "[lte-ue] [" << level << "] " << message << std::endl;
}

void LogState(State state)
{
    Log("INFO", std::string("State=") + ToString(state));
}

// Which simulated-radio message type is valid where. The three uplink NAS
// routes are alternatives, not fallbacks of one another: no path ever swaps one
// for another after the fact.
//
//   NAS_UPLINK  every uplink NAS the MME already has an S1 UE context for:
//     Attach, Authentication and Security Mode, a standalone Normal or Periodic
//     Tracking Area Update, Detach, the ESM of a dedicated bearer activation or
//     modification, TAU Complete, and the retransmission of any of these.
//
//   NAS_UPLINK_MOBILITY_CONTEXT  the ECM-IDLE cell reselection bootstrap and
//     nothing else: the single uplink that opens a new S1 connection at a cell
//     whose UE registry is fresh, declaring beside its protected NAS the EPS
//     bearer identities that cell has to restore. Its retransmissions repeat
//     that exact frame while the new connection is still the one being opened,
//     and travel as NAS_UPLINK once the MME has established the S1 UE context.
//     There is no downgrade of this form to the legacy one.
//
//   NAS_UPLINK_MOBILITY  the identity-only ancestor of the form above. It stays
//     decodable for wire compatibility and is selected by no current UE
//     procedure: it declares no bearers, so a fresh target cannot restore from
//     it.
//
//   SERVICE_REQUEST  the compact four-octet EPS Service Request, used by a
//     Service Request and by the answer to a paging indication.
void SendNas(udp::UdpServer &socket, const InetAddress &enb, uint32_t ueId, std::vector<uint8_t> nas)
{
    auto frame = link::Encode({link::MessageType::NAS_UPLINK, ueId, std::move(nas)});
    socket.Send(enb, frame.data(), frame.size());
}

void SendServiceRequest(udp::UdpServer &socket, const InetAddress &enb, uint32_t ueId,
                        const std::array<uint8_t, 11> &guti, const std::vector<uint8_t> &nas)
{
    if (nas.size() != 4)
        throw std::runtime_error("Compact Service Request NAS must be four octets");
    std::vector<uint8_t> payload;
    payload.reserve(9);
    payload.push_back(guti[6]);
    payload.insert(payload.end(), guti.begin() + 7, guti.end());
    payload.insert(payload.end(), nas.begin(), nas.end());
    auto frame = link::Encode({link::MessageType::SERVICE_REQUEST, ueId, std::move(payload)});
    socket.Send(enb, frame.data(), frame.size());
}

// Protected uplink NAS that continues an existing EPS session over a new S1
// connection at a reselected cell. The frame carries the bearer inventory the
// target has to restore beside the protected NAS it has to deliver, and the
// identity prefix is derived from the UE's own valid GUTI, so the target eNB can
// address the Initial UE Message without the UE presenting any identifier the
// source cell allocated.
//
// The caller passes a frame that has already been built and validated: the
// declaration is encoded before a frame exists, so an inventory the wire cannot
// express is refused before anything is transmitted rather than after. Because
// the whole frame travels through here, a retransmission repeats the same
// message type, the same declaration bytes and the same protected NAS.
void SendMobilityNas(udp::UdpServer &socket, const InetAddress &enb, const link::Message &frame)
{
    const auto wire = link::Encode(frame);
    socket.Send(enb, wire.data(), wire.size());
}

// Verifies and recovers a security-protected downlink NAS message, then records
// the accepted DL COUNT. An unverified message never reaches the caller.
std::vector<uint8_t> ReceiveProtected(SecurityContext &security, const std::vector<uint8_t> &message)
{
    return nas::ReceiveProtectedDownlink(security, message);
}
} // namespace

int Run(const Config &config, const std::atomic_bool &shutdownRequested)
{
    State state = State::DISCONNECTED;
    SecurityContext security{};
    // Phase 18-F-B4: the UE-owned EPS AS security context (KeNB/NH/NCC). It is
    // created when NAS security activates, replaced when a fresh EPS AKA
    // replaces KASME, and destroyed on deregistration. It is never copied and
    // its key material never reaches a log or a provenance record.
    std::optional<lte::security::AsSecurityContext> asSecurity;
    uint64_t nasSecurityGeneration = 1;
    MobilityContext mobility{};
    bool attachAcceptSeen = false;
    bool defaultBearerAccepted = false;
    uint8_t activeEbi = 0;
    std::array<uint8_t, 4> assignedIpv4{};
    std::unique_ptr<TunDevice> tun;
    // Dedicated EPS bearers accepted on top of the default bearer. Each keeps
    // its own TFT so an uplink packet is routed by what the network selected,
    // never by a heuristic.
    nas::EpsBearerConfiguration defaultConfiguration;
    std::vector<DedicatedBearerRuntime> dedicatedBearers;
    uint64_t dedicatedUplinkPackets = 0;
    uint64_t dedicatedDownlinkPackets = 0;
    uint64_t tunUplinkPackets = 0;
    uint64_t tunUplinkBytes = 0;
    uint64_t tunDownlinkPackets = 0;
    uint64_t tunDownlinkBytes = 0;
    uint64_t malformedDrops = 0;
    uint64_t bearerInactiveDrops = 0;
    // Packets generated while no usable access transport exists. They are
    // dropped, counted and never buffered and never rerouted to another bearer.
    uint64_t accessUnavailableDrops = 0;
    // Unexpected S1-MME association loss bookkeeping. The UE keeps its EPS
    // registration and logical bearers; only access transport is invalidated.
    uint64_t accessLosses = 0;
    RestorationTrigger restorationTrigger;
    int recoveryAttempts = 0;
    uint64_t recoveryRestorations = 0;
    uint64_t recoveryFailures = 0;
    auto recoveryDeadline = std::chrono::steady_clock::time_point::max();
    bool scenarioTriggered = false;
    // Controlled idle periods already completed by this EPS registration. A
    // round ends when the access it opened has genuinely been restored, so the
    // rounds are consecutive epochs of one registration and never overlap.
    int scenarioRoundsDone = 0;
    bool idleReleaseRequested = false;
    std::vector<uint8_t> pendingWire;
    // The complete radio message an outstanding mobility uplink has to repeat.
    // It is frozen when it first leaves the UE, so a retransmission repeats the
    // same message type, the same declared bearer inventory and the same
    // protected NAS instead of rebuilding the declaration from bearer state
    // that may since have moved on. It is cleared the moment the MME has
    // established the S1 UE context and later repeats can travel as ordinary
    // uplink NAS transport.
    std::optional<link::Message> pendingMobilityFrame;
    int procedureRetries = 0;
    auto procedureDeadline = std::chrono::steady_clock::time_point::max();
    // Network-triggered paging bookkeeping. Nothing here can make the UE send a
    // Service Request on its own: only an accepted page does.
    bool pagingWaitArmed = false;
    auto pagingDeadline = std::chrono::steady_clock::time_point::max();
    uint64_t pagingIndications = 0;
    uint64_t pagingMatched = 0;
    uint64_t pagingIgnored = 0;
    uint64_t pagingSuppressed = 0;
    uint64_t pagingServiceRequests = 0;
    uint64_t pagingRestorations = 0;
    uint64_t pagingRestorationFailures = 0;
    udp::UdpServer socket(config.link.localAddress, config.link.localPort);
    if (config.link.receiveBufferBytes > 0)
    {
        // A request the kernel capped is refused here rather than reported as
        // applied: the operator asked for a budget this host cannot give.
        const auto status = socket.ConfigureReceiveBuffer(config.link.receiveBufferBytes);
        if (!status.applied)
            throw std::runtime_error("UE radio receive buffer was not applied: " + status.error);
        Log("INFO", "UE radio receive buffer: requested=" + std::to_string(status.requestedBytes) +
                        " effective=" + std::to_string(status.effectiveBytes) +
                        " usable=" + std::to_string(status.usableBytes));
    }
    InetAddress enb(config.link.enbAddress, config.link.enbPort);
    const uint32_t ueId = config.ueId;
    mobility.ecm = EcmState::CONNECTED;
    state = State::CONNECTED_TO_ENB;
    LogState(state);
    Log("INFO", "LTE UE " + std::to_string(ueId) + " using subscriber IMSI ..." + config.imsi.substr(config.imsi.size() - 4));

    // Phase 18-F-B6-D3: a configuration that states a Uu endpoint makes the
    // production UE carry its connected-mode NAS over SRB1. The transport owns
    // the RRC connection and the socket; this application keeps the NAS state
    // machine and the single downlink entry both transports deliver into.
    std::unique_ptr<UuNasTransport> uuTransport;
    std::deque<std::vector<uint8_t>> uuDownlink;
    // Phase 18-F-B6-D6: the DRB user plane of this UE. It exists only while a
    // Uu access is up; the rrc-prefixed DRB runtime owns the PDCP/RLC entities
    // and the DTCH routing. It is released on an RRC release and rebuilt from
    // the next RRCConnectionReconfiguration, with the keys of that access.
    std::unique_ptr<rrc::DrbRuntime> uuDrbs;
    uint64_t uuUplinkPackets = 0;
    uint64_t uuUplinkBytes = 0;
    uint64_t uuDownlinkPackets = 0;
    uint64_t uuDownlinkBytes = 0;
    uint64_t uuDrbDrops = 0;
    uint64_t uuDrbConfigurations = 0;
    bool uuUserPlaneReady = false;
    // Events the Uu runtime reports from inside Pump. They only set a flag; the
    // loop above RRC decides what they mean, so no application state is mutated
    // from inside the radio runtime.
    struct UuEvents
    {
        bool released{false};
        bool paging{false};
        uint8_t pageMmec{0};
        uint32_t pageMTmsi{0};
    } uuEvents;
    rrc::RrcState lastUuState = rrc::RrcState::RRC_IDLE;
    if (config.uu.enabled)
    {
        // The Attach exchange, the UE-initiated Detach and the ECM-IDLE access
        // restoration (Service Request / Paging) travel on the Uu path. Every
        // other lifecycle procedure still uses the legacy link, so a
        // configuration that names one is refused here rather than silently
        // mixing the two transports.
        const auto uuScenario = config.lifecycle.scenario;
        if (uuScenario != LifecycleScenario::ATTACH_ONLY && uuScenario != LifecycleScenario::DETACH &&
            uuScenario != LifecycleScenario::SERVICE_REQUEST && uuScenario != LifecycleScenario::PAGING)
            throw std::runtime_error("a Uu configuration supports the ATTACH_ONLY, ATTACH_DETACH, "
                                     "SERVICE_REQUEST and PAGING lifecycle scenarios only");
        UuEndpoint endpoint{config.uu.localAddress, config.uu.localPort, config.uu.enbAddress,
                            config.uu.enbPort};
        rrc::UeSrb1Runtime::Config rrcConfig{};
        rrcConfig.association = ueId;
        rrcConfig.mmec = 0;
        rrcConfig.mTmsi = ueId;
        rrcConfig.selectedPlmnIdentity = 1;
        uuTransport = std::make_unique<UuNasTransport>(endpoint, rrcConfig);
        // The callback only queues. The transport is pumped on this thread and
        // the queued NAS is handled by the loop, so no application state is
        // mutated from inside the RRC runtime.
        uuTransport->SetNasHandler([&uuDownlink](const std::vector<uint8_t> &nas) { uuDownlink.push_back(nas); });
        // A bind failure throws here: there is no fallback to the legacy link
        // and no substitution of a different address.
        uuTransport->SetReleaseHandler([&uuEvents]() { uuEvents.released = true; });
        uuTransport->SetPagingHandler([&uuEvents](uint8_t mmec, uint32_t mTmsi) {
            uuEvents.paging = true;
            uuEvents.pageMmec = mmec;
            uuEvents.pageMTmsi = mTmsi;
        });
        // Phase 18-F-B6-D6: the eNB configures the DRBs after the Initial
        // Context Setup has completed and AS security is active. The UE answers
        // with RRCConnectionReconfigurationComplete and then restates its PDN
        // address on the new DRBs, exactly as the accepted legacy and handover
        // confirmations do; the eNB never decrypts NAS to learn that address.
        uuTransport->SetDrbReconfigurationHandler([&](const rrc::DrbReconfiguration &configuration) {
            try
            {
                if (tun == nullptr)
                    throw std::runtime_error("DRB configuration received with no TUN");
                const auto *securityContext = uuTransport->SecurityContext();
                if (securityContext == nullptr || !securityContext->IsActive())
                    throw std::runtime_error("DRB configuration received before AS security is active");
                const auto keys = securityContext->DeriveAccessKeys();
                const auto algorithms = securityContext->Algorithms();
                if (!uuDrbs)
                    uuDrbs = std::make_unique<rrc::DrbRuntime>(
                        rlc::am::EndpointRole::UE, uuTransport->Association(),
                        [&](const std::vector<uint8_t> &payload) { return uuTransport->SendUserPlane(payload); },
                        [&](uint8_t, const std::vector<uint8_t> &ip) {
                            if (tun == nullptr)
                            {
                                ++uuDrbDrops;
                                return;
                            }
                            try
                            {
                                const auto ipv4 = ip::Validate(ip.data(), ip.size(),
                                                               static_cast<size_t>(config.tun.mtu));
                                if (ipv4.destination != assignedIpv4)
                                    throw ip::ValidationError(
                                        "DRB downlink destination does not match the assigned UE address");
                                if (tun->writePacket(ip.data(), ip.size()))
                                {
                                    ++tunDownlinkPackets;
                                    tunDownlinkBytes += ip.size();
                                    ++uuDownlinkPackets;
                                    uuDownlinkBytes += ip.size();
                                }
                            }
                            catch (const std::exception &e)
                            {
                                ++malformedDrops;
                                Log("WARN", std::string("Dropped invalid DRB downlink packet: ") + e.what());
                            }
                        });
                for (const auto &drb : configuration.drbs)
                {
                    if (uuDrbs->HasBearer(drb.ebi))
                        continue;
                    rrc::DrbBearerConfig bearer;
                    bearer.ebi = drb.ebi;
                    bearer.drbIdentity = drb.drbIdentity;
                    bearer.am = drb.am;
                    bearer.cipheringAlgorithm = algorithms.upCiphering;
                    bearer.kUpEnc = keys.kUpEnc;
                    if (!uuDrbs->AddBearer(bearer))
                        throw std::runtime_error("the DRB bearer could not be established");
                    if (drb.ebi != activeEbi)
                    {
                        const auto dedicated = std::find_if(dedicatedBearers.begin(), dedicatedBearers.end(),
                                                            [&](const auto &candidate) {
                                                                return candidate.ebi == drb.ebi;
                                                            });
                        if (dedicated != dedicatedBearers.end())
                            dedicated->accessReady = true;
                    }
                }
                uuTransport->SubmitReconfigurationComplete(configuration.transactionId);
                ++uuDrbConfigurations;
                for (const auto &drb : configuration.drbs)
                {
                    rrc::DrbReady ready;
                    ready.ebi = drb.ebi;
                    ready.generation = mobility.accessGeneration;
                    ready.ipv4 = assignedIpv4;
                    if (!uuDrbs->SendReady(ready))
                        throw std::runtime_error("the DRB ready confirmation could not be sent");
                }
                state = State::USER_PLANE_ACTIVE;
                LogState(state);
                Log("INFO", "DRB user plane configured for EBI(s)=" + [&] {
                    std::ostringstream list;
                    for (size_t i = 0; i < configuration.drbs.size(); ++i)
                    {
                        if (i != 0)
                            list << ',';
                        list << static_cast<int>(configuration.drbs[i].ebi);
                    }
                    return list.str();
                }() + " generation=" + std::to_string(mobility.accessGeneration) +
                                " IPv4 " + Ipv4ToString(assignedIpv4));
            }
            catch (const std::exception &e)
            {
                ++uuDrbDrops;
                Log("ERROR", std::string("DRB configuration failed: ") + e.what());
            }
        });
        uuTransport->SetUserPlaneHandler([&](const uu::Frame &frame) {
            if (uuDrbs == nullptr)
            {
                ++uuDrbDrops;
                return;
            }
            if (!uuDrbs->OnFrame(frame))
                ++uuDrbDrops;
        });
        uuTransport->Start();
        Log("INFO", "Uu SRB1 transport started on " + config.uu.localAddress + ":" +
                        std::to_string(uuTransport->LocalPort()) + " towards " + config.uu.enbAddress + ":" +
                        std::to_string(config.uu.enbPort));
    }

    // The one uplink NAS interface. A refusal is reported to the caller and is
    // never retried over another transport.
    auto sendNas = [&](const std::vector<uint8_t> &nas) -> bool {
        if (uuTransport)
            return uuTransport->SendNas(nas);
        SendNas(socket, enb, ueId, nas);
        return true;
    };
    // Protects and sends, and fails loudly: a state machine that advanced past
    // a message it never sent would invent an outcome.
    auto sendProtected = [&](bool newContext, const std::vector<uint8_t> &plain) {
        auto protectedMessage = nas::Protect(security, true, newContext, plain);
        if (!sendNas(protectedMessage))
            throw std::runtime_error("the uplink NAS transport refused a protected NAS message");
        security.ulNasCount = (security.ulNasCount + 1U) & 0xFFFFFFU;
    };
    mobility.beginNewAttach();
    auto attach = nas::EncodeAttachRequest(config);
    // In Uu mode the Attach Request is the first NAS message and may only leave
    // once the RRC connection exists; the loop retries SendNas until the
    // transport accepts it. The legacy form sends it immediately, as before.
    bool initialAttachSent = false;
    if (!uuTransport)
    {
        SendNas(socket, enb, ueId, attach);
        initialAttachSent = true;
        state = State::ATTACH_REQUEST_SENT;
        LogState(state);
    }
    else
    {
        Log("INFO", "The Attach Request waits for the RRC connection before it is sent");
    }
    state = State::AUTHENTICATION_PENDING;
    LogState(state);

    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(config.link.timeoutMs);
    auto scenarioDeadline = std::chrono::steady_clock::time_point::max();

    // The single NAS downlink entry. The legacy link and the Uu transport both
    // deliver here; the application has one NAS state machine, not two. The
    // return value is a process exit code when the message ended the run.
    auto handleNasDownlink = [&](const std::vector<uint8_t> &nasPayload) -> std::optional<int>
    {
        if (!security.securityActive)
        {
                    // Only a Security Mode Command may arrive before the context is active.
                    if (!nas::IsSecurityModeCommand(nasPayload.data(), nasPayload.size()))
                    {
                        // Authentication Request is still plain EMM.
                        if (state == State::AUTHENTICATION_PENDING || state == State::AUTHENTICATION_RESPONSE_SENT ||
                            state == State::EPS_AKA_ACCEPTED)
                        {
                            if (state == State::EPS_AKA_ACCEPTED)
                                throw nas::DecodeError("Plain NAS received after EPS AKA acceptance");
                        }
                        else
                            throw nas::DecodeError("Unexpected plain NAS message before security activation");

                        auto request = nas::DecodeAuthenticationRequest(nasPayload.data(), nasPayload.size());
                        state = State::AUTHENTICATION_REQUEST_RECEIVED;
                        LogState(state);
                        auto result = nas::Authenticate(config, request);
                        if (result.failure != nas::AkaFailure::NONE)
                        {
                            state = State::AUTHENTICATION_FAILED;
                            LogState(state);
                            if (result.failure == nas::AkaFailure::MAC_FAILURE)
                            {
                                Log("ERROR",
                                    "AUTN MAC verification failed; returning EPS Authentication Failure (MAC failure)");
                                if (!sendNas(nas::EncodeAuthenticationFailureMac()))
                                throw std::runtime_error(
                                    "the uplink NAS transport refused the Authentication Failure");
                            }
                            else if (result.failure == nas::AkaFailure::SYNCHRONIZATION_FAILURE)
                                Log("ERROR", "AUTN SQN is stale; AUTS resynchronization is unsupported, failing closed");
                            else
                                Log("ERROR", "Authentication Request processing failed");
                            return 1;
                        }
                        // A fresh EPS AKA replaces KASME, so the AS context that
                        // was derived from the old one is worthless.
                        asSecurity.reset();
                        nasSecurityGeneration++;
                        security = result.context;
                        // Record the exact UE security capability octets that went
                        // out in the Attach Request so the SMC replay check can use
                        // them (TS 24.301 5.4.3.3).
                        security.advertisedSecurityCapabilities.assign(config.networkCapability.begin(),
                                                                        config.networkCapability.end());
                        if (!sendNas(nas::EncodeAuthenticationResponse(result.res)))
                            throw std::runtime_error(
                                "the uplink NAS transport refused the Authentication Response");
                        state = State::AUTHENTICATION_RESPONSE_SENT;
                        LogState(state);
                        return std::nullopt;
                    }

                    // Security Mode Command: header type 3, integrity protected with the
                    // new context and not ciphered, so the IEs are readable in the clear.
                    if (!security.valid)
                        throw nas::DecodeError("Security Mode Command received before a valid AKA response");
                    auto parsed = nas::ParseProtectedHeader(nasPayload.data(), nasPayload.size());
                    if (parsed.headerType != nas::SecurityHeaderType::INTEGRITY_PROTECTED_WITH_NEW_CONTEXT)
                        throw nas::DecodeError("Security Mode Command must use the new EPS security context header");
                    auto command = nas::DecodeSecurityModeCommand(parsed.plain.data(), parsed.plain.size());
                    nas::ValidateSecurityModeCommand(config, command, security);
                    security.kNasInt = nas::DeriveKnasInt(security.kasme, security.integrity);
                    security.kNasEnc = nas::DeriveKnasEnc(security.kasme, security.ciphering);
                    security.keysDerived = true;
                    // MAC verification is mandatory before the context becomes active.
                    nas::UnprotectBody(security, false, parsed.headerType, parsed.sequenceNumber, parsed.mac,
                                       parsed.plain);
                    security.dlNasCount = parsed.sequenceNumber;
                    security.ulNasCount = 0;
                    security.securityActive = true;
                    mobility.securityContextValid = true;
                    state = State::SECURITY_MODE_COMMAND_RECEIVED;
                    LogState(state);
                    Log("INFO", std::string("NAS security activated: ") + nas::ToString(security.integrity) + "/" +
                                    nas::ToString(security.ciphering) + " KSI=" + std::to_string(security.ksi));
                    state = State::NAS_SECURITY_ACTIVE;
                    LogState(state);

                    // TS 33.401 7.2.1: the uplink NAS COUNT that activates AS
                    // security is the one the Security Mode Complete travels with.
                    // It is read before the send advances the COUNT.
                    const uint32_t securityModeCompleteCount = security.ulNasCount;
                    sendProtected(true,
                                  nas::EncodeSecurityModeComplete(config, command.imeisvRequested));
                    if (uuTransport)
                    {
                        // The next downlink SRB1 PDU is the RRC SecurityModeCommand,
                        // so the RRC runtime is told the same KASME and the uplink
                        // NAS COUNT this Security Mode Complete travelled with. The
                        // eNB derives its KeNB from the MME's Initial Context Setup
                        // key at that COUNT; the two must name the same key.
                        uuTransport->PrepareAsSecurity(security.kasme, securityModeCompleteCount,
                                                       nasSecurityGeneration);
                        Log("INFO", "RRC AS security prepared from KASME at uplink NAS COUNT " +
                                        std::to_string(securityModeCompleteCount));
                    }
                    else
                    {
                        // No RRC security mode procedure exists in this simulator,
                        // so no AS algorithm has been selected. The context is built
                        // with that stated, and it refuses to derive RRC/UP keys
                        // rather than reusing the NAS selection in a role the
                        // standard gives to a different procedure.
                        lte::security::AsAlgorithmSet algorithms;
                        algorithms.negotiated = false;
                        asSecurity.emplace(lte::security::AsSecurityContext::Create(
                            static_cast<uint32_t>(ueId), security.kasme, securityModeCompleteCount,
                            nasSecurityGeneration, algorithms));
                        Log("INFO", "EPS AS security context established: " + asSecurity->Describe());
                    }
                    state = State::SECURITY_MODE_COMPLETE_SENT;
                    LogState(state);
                    return std::nullopt;
                }

                // A network without a matching security context may return a plain
                // Service Reject. It can only fail a pending Service Request; it
                // never updates trusted mobility state. Every other downlink after
                // security activation must verify integrity.
                std::vector<uint8_t> plain;
                if (mobility.pending == PendingProcedure::SERVICE_REQUEST && nasPayload.size() >= 3 &&
                    nasPayload[0] == 0x07 && nasPayload[1] == 0x4E)
                {
                    plain = nasPayload;
                    Log("WARN", "Received unprotected Service Reject while restoring a released context");
                }
                else
                    plain = ReceiveProtected(security, nasPayload);
                // Handle C9 here so a malformed optional IE still receives a
                // protected Reject using the authenticated EBI/PTI header.
                if (plain.size() >= 3 && (plain[0] & 15U) == 2 && plain[2] == 0xC9)
                {
                    const uint8_t ebi = plain[0] >> 4U, pti = plain[1];
                    uint8_t cause = 0;
                    std::string error;
                    nas::EpsBearerConfiguration *target = nullptr;
                    nas::EpsBearerConfiguration candidate;
                    try
                    {
                        if (mobility.emm != EmmState::REGISTERED || mobility.ecm != EcmState::CONNECTED ||
                            mobility.pending != PendingProcedure::NONE)
                            throw nas::EsmError(101, "Bearer modification conflicts with mobility state");
                        const auto request = nas::DecodeModifyEpsBearerContextRequest(plain.data(), plain.size());
                        if (ebi == activeEbi)
                            target = &defaultConfiguration;
                        else
                            for (auto &bearer : dedicatedBearers)
                                if (bearer.ebi == ebi)
                                    target = &bearer;
                        if (!target)
                            throw nas::EsmError(43, "Unknown EPS bearer");
                        candidate = *target;
                        nas::ApplyBearerModification(candidate, request);
                    }
                    catch (const nas::EsmError &e)
                    {
                        cause = e.cause;
                        error = e.what();
                    }
                    catch (const std::bad_alloc &)
                    {
                        cause = 26;
                        error = "Insufficient local resources";
                    }
                    if (cause)
                    {
                        sendProtected(false,
                                      nas::EncodeModifyEpsBearerContextReject(ebi, pti, cause));
                        Log("WARN", "Modify EPS bearer rejected EBI=" + std::to_string(ebi) +
                                        " cause=" + std::to_string(cause) + ": " + error);
                    }
                    else
                    {
                        sendProtected(false,
                                      nas::EncodeModifyEpsBearerContextAccept(ebi, pti));
                        *target = std::move(candidate);
                        Log("INFO", "Modify EPS bearer accepted EBI=" + std::to_string(ebi) +
                                        " PTI=" + std::to_string(pti) + " QCI=" + std::to_string(target->qci) +
                                        " filters=" + std::to_string(target->tft.size()) +
                                        " UL-COUNT-next=" + std::to_string(security.ulNasCount) +
                                        " DL-COUNT=" + std::to_string(security.dlNasCount));
                    }
                    return std::nullopt;
                }
                auto downlink = nas::DecodeDownlink(plain.data(), plain.size());

                if (downlink.type == nas::DownlinkEmm::ACTIVATE_DEDICATED_EPS_BEARER_CONTEXT)
                {
                    const auto &request = downlink.dedicatedBearer;
                    try
                    {
                        if (mobility.emm != EmmState::REGISTERED || mobility.ecm != EcmState::CONNECTED ||
                            mobility.pending != PendingProcedure::NONE)
                            throw nas::DecodeError("Dedicated bearer activation conflicts with mobility state");
                        if (request.linkedEpsBearerIdentity != activeEbi)
                            throw nas::DecodeError("Dedicated bearer references a different default bearer");
                        for (const auto &bearer : dedicatedBearers)
                        {
                            if (bearer.ebi == request.epsBearerIdentity)
                                throw nas::DecodeError("Dedicated bearer identity is already active");
                        }
                        if (dedicatedBearers.size() >= 7)
                            throw nas::DecodeError("Dedicated bearer capacity is exhausted");

                        DedicatedBearerRuntime bearer;
                        bearer.ebi = request.epsBearerIdentity;
                        bearer.qci = request.qci;
                        bearer.linkedEbi = request.linkedEpsBearerIdentity;
                        bearer.epsQos = {request.qci};
                        if (!request.tft.empty())
                            bearer.tft.apply(lte::tft::Decode(request.tft.data(), request.tft.size()));

                        dedicatedBearers.push_back(std::move(bearer));
                        sendProtected(false,
                                      nas::EncodeActivateDedicatedEpsBearerContextAccept(
                                          request.epsBearerIdentity, request.procedureTransactionId));

                        std::vector<uint8_t> activated{request.epsBearerIdentity};
                        auto activatedFrame =
                            link::Encode({link::MessageType::BEARER_ACTIVATED, ueId, std::move(activated)});
                        socket.Send(enb, activatedFrame.data(), activatedFrame.size());

                        Log("INFO", "Dedicated EPS bearer " + std::to_string(request.epsBearerIdentity) +
                                        " activated (QCI=" + std::to_string(request.qci) + ", linked-EBI=" +
                                        std::to_string(request.linkedEpsBearerIdentity) + ", filters=" +
                                        std::to_string(dedicatedBearers.back().tft.size()) + ")");
                    }
                    catch (const std::exception &e)
                    {
                        // Reject with insufficient resources and keep every other
                        // bearer untouched; a failed activation must not disturb the
                        // default bearer.
                        sendProtected(false,
                                      nas::EncodeActivateDedicatedEpsBearerContextReject(
                                          request.epsBearerIdentity, request.procedureTransactionId, 26));
                        Log("WARN", std::string("Rejected dedicated EPS bearer activation: ") + e.what());
                    }
                    return std::nullopt;
                }

                if (downlink.type == nas::DownlinkEmm::DEACTIVATE_EPS_BEARER_CONTEXT)
                {
                    const auto &request = downlink.deactivateBearer;
                    const auto bearer = std::find_if(dedicatedBearers.begin(), dedicatedBearers.end(),
                                                     [&request](const DedicatedBearerRuntime &candidate) {
                                                         return candidate.ebi == request.epsBearerIdentity;
                                                     });
                    if (bearer == dedicatedBearers.end())
                        throw nas::DecodeError("Deactivation names an unknown dedicated bearer");
                    dedicatedBearers.erase(bearer);
                    sendProtected(false,
                                  nas::EncodeDeactivateEpsBearerContextAccept(request.epsBearerIdentity,
                                                                              request.procedureTransactionId));
                    Log("INFO", "Dedicated EPS bearer " + std::to_string(request.epsBearerIdentity) +
                                    " deactivated; default bearer retained");
                    return std::nullopt;
                }

                if (downlink.type == nas::DownlinkEmm::DETACH_ACCEPT)
                {
                    if (mobility.pending != PendingProcedure::DETACH)
                        throw nas::DecodeError("Unexpected EPS Detach Accept");
                    // The legacy notification is addressed to the legacy eNB. In Uu
                    // mode the eNB is the peer that accepted the Detach, and the
                    // S1 release that follows a Detach is the MME's decision, not a
                    // message this UE may invent on another transport.
                    if (!uuTransport)
                    {
                        auto deleted = link::Encode({link::MessageType::EPS_SESSION_DELETED, ueId,
                            link::EncodeBearerRestoration(activeEbi, mobility.accessGeneration)});
                        socket.Send(enb, deleted.data(), deleted.size());
                    }
                    mobility.onDetachAccepted();
                    if (asSecurity)
                    {
                        asSecurity->Reset();
                        asSecurity.reset();
                    }
                    security = SecurityContext{};
                    pendingWire.clear();
                    tun.reset();
                    dedicatedBearers.clear();
                    defaultConfiguration = {};
                    Log("INFO", "EPS Detach accepted; State=EMM_DEREGISTERED, bearer and TUN released");
                    if (uuTransport)
                        Log("INFO", "The Uu SRB1 transport is released with the process after the Detach");
                    return 0;
                }
                if (downlink.type == nas::DownlinkEmm::SERVICE_REJECT)
                {
                    mobility.onProcedureRejected();
                    Log("ERROR", "EPS Service Request rejected, EMM cause=" + std::to_string(downlink.emmCause));
                    return 1;
                }
                if (downlink.type == nas::DownlinkEmm::TAU_REJECT)
                {
                    mobility.onProcedureRejected();
                    Log("ERROR", "Tracking Area Update rejected, EMM cause=" + std::to_string(downlink.emmCause));
                    return 1;
                }
                if (downlink.type == nas::DownlinkEmm::TAU_ACCEPT)
                {
                    if (mobility.pending != PendingProcedure::TAU_NORMAL &&
                        mobility.pending != PendingProcedure::TAU_PERIODIC)
                        throw nas::DecodeError("Unexpected Tracking Area Update Accept");
                    // The Accept is one NAS message carrying several independent
                    // assignments. It is applied as one validated step, so an
                    // Accept that is malformed in any one of them cannot leave the
                    // bearer set, the GUTI or the tracking areas half-changed
                    // behind a rejected update.
                    const auto acceptance = ApplyTauAccept(mobility, dedicatedBearers, downlink.tauAccept);
                    for (const uint8_t ebi : acceptance.releasedDedicated)
                        Log("INFO", "Dedicated EPS bearer " + std::to_string(ebi) +
                                        " was not retained by the network and is no longer active");
                    pendingWire.clear();
                    pendingMobilityFrame.reset();
                    if (acceptance.completeRequired)
                        sendProtected(false, nas::EncodeTauComplete());
                    Log("INFO", std::string("Tracking Area Update accepted; context preserved") +
                                    (acceptance.completeRequired ? "; TAU Complete sent for new GUTI" : ""));
                    scenarioDeadline = std::chrono::steady_clock::time_point::max();
                    return std::nullopt;
                }

                if (downlink.type == nas::DownlinkEmm::ESM_INFORMATION_REQUEST)
                {
                    state = State::ESM_INFORMATION_REQUEST_RECEIVED;
                    LogState(state);
                    sendProtected(false,
                                  nas::EncodeEsmInformationResponse(downlink.esmInformationRequest.procedureTransactionId,
                                                                   downlink.esmInformationRequest.apn));
                    state = State::ESM_INFORMATION_RESPONSE_SENT;
                    LogState(state);
                    return std::nullopt;
                }

                if (downlink.type == nas::DownlinkEmm::ATTACH_REJECT)
                {
                    state = State::PROCEDURE_FAILED;
                    LogState(state);
                    Log("ERROR", "EPS Attach rejected by the MME, EMM cause=" + std::to_string(downlink.emmCause));
                    return 1;
                }

                if (downlink.type != nas::DownlinkEmm::ATTACH_ACCEPT)
                {
                    Log("WARN", "Ignoring unexpected protected EMM message type " +
                                   std::to_string(downlink.messageType));
                    return std::nullopt;
                }

                if (!attachAcceptSeen)
                {
                    attachAcceptSeen = true;
                    state = State::ATTACH_ACCEPT_RECEIVED;
                    LogState(state);
                }

                const auto &accept = downlink.attachAccept;
                if (!accept.bearer.has_value())
                    throw nas::DecodeError("Attach Accept did not carry Activate Default EPS Bearer Context Request");
                if (defaultBearerAccepted)
                    throw nas::DecodeError("Duplicate Activate Default EPS Bearer Context Request");
                defaultBearerAccepted = true;
                state = State::DEFAULT_BEARER_PENDING;
                LogState(state);
                Log("INFO", "Default EPS bearer: EBI=" + std::to_string(accept.bearer->epsBearerIdentity) +
                                " QCI=" + std::to_string(accept.bearer->qci) + " APN=" + accept.bearer->apn);

                auto esmAccept = nas::EncodeActivateDefaultEpsBearerContextAccept(
                    accept.bearer->epsBearerIdentity, accept.bearer->procedureTransactionId);
                sendProtected(false, nas::EncodeAttachComplete(esmAccept));
                state = State::ATTACH_COMPLETE_SENT;
                LogState(state);
                state = State::EPS_REGISTERED;
                LogState(state);
                state = State::DEFAULT_BEARER_SIGNALING_COMPLETE;
                LogState(state);

                activeEbi = accept.bearer->epsBearerIdentity;
                defaultConfiguration.ebi = activeEbi;
                defaultConfiguration.qci = accept.bearer->qci;
                defaultConfiguration.epsQos = {accept.bearer->qci};
                assignedIpv4 = accept.bearer->pdnAddress;
                if (assignedIpv4 == std::array<uint8_t, 4>{})
                    throw nas::DecodeError("Default bearer did not provide a supported non-zero IPv4 PDN address");
                mobility.onAttachComplete(activeEbi, assignedIpv4, accept.guti, accept.taiList, accept.t3412);
                mobility.securityContextValid = security.securityActive;
                if (uuTransport && mobility.guti.has_value())
                {
                    // TS 36.331 5.3.3: after the Attach the UE uses the S-TMSI
                    // the MME assigned. It is the identity a later page names.
                    if (const auto assigned = STmsiFromGuti(*mobility.guti); assigned.has_value())
                    {
                        uuTransport->SetIdentity(assigned->mmeCode, assigned->mTmsi);
                        Log("INFO", "Uu identity set to the assigned S-TMSI (MMEC=" +
                                        std::to_string(assigned->mmeCode) + ", M-TMSI=0x" + [&] {
                                            std::ostringstream value;
                                            value << std::hex << std::uppercase << std::setw(8)
                                                  << std::setfill('0') << assigned->mTmsi;
                                            return value.str();
                                        }() + ")");
                    }
                }
                {
                    std::ostringstream taiText;
                    for (size_t i = 0; i < mobility.taiList.size(); ++i)
                    {
                        if (i != 0)
                            taiText << ',';
                        taiText << mobility.taiList[i].plmn.toString() << '/' << mobility.taiList[i].tac;
                    }
                    std::string sTmsiText = "none";
                    if (mobility.guti.has_value())
                    {
                        const auto derived = STmsiFromGuti(*mobility.guti);
                        if (derived.has_value())
                        {
                            std::ostringstream sTmsi;
                            sTmsi << "MMEC=" << static_cast<int>(derived->mmeCode) << " M-TMSI=0x" << std::hex
                                  << std::uppercase << std::setw(8) << std::setfill('0') << derived->mTmsi;
                            sTmsiText = sTmsi.str();
                        }
                    }
                    Log("INFO", "Assigned EPS bearer EBI=" + std::to_string(activeEbi) + " IPv4=" +
                                    Ipv4ToString(assignedIpv4) + " S-TMSI{" + sTmsiText + "} TAI-list=" +
                                    taiText.str());
                }
                try { tun = std::make_unique<TunDevice>(config.tun, assignedIpv4); }
                catch (const std::exception &e)
                {
                    if (config.tun.required) throw;
                    Log("WARN", std::string("Control-plane-only mode: LTE TUN unavailable: ") + e.what());
                }
                if (tun)
                {
                    state = State::TUN_READY;
                    LogState(state);
                    Log("INFO", "LTE TUN " + tun->name() + " configured with " + Ipv4ToString(assignedIpv4) +
                                    "/32 MTU=" + std::to_string(config.tun.mtu) +
                                    " explicit-routes=" + std::to_string(config.tun.routes.size()));

                    if (uuTransport)
                    {
                        // The user plane of a Uu UE is established by the DRB
                        // configuration the eNB sends after the Initial Context
                        // Setup. The legacy bearer-ready frame belongs to the
                        // software-radio link and is never sent from here.
                        Log("INFO", "Waiting for the RRC DRB configuration; the legacy bearer-ready frame is not "
                                        "used on the Uu path");
                    }
                    else
                    {
                        std::vector<uint8_t> ready{activeEbi, assignedIpv4[0], assignedIpv4[1], assignedIpv4[2],
                                                   assignedIpv4[3]};
                        auto readyFrame = link::Encode({link::MessageType::BEARER_READY, ueId, std::move(ready)});
                        if (!socket.TrySend(enb, readyFrame.data(), readyFrame.size()))
                            throw std::runtime_error("LTE bearer-ready frame could not be sent");
                        state = State::USER_PLANE_ACTIVE;
                        LogState(state);
                        mobility.onUserPlaneReady();
                    }
                }
                scenarioDeadline = std::chrono::steady_clock::now() +
                                   std::chrono::milliseconds(config.lifecycle.triggerAfterMs);
                Log("INFO", tun ? "EPS Attach complete; persistent IPv4 user plane is active"
                                 : "EPS Attach complete; bearer signaling active without local user plane");
                return std::nullopt;
    };

    auto deliverNas = [&](const std::vector<uint8_t> &nas) -> std::optional<int> {
        try
        {
            return handleNasDownlink(nas);
        }
        catch (const nas::SecurityError &e)
        {
            if (mobility.emm == EmmState::REGISTERED)
            {
                ++malformedDrops;
                Log("WARN", std::string("Dropped unauthenticated/replayed NAS: ") + e.what());
                return std::nullopt;
            }
            state = State::PROCEDURE_FAILED;
            LogState(state);
            Log("ERROR", std::string("NAS security failure: ") + e.what());
            return 1;
        }
        catch (const std::exception &e)
        {
            if (mobility.emm == EmmState::REGISTERED &&
                state != State::DEFAULT_BEARER_SIGNALING_COMPLETE && state != State::TUN_READY)
            {
                ++malformedDrops;
                Log("WARN", std::string("Dropped invalid LTE radio-link message: ") + e.what());
                return std::nullopt;
            }
            state = State::PROCEDURE_FAILED;
            LogState(state);
            Log("ERROR", e.what());
            return 1;
        }
    };
    // ECM-IDLE access restoration bookkeeping. Only the Uu scenarios use it;
    // the legacy idle path keeps its own S1 release request.
    bool uuIdle = false;
    bool uuSrArmed = false;
    bool uuSrSent = false;
    bool uuRestored = false;
    uint32_t uuServiceRequestCount = 0;
    auto uuTriggerDeadline = std::chrono::steady_clock::time_point::max();
    auto uuPagingDeadline = std::chrono::steady_clock::time_point::max();
    auto uuDeadline = std::chrono::steady_clock::time_point::max();
    uint8_t buffer[link::MaxDataPduSize + link::HeaderSize];
    while (!shutdownRequested && (mobility.emm == EmmState::REGISTERED || std::chrono::steady_clock::now() < deadline))
    {
        const auto now = std::chrono::steady_clock::now();

        if (uuTransport)
        {
            uuTransport->Pump(0);
            uuTransport->Tick();
            if (!initialAttachSent && uuTransport->SendNas(attach))
            {
                initialAttachSent = true;
                state = State::ATTACH_REQUEST_SENT;
                LogState(state);
                state = State::AUTHENTICATION_PENDING;
                LogState(state);
            }
            if (uuTransport->State() != lastUuState)
            {
                lastUuState = uuTransport->State();
                Log("INFO", std::string("Uu RRC state=") + rrc::ToString(lastUuState));
            }
            while (!uuDownlink.empty())
            {
                auto nas = std::move(uuDownlink.front());
                uuDownlink.pop_front();
                if (auto outcome = deliverNas(nas))
                    return *outcome;
            }

            if (uuEvents.released)
            {
                uuEvents.released = false;
                if (mobility.emm == EmmState::REGISTERED)
                {
                    // TS 23.401 5.3.5: ECM-IDLE keeps the EPS registration and
                    // the NAS security context. Only the access is gone, and
                    // with it the DRB, PDCP and RLC entities that carried this
                    // access. The EPS bearer context and the TUN address stay.
                    if (uuDrbs != nullptr)
                    {
                        Log("INFO", "Releasing the DRB user plane of the released access after " +
                                        std::to_string(uuUplinkPackets) + " UL / " +
                                        std::to_string(uuDownlinkPackets) + " DL DRB packets");
                        uuDrbs.reset();
                    }
                    uuUserPlaneReady = false;
                    const bool wasConnected = mobility.ecm == EcmState::CONNECTED;
                    mobility.onS1ContextReleased();
                    // The RRC release is not the simulator's generation-bound
                    // release frame, so the UE advances its own access epoch in
                    // step with the eNB, which advances when this access carried
                    // a confirmed bearer transport. A duplicate release of an
                    // access that already ended advances nothing.
                    if (wasConnected)
                        mobility.advanceAccessGeneration();
                    uuIdle = true;
                    pendingWire.clear();
                    state = State::EPS_REGISTERED;
                    LogState(state);
                    Log("INFO", "RRC connection released by the network; EMM-REGISTERED and the NAS security "
                                    "context are preserved (ECM-IDLE)");
                    if (config.lifecycle.scenario == LifecycleScenario::PAGING)
                        uuPagingDeadline = now + std::chrono::milliseconds(config.lifecycle.pagingWaitMs);
                }
            }

            if (uuEvents.paging)
            {
                const uint8_t mmec = uuEvents.pageMmec;
                const uint32_t mTmsi = uuEvents.pageMTmsi;
                uuEvents.paging = false;
                if (uuIdle && config.lifecycle.scenario == LifecycleScenario::PAGING && !uuSrArmed)
                {
                    std::ostringstream page;
                    page << "PCCH Paging matched the UE identity (MMEC=" << static_cast<int>(mmec)
                         << " M-TMSI=0x" << std::hex << std::uppercase << std::setw(8) << std::setfill('0')
                         << mTmsi << std::dec << ")";
                    Log("INFO", page.str());
                    uuTriggerDeadline = now;
                }
                else
                    Log("WARN", "Ignoring a Paging indication that does not match an idle UE state");
            }

            if (uuIdle && !uuSrArmed &&
                (config.lifecycle.scenario == LifecycleScenario::SERVICE_REQUEST ||
                 config.lifecycle.scenario == LifecycleScenario::PAGING) &&
                now >= uuTriggerDeadline)
            {
                mobility.startServiceRequest();
                pendingWire = nas::EncodeServiceRequest(security);
                uuServiceRequestCount = security.ulNasCount & 0xFFFFFFU;
                // A new RRC connection is established; the Service Request is
                // its first NAS message and travels in SetupComplete.
                uuTransport->ResumeAccess();
                uuSrArmed = true;
                uuDeadline = now + std::chrono::milliseconds(config.lifecycle.procedureTimeoutMs);
                Log("INFO", "ECM-IDLE access restoration: RRC connection establishment started for the Service "
                                "Request");
            }

            if (uuSrArmed && !uuSrSent && uuTransport->State() == rrc::RrcState::RRC_SRB1_CONFIGURING)
            {
                // TS 33.401 7.2.1: the KeNB follows the uplink NAS COUNT the
                // Service Request travels with.
                uuTransport->PrepareAsSecurity(security.kasme, uuServiceRequestCount, nasSecurityGeneration);
                if (!uuTransport->SendNas(pendingWire))
                {
                    state = State::PROCEDURE_FAILED;
                    LogState(state);
                    Log("ERROR", "The uplink NAS transport refused the EPS Service Request");
                    return 1;
                }
                {
                    std::ostringstream request;
                    request << "EPS Service Request sent in RRCConnectionSetupComplete: KSI="
                            << static_cast<int>(security.ksi) << " COUNT=" << uuServiceRequestCount
                            << " short-MAC=0x" << std::hex << std::uppercase << std::setw(2)
                            << std::setfill('0') << static_cast<int>(pendingWire[2]) << std::setw(2)
                            << static_cast<int>(pendingWire[3]) << std::dec;
                    Log("INFO", request.str());
                }
                security.ulNasCount = (security.ulNasCount + 1U) & 0xFFFFFFU;
                uuSrSent = true;
                uuDeadline = now + std::chrono::milliseconds(config.lifecycle.procedureTimeoutMs);
            }

            if (uuSrSent && !uuRestored && uuTransport->AsSecurityActive())
            {
                // The network accepted the Service Request: it sent the Initial
                // Context Setup with a new KeNB and the AS security procedure
                // completed over this connection.
                mobility.onServiceRequestAccepted();
                uuRestored = true;
                uuIdle = false;
                uuSrArmed = false;
                uuSrSent = false;
                state = State::EPS_REGISTERED;
                LogState(state);
                Log("INFO", "EPS Service Request accepted; AS security restored; ECM-CONNECTED");
                return 0;
            }

            // The access is connected and the DRBs exist: the retained EPS
            // bearer's user plane is ready on this access. This is the only
            // place the UE-lifetime state is told so, and it is driven by the
            // real DRB objects rather than by the request that opened them.
            if (uuTransport && uuDrbs != nullptr && !uuUserPlaneReady && mobility.emm == EmmState::REGISTERED &&
                mobility.ecm == EcmState::CONNECTED && mobility.bearer == EpsBearerState::SIGNALING_ESTABLISHED)
            {
                mobility.onUserPlaneReady();
                uuUserPlaneReady = true;
                state = State::USER_PLANE_ACTIVE;
                LogState(state);
                Log("INFO", "Existing EPS bearer user plane ready over SRB1/DRB; EBI=" +
                                std::to_string(activeEbi));
            }
        }

        if (mobility.emm == EmmState::REGISTERED && !scenarioTriggered &&
            scenarioRoundsDone < config.lifecycle.idleRounds && now >= scenarioDeadline)
        {
            scenarioTriggered = true;
            if (uuTransport && (config.lifecycle.scenario == LifecycleScenario::SERVICE_REQUEST ||
                                config.lifecycle.scenario == LifecycleScenario::PAGING))
            {
                // The network, not the UE, releases the access. The peer sends
                // the S1 UE Context Release Command and the eNB releases RRC.
                uuDeadline = now + std::chrono::milliseconds(config.lifecycle.procedureTimeoutMs);
                if (config.lifecycle.scenario == LifecycleScenario::SERVICE_REQUEST)
                    uuTriggerDeadline = now;
                Log("INFO", config.lifecycle.scenario == LifecycleScenario::PAGING
                                ? "Waiting for the network to release the RRC connection; a Paging indication "
                                  "will start the restoration"
                                : "Waiting for the network to release the RRC connection; the UE will send a "
                                  "Service Request from ECM-IDLE");
            }
            else if (config.lifecycle.scenario == LifecycleScenario::SERVICE_REQUEST ||
                     config.lifecycle.scenario == LifecycleScenario::PAGING ||
                     config.lifecycle.scenario == LifecycleScenario::IDLE_RESELECTION)
            {
                auto request = link::Encode({link::MessageType::S1_CONTEXT_RELEASE_REQUEST, ueId,
                                             {mobility.defaultEbi}});
                socket.Send(enb, request.data(), request.size());
                idleReleaseRequested = true;
                procedureDeadline = now + std::chrono::milliseconds(config.lifecycle.procedureTimeoutMs);
                if (config.lifecycle.scenario == LifecycleScenario::PAGING)
                    Log("INFO", "Controlled idle trigger sent an S1 Context Release Request; the UE will wait "
                                "for a network paging indication instead of sending Service Request");
                else if (config.lifecycle.scenario == LifecycleScenario::IDLE_RESELECTION)
                    Log("INFO", "Controlled idle trigger sent an S1 Context Release Request; the UE will reselect "
                                "the configured target cell once it reaches ECM-IDLE");
                else
                    Log("INFO", "Controlled idle trigger sent a standards-based S1 Context Release Request");
            }
            else if (config.lifecycle.scenario == LifecycleScenario::DETACH)
            {
                mobility.startDetach();
                auto plain = nas::EncodeDetachRequest(security.ksi, *mobility.guti, config.lifecycle.switchOff);
                pendingWire = nas::Protect(security, true, false, plain);
                pendingMobilityFrame.reset();
                // The Detach Request is the same kind of connected-mode uplink NAS
                // as the Attach exchange: it leaves through the one send interface,
                // so in Uu mode it travels in ULInformationTransfer over SRB1. A
                // refusal fails the run; it is never retried on the legacy link.
                if (!sendNas(pendingWire))
                {
                    state = State::PROCEDURE_FAILED;
                    LogState(state);
                    Log("ERROR", "The uplink NAS transport refused the EPS Detach Request");
                    return 1;
                }
                security.ulNasCount = (security.ulNasCount + 1U) & 0xFFFFFFU;
                procedureDeadline = now + std::chrono::milliseconds(config.lifecycle.procedureTimeoutMs);
                Log("INFO", std::string("Protected EPS Detach Request sent; switch-off=") +
                                (config.lifecycle.switchOff ? "true" : "false") + " UL-COUNT=" +
                                std::to_string((security.ulNasCount + 0xFFFFFFU) & 0xFFFFFFU));
                if (config.lifecycle.switchOff)
                {
                    // A switch-off Detach ends locally (TS 24.301 5.5.2.2.2).
                    // The legacy control frame is addressed to the legacy eNB, so
                    // it is not emitted when the session ran over Uu.
                    if (!uuTransport)
                    {
                        auto deleted = link::Encode({link::MessageType::EPS_SESSION_DELETED, ueId,
                            link::EncodeBearerRestoration(activeEbi, mobility.accessGeneration)});
                        socket.Send(enb, deleted.data(), deleted.size());
                    }
                    mobility.onDetachAccepted();
                    dedicatedBearers.clear();
                    defaultConfiguration = {};
                    security = SecurityContext{};
                    tun.reset();
                    Log("INFO", "Switch-off Detach completed without waiting for Detach Accept");
                    return 0;
                }
            }
            else if (config.lifecycle.scenario == LifecycleScenario::TAU_NORMAL ||
                     config.lifecycle.scenario == LifecycleScenario::TAU_PERIODIC)
            {
                const bool periodic = config.lifecycle.scenario == LifecycleScenario::TAU_PERIODIC;
                mobility.startTau(periodic);
                auto plain = nas::EncodeTauRequest(
                    security.ksi, *mobility.guti,
                    RetainedBearerIdentities(mobility.defaultEbi, dedicatedBearers), periodic);
                pendingWire = nas::Protect(security, true, false, plain);
                pendingMobilityFrame.reset();
                SendNas(socket, enb, ueId, pendingWire);
                security.ulNasCount = (security.ulNasCount + 1U) & 0xFFFFFFU;
                procedureDeadline = now + std::chrono::milliseconds(config.lifecycle.procedureTimeoutMs);
                Log("INFO", std::string("Protected ") + (periodic ? "periodic" : "normal") +
                                " Tracking Area Update Request sent");
            }
        }

        // A stop request always wins over a deadline inside the same turn, so a
        // shutdown is never reported as a failed procedure. The loop condition
        // is evaluated before these checks; the guard makes the precedence
        // explicit rather than depending on when the flag was set.
        if (!shutdownRequested && idleReleaseRequested && now >= procedureDeadline)
        {
            Log("ERROR", "Timed out waiting for the MME S1 Context Release Command/Complete flow");
            return 1;
        }

        if (!shutdownRequested && pagingWaitArmed && now >= pagingDeadline)
        {
            // The MME owns paging retries. This is a bounded laboratory wait, and
            // its expiry is an unresolved test condition, never paging success.
            Log("ERROR", "Timed out waiting for a network paging indication; no Service Request was sent");
            return 1;
        }

        if (!shutdownRequested && uuTransport)
        {
            const bool idleScenario = config.lifecycle.scenario == LifecycleScenario::SERVICE_REQUEST ||
                                      config.lifecycle.scenario == LifecycleScenario::PAGING;
            if (!uuIdle && scenarioTriggered && idleScenario && !uuSrArmed && now >= uuDeadline)
            {
                Log("ERROR", "Timed out waiting for the network to release the RRC connection");
                return 1;
            }
            if (uuIdle && config.lifecycle.scenario == LifecycleScenario::PAGING && !uuSrArmed &&
                now >= uuPagingDeadline)
            {
                Log("ERROR", "Timed out waiting for a network Paging indication; no Service Request was sent");
                return 1;
            }
            if (uuSrArmed && !uuSrSent && now >= uuDeadline)
            {
                Log("ERROR", "Timed out waiting for the RRC connection during Service Request restoration");
                return 1;
            }
            if (uuSrSent && !uuRestored && now >= uuDeadline)
            {
                Log("ERROR", "Timed out waiting for the network to restore the AS security context");
                return 1;
            }
        }

        // Access restoration after an unexpected S1-MME association loss. The
        // UE sends a genuine compact EPS Service Request under its existing NAS
        // security context and GUTI. It never re-Attaches silently and never
        // invents a network procedure; the MME decides whether the old EPS
        // context still exists.
        //
        // A connected-mode handover is explicitly not a reason to start one. A
        // UE that has accepted a handover command is between two accesses of one
        // live ECM connection and must await the target's outcome; the clause is
        // stated here so the rule is enforced where a Service Request would be
        // sent rather than only implied by the ECM-CONNECTED state.
        if (restorationTrigger.recoveryArmed() && mobility.emm == EmmState::REGISTERED &&
            mobility.ecm == EcmState::IDLE && mobility.pending == PendingProcedure::NONE &&
            mobility.handover == HandoverExecution::NONE && now >= recoveryDeadline)
        {
            if (recoveryAttempts >= config.lifecycle.recoveryMaxAttempts)
            {
                restorationTrigger.abandon();
                Log("ERROR", "Access recovery gave up after " + std::to_string(recoveryAttempts) +
                                " Service Request attempt(s); the UE remains registered and ECM-IDLE");
            }
            else if (restorationTrigger.tryTakeFromRecovery())
            {
                try
                {
                    mobility.startServiceRequest();
                    pendingWire = nas::EncodeServiceRequest(security);
                    pendingMobilityFrame.reset();
                    SendServiceRequest(socket, enb, ueId, *mobility.guti, pendingWire);
                    security.ulNasCount = (security.ulNasCount + 1U) & 0xFFFFFFU;
                    ++recoveryAttempts;
                    procedureRetries = 0;
                    procedureDeadline = now + std::chrono::milliseconds(config.lifecycle.procedureTimeoutMs);
                    recoveryDeadline = now + std::chrono::milliseconds(config.lifecycle.recoveryRetryMs);
                    Log("INFO", "Compact EPS Service Request sent after unexpected S1 access loss (attempt " +
                                    std::to_string(recoveryAttempts) + ")");
                }
                catch (const std::exception &e)
                {
                    restorationTrigger.abandon();
                    Log("ERROR", std::string("Access recovery cannot start a Service Request: ") + e.what());
                }
            }
        }

        // A stop request wins over a deadline here as well. The guards above
        // already establish that precedence for the idle-release and paging
        // waits; a procedure that is still outstanding when the UE is asked to
        // stop is abandoned at shutdown, not retransmitted into a timeout.
        if (!shutdownRequested && mobility.pending != PendingProcedure::NONE && !pendingWire.empty() &&
            now >= procedureDeadline)
        {
            if (procedureRetries >= config.lifecycle.maxRetries)
            {
                const auto failed = restorationTrigger.takeFailed();
                if (failed == RestorationOwner::PAGING)
                {
                    ++pagingRestorationFailures;
                    Log("ERROR", "Paging-triggered service restoration failed after bounded retransmissions");
                }
                else if (failed == RestorationOwner::RECOVERY)
                {
                    // A bounded recovery outcome: the network never completed
                    // the restoration. The UE stays registered and ECM-IDLE and
                    // reports the failure instead of fabricating success.
                    ++recoveryFailures;
                    pendingWire.clear();
                    mobility.onProcedureRejected();
                    Log("ERROR", "Access recovery Service Request timed out after bounded retransmissions");
                    recoveryDeadline = now + std::chrono::milliseconds(config.lifecycle.recoveryRetryMs);
                    continue;
                }
                Log("ERROR", std::string(ToString(mobility.pending)) + " timed out after bounded retransmissions");
                return 1;
            }
            if (pendingMobilityFrame.has_value())
                // A retransmission of a procedure that is still opening an S1
                // connection repeats the very frame the first transmission sent.
                // This is decided from how the original left rather than from
                // whether the MME has assigned an identifier yet, because the
                // UE has never been told that identifier and a guess would
                // change the message a reselected cell receives. The frame is
                // frozen, so the retry cannot rebuild the declared bearer
                // inventory from state that has moved on since the first send.
                // It takes precedence over the compact form below because an
                // answer to a page is a Service Request that also declared its
                // inventory, and repeating it as the compact form would drop
                // that declaration from the retry.
                SendMobilityNas(socket, enb, *pendingMobilityFrame);
            else if (mobility.pending == PendingProcedure::SERVICE_REQUEST)
                SendServiceRequest(socket, enb, ueId, *mobility.guti, pendingWire);
            else if (!sendNas(pendingWire))
            {
                // A retransmission cannot be diverted to another transport: the
                // procedure is bound to the one that carried its first message.
                state = State::PROCEDURE_FAILED;
                LogState(state);
                Log("ERROR", "The uplink NAS transport refused a procedure retransmission");
                return 1;
            }
            ++procedureRetries;
            procedureDeadline = now + std::chrono::milliseconds(config.lifecycle.procedureTimeoutMs);
            Log("WARN", std::string("Retransmitted ") + ToString(mobility.pending) +
                            ", retry=" + std::to_string(procedureRetries));
        }

        bool tunHadUplink = false;
        if (tun)
        {
            // Bound each turn so continuous application traffic cannot starve
            // downlink radio-link processing.
            for (int packetBudget = 0; packetBudget < 16; ++packetBudget)
            {
                std::vector<uint8_t> packet;
                if (!tun->readPacket(packet))
                    break;
                tunHadUplink = true;
                try
                {
                    const auto ipv4 = ip::Validate(packet.data(), packet.size(),
                                                   static_cast<size_t>(config.tun.mtu));
                    if (ipv4.source != assignedIpv4)
                        throw ip::ValidationError("TUN uplink source does not match the assigned UE IPv4 address");
                    ++tunUplinkPackets;
                    tunUplinkBytes += packet.size();

                    // Access transport may be temporarily unavailable, for
                    // example after an unexpected S1-MME association loss. Such
                    // packets are dropped and counted: they are never buffered
                    // and never sent through an obsolete TEID.
                    if (!mobility.canForwardUserPlane())
                    {
                        ++accessUnavailableDrops;
                        continue;
                    }

                    // Select the bearer by the network-provided TFT. Ties are
                    // resolved by evaluation precedence, and no match falls
                    // back to the default bearer.
                    const auto selection = SelectUplinkBearer(activeEbi, dedicatedBearers, packet.data(), packet.size());
                    const uint8_t selectedEbi = selection.ebi;

                    if (uuTransport)
                    {
                        // Every uplink IP packet travels the DRB of its EPS
                        // bearer: PDCP, then RLC AM, then the simulated Uu. The
                        // legacy DATA_UPLINK frame is not used for a Uu UE.
                        if (uuDrbs == nullptr)
                        {
                            ++accessUnavailableDrops;
                            continue;
                        }
                        if (selectedEbi != activeEbi)
                        {
                            const auto dedicated = std::find_if(dedicatedBearers.begin(), dedicatedBearers.end(),
                                                                [&](const auto &bearer) {
                                                                    return bearer.ebi == selectedEbi;
                                                                });
                            if (dedicated == dedicatedBearers.end() || !dedicated->accessReady)
                            {
                                ++bearerInactiveDrops;
                                continue;
                            }
                        }
                        if (!uuDrbs->SubmitIp(selectedEbi, packet.data(), packet.size()))
                        {
                            ++uuDrbDrops;
                            continue;
                        }
                        ++uuUplinkPackets;
                        uuUplinkBytes += packet.size();
                        if (selectedEbi != activeEbi)
                        {
                            ++dedicatedUplinkPackets;
                            ++std::find_if(dedicatedBearers.begin(), dedicatedBearers.end(),
                                           [&](const auto &bearer) { return bearer.ebi == selectedEbi; })
                                  ->uplinkPackets;
                        }
                        continue;
                    }

                    std::vector<uint8_t> frame;
                    if (selectedEbi != activeEbi)
                    {
                        auto &selected = *std::find_if(dedicatedBearers.begin(), dedicatedBearers.end(),
                            [&](const auto &bearer) { return bearer.ebi == selectedEbi; });
                        if (!selected.accessReady)
                        {
                            ++bearerInactiveDrops;
                            ++selected.inactiveDrops;
                            continue; // bounded drop; keep the TFT and never fall back to default
                        }
                        std::vector<uint8_t> payload;
                        payload.reserve(packet.size() + 1);
                        payload.push_back(selectedEbi);
                        payload.insert(payload.end(), packet.begin(), packet.end());
                        frame = link::Encode({link::MessageType::DATA_UPLINK_BEARER, ueId, std::move(payload)});
                    }
                    else
                        frame = link::Encode({link::MessageType::DATA_UPLINK, ueId, std::move(packet)});

                    if (!socket.TrySend(enb, frame.data(), frame.size()))
                        Log("WARN", "LTE radio-link uplink send would block; packet dropped");
                    else if (selectedEbi != activeEbi)
                    {
                        ++dedicatedUplinkPackets;
                        ++std::find_if(dedicatedBearers.begin(), dedicatedBearers.end(),
                            [&](const auto &bearer) { return bearer.ebi == selectedEbi; })->uplinkPackets;
                    }
                }
                catch (const std::exception &e)
                {
                    ++malformedDrops;
                    Log("WARN", std::string("Dropped invalid LTE TUN uplink packet: ") + e.what());
                }
            }
        }

        InetAddress peer;
        // With a Uu transport the legacy socket is polled only to keep its
        // pre-existing paths alive; a short bound keeps RRC and SRB1 timers
        // advancing instead of sleeping inside the legacy receive.
        const auto radioTimeout = uuTransport
                                      ? std::min(5, RadioReceiveTimeoutMs(mobility.emm == EmmState::REGISTERED,
                                                                          tunHadUplink))
                                      : RadioReceiveTimeoutMs(mobility.emm == EmmState::REGISTERED, tunHadUplink);
        int received = socket.Receive(buffer, sizeof(buffer), radioTimeout, peer);
        if (received <= 0)
            continue;
        if (peer != enb)
        {
            Log("WARN", "Ignoring LTE radio-link datagram from an unexpected endpoint");
            continue;
        }
        try
        {
            auto message = link::Decode(buffer, static_cast<size_t>(received));
            if (!link::IsDownlink(message.type) || message.ueId != ueId)
                throw link::DecodeError("Unexpected LTE radio-link routing fields");

            if (message.type == link::MessageType::BEARER_RELEASED)
            {
                if (mobility.emm != EmmState::REGISTERED || message.payload.size() != 1)
                    throw link::DecodeError("Malformed bearer release");
                const uint8_t releasedEbi = message.payload[0];
                if (releasedEbi == activeEbi)
                {
                    tun.reset();
                    dedicatedBearers.clear();
                    defaultConfiguration = {};
                    mobility.bearer = EpsBearerState::INACTIVE;
                    state = State::EPS_REGISTERED;
                    LogState(state);
                    Log("WARN", "Default bearer released; LTE TUN resources were closed");
                    continue;
                }
                const auto released = std::find_if(dedicatedBearers.begin(), dedicatedBearers.end(),
                                                   [releasedEbi](const DedicatedBearerRuntime &bearer) {
                                                       return bearer.ebi == releasedEbi;
                                                   });
                if (released == dedicatedBearers.end())
                    throw link::DecodeError("Bearer release names an unknown bearer");
                dedicatedBearers.erase(released);
                Log("INFO", "Dedicated EPS bearer " + std::to_string(releasedEbi) +
                                " released; default bearer and TUN retained");
                continue;
            }
            if (message.type == link::MessageType::S1_CONTEXT_RELEASED)
            {
                if (mobility.emm != EmmState::REGISTERED || message.payload[0] != activeEbi)
                    throw link::DecodeError("S1 context release does not match the registered bearer");
                const auto release = link::DecodeBearerRestoration(message.payload);
                const bool serviceAborted = mobility.pending == PendingProcedure::SERVICE_REQUEST;
                mobility.acceptAccessRelease(release.first, release.second);
                if (serviceAborted)
                    pendingWire.clear();
                for (auto &bearer : dedicatedBearers)
                    bearer.releaseAccessTransport();
                Log("INFO", "State=ECM_IDLE; EPS registration, security, GUTI, bearer and TUN retained");
                if (idleReleaseRequested)
                {
                    idleReleaseRequested = false;
                    if (config.lifecycle.scenario == LifecycleScenario::PAGING)
                    {
                        // The wait starts here, at the first ECM-IDLE turn, so its
                        // deadline measures the paging window alone. Arming it when
                        // the release request was sent would let a short pagingWaitMs
                        // expire in the middle of the release exchange and report a
                        // paging timeout for what is really a release failure.
                        pagingWaitArmed = true;
                        pagingDeadline = std::chrono::steady_clock::now() +
                                         std::chrono::milliseconds(config.lifecycle.pagingWaitMs);
                        // Network-triggered scenario: stay idle until the MME pages.
                        Log("INFO", "Waiting for a network paging indication; no Service Request is sent locally");
                    }
                    else if (config.lifecycle.scenario == LifecycleScenario::IDLE_RESELECTION)
                    {
                        if (!config.link.targetCell.has_value())
                            throw std::runtime_error(
                                "The idle-reselection scenario needs a configured enbLink.targetCell");
                        // Only the first round moves. The later rounds of the
                        // same registration are idle access epochs on the cell
                        // that move reached, and reselecting it again would
                        // retire an access that is genuinely still the serving
                        // one and demand a bearer inventory from a cell that
                        // has already been confirmed to hold the session.
                        if (scenarioRoundsDone > 0)
                        {
                            Log("INFO", "Controlled idle trigger released S1 on the reselected cell; the UE "
                                        "will wait for a network paging indication");
                            continue;
                        }
                        const auto &target = *config.link.targetCell;
                        const Tai serving{config.plmn, config.link.servingTac};
                        const Tai arriving{target.plmn, target.tac};
                        // The cell being left keeps its S1AP identities, its
                        // access TEIDs and its access generation. None of them
                        // may be presented at the target.
                        mobility.onCellReselected();
                        enb = InetAddress(target.radioAddress, target.radioPort);
                        Log("INFO", "ECM-IDLE cell reselection " + serving.plmn.toString() + "/" +
                                        std::to_string(serving.tac) + " -> " + arriving.plmn.toString() + "/" +
                                        std::to_string(arriving.tac) + " via " + target.radioAddress + ":" +
                                        std::to_string(target.radioPort));

                        // Whether the move calls for a Normal Tracking Area
                        // Update is decided from the registered tracking area
                        // list alone. Moving cells is not the trigger; moving
                        // out of the registered area is.
                        const auto decision = EvaluateServingTai(mobility, arriving);
                        if (decision == TauDecision::NO_CHANGE)
                        {
                            Log("INFO", std::string("Target tracking area is in the registered list (") +
                                            ToString(decision) + "); no Tracking Area Update is sent");
                        }
                        else if (decision == TauDecision::NORMAL_TAU)
                        {
                            mobility.startTau(false);
                            // The declaration is derived from the NAS-confirmed
                            // bearer state and encoded before any frame exists,
                            // so an inventory the wire cannot express is refused
                            // here rather than transmitted as a claim a fresh
                            // target would restore from. There is no fallback to
                            // the identity-only mobility form: a target that
                            // needs the declaration is never given an uplink
                            // without one, and an unusable one stops the
                            // procedure before any misleading frame exists.
                            try
                            {
                                const auto inventory =
                                    ValidateBearerInventory(mobility.defaultEbi, dedicatedBearers);
                                auto plain = nas::EncodeTauRequest(
                                    security.ksi, *mobility.guti,
                                    RetainedBearerIdentities(mobility.defaultEbi, dedicatedBearers), false);
                                pendingWire = nas::Protect(security, true, false, plain);
                                pendingMobilityFrame =
                                    link::BuildMobilityContext(ueId, *mobility.guti, inventory, pendingWire);
                            }
                            catch (const std::exception &e)
                            {
                                pendingWire.clear();
                                pendingMobilityFrame.reset();
                                Log("ERROR", std::string("Refusing to open the reselected cell without a valid "
                                                         "bearer inventory: ") +
                                                 e.what());
                                return 1;
                            }
                            SendMobilityNas(socket, enb, *pendingMobilityFrame);
                            // Exactly one uplink NAS COUNT opens the procedure.
                            // The retransmissions repeat the frozen frame and
                            // consume none of their own.
                            security.ulNasCount = (security.ulNasCount + 1U) & 0xFFFFFFU;
                            procedureRetries = 0;
                            procedureDeadline = std::chrono::steady_clock::now() +
                                                std::chrono::milliseconds(config.lifecycle.procedureTimeoutMs);
                            Log("INFO", "Protected Normal Tracking Area Update Request sent through the "
                                        "reselected cell");
                        }
                        else
                        {
                            throw std::runtime_error(
                                std::string("Cannot start a Normal Tracking Area Update after reselection: ") +
                                ToString(decision));
                        }
                    }
                    else
                    {
                        mobility.startServiceRequest();
                        pendingWire = nas::EncodeServiceRequest(security);
                        pendingMobilityFrame.reset();
                        SendServiceRequest(socket, enb, ueId, *mobility.guti, pendingWire);
                        security.ulNasCount = (security.ulNasCount + 1U) & 0xFFFFFFU;
                        procedureRetries = 0;
                        procedureDeadline = std::chrono::steady_clock::now() +
                                            std::chrono::milliseconds(config.lifecycle.procedureTimeoutMs);
                        Log("INFO", "Compact EPS Service Request sent from ECM-IDLE");
                    }
                }
                continue;
            }
            if (message.type == link::MessageType::S1_ACCESS_LOST)
            {
                // INTERNAL simulator abstraction: the eNB lost its S1-MME SCTP
                // association and invalidated this UE's access transport. This
                // is deliberately not a UE Context Release procedure — no S1AP
                // message was exchanged and no NAS or RRC message is implied.
                if (mobility.emm != EmmState::REGISTERED || message.payload[0] != activeEbi)
                    throw link::DecodeError("S1 access loss does not match the registered bearer");
                const auto lost = link::DecodeBearerRestoration(message.payload);
                mobility.acceptAccessRelease(lost.first, lost.second);
                pendingWire.clear();
                for (auto &bearer : dedicatedBearers)
                    bearer.releaseAccessTransport();
                ++accessLosses;
                // Only the UE-initiated path is armed here. Network-initiated
                // Paging is left untouched and remains fully functional.
                restorationTrigger.onAccessLoss(config.lifecycle.recoveryDelayMs > 0 &&
                                                config.lifecycle.recoveryMaxAttempts > 0);
                recoveryAttempts = 0;
                recoveryDeadline = std::chrono::steady_clock::now() +
                                   std::chrono::milliseconds(config.lifecycle.recoveryDelayMs);
                Log("WARN", "S1 access transport lost unexpectedly; EPS registration, security, GUTI, "
                            "logical bearers, TFT and TUN retained");
                continue;
            }
            if (message.type == link::MessageType::PAGING_INDICATION)
            {
                ++pagingIndications;
                // Decoding is strict: a notification that is not exactly the
                // seven-octet S-TMSI||TAC frame never reaches the state machine.
                const auto notification =
                    link::DecodePagingNotification(message.payload.data(), message.payload.size());
                const auto match = EvaluatePaging(mobility, config.plmn, notification);
                if (match != PagingMatch::ACCEPTED)
                {
                    ++pagingIgnored;
                    Log("INFO", std::string("Paging indication ignored: ") + ToString(match));
                    continue;
                }

                // A duplicate or late page must not start a second Service
                // Request, consume a second NAS COUNT, nor erase a
                // UE-initiated restoration that is already in flight.
                if (!restorationTrigger.tryTakeFromPaging())
                {
                    ++pagingSuppressed;
                    Log("INFO", "Paging indication ignored: another trigger already owns the pending restoration");
                    continue;
                }
                ++pagingMatched;
                auto compact = RespondToPaging(mobility, config.plmn, notification, security);
                if (!compact.has_value())
                    throw std::runtime_error("Accepted paging produced no compact Service Request");
                pendingWire = std::move(*compact);
                if (pendingWire.size() != 4)
                    throw std::runtime_error("Compact Service Request NAS must be four octets");
                // Whether this answer also declares the bearer inventory the UE
                // holds is decided from what the endpoint being answered has
                // already been confirmed to hold, never from the access
                // generation. The generation numbers that endpoint's access
                // epochs and is shared with it so stale confirmations can be
                // refused; it says nothing about whether the endpoint still
                // knows which E-RAB is the default bearer. The endpoint that
                // carried this session's Attach, or any later confirmed bearer
                // access, and has since released it keeps those roles, and a
                // compact EPS Service Request is enough. An endpoint that has
                // never completed such an access — a cell reached by an
                // ECM-IDLE reselection, whose Tracking Area Update established
                // no bearer here — holds none of them, and the MME's Initial
                // Context Setup Request marks no roles in its E-RAB list, so
                // the cell is told them here rather than left to infer them
                // from QCI or from the order of that list.
                //
                // The compact Service Request travels beside the declaration
                // unchanged, so the network still answers an ordinary
                // four-octet EPS Service Request rather than a new procedure.
                if (mobility.accessBootstrap == AccessBootstrap::DECLARE_REQUIRED)
                {
                    try
                    {
                        const auto inventory = ValidateBearerInventory(mobility.defaultEbi, dedicatedBearers);
                        pendingMobilityFrame =
                            link::BuildMobilityContext(ueId, *mobility.guti, inventory, pendingWire);
                    }
                    catch (const std::exception &e)
                    {
                        pendingWire.clear();
                        pendingMobilityFrame.reset();
                        throw std::runtime_error(std::string("Refusing to answer a page without a valid bearer "
                                                             "inventory: ") +
                                                 e.what());
                    }
                    SendMobilityNas(socket, enb, *pendingMobilityFrame);
                    Log("INFO", "Paging identity matched (MMEC=" + std::to_string(notification.mmeCode) +
                                    "); bearer-inventory Service Request sent for the network-triggered "
                                    "restoration (bootstrap=" +
                                    ToString(mobility.accessBootstrap) + ")");
                }
                else
                {
                    pendingMobilityFrame.reset();
                    SendServiceRequest(socket, enb, ueId, *mobility.guti, pendingWire);
                    Log("INFO", "Paging identity matched (MMEC=" + std::to_string(notification.mmeCode) +
                                    "); compact EPS Service Request sent for the network-triggered "
                                    "restoration (bootstrap=" +
                                    ToString(mobility.accessBootstrap) + ")");
                }
                ++pagingServiceRequests;
                pagingWaitArmed = false;
                procedureRetries = 0;
                procedureDeadline = std::chrono::steady_clock::now() +
                                    std::chrono::milliseconds(config.lifecycle.procedureTimeoutMs);
                continue;
            }
            if (message.type == link::MessageType::S1_CONTEXT_RESTORED)
            {
                const auto restored = link::DecodeBearerRestoration(message.payload);
                mobility.validateAccessRestoration(restored.first, restored.second, false);
                // A restoration answers the access, not every procedure that
                // was carried over it. A Tracking Area Update that opened this
                // connection is still waiting for its Accept, so it keeps its
                // outstanding message and its deadline; reporting the restored
                // transport as an accepted update would invent an outcome.
                const bool tauOutstanding = mobility.pending == PendingProcedure::TAU_NORMAL ||
                                            mobility.pending == PendingProcedure::TAU_PERIODIC;
                if (tauOutstanding)
                    mobility.onTauAccessRestored(tun != nullptr);
                else
                {
                    mobility.onServiceRestored(tun != nullptr);
                    pendingWire.clear();
                }
                // The S1 connection now exists, so an outstanding uplink no
                // longer has to open one and its retransmissions travel as
                // ordinary uplink NAS transport.
                pendingMobilityFrame.reset();
                // Exactly one trigger owns a restoration. A page that won the
                // race against an armed recovery timer is a paging restoration
                // even though the timer had already been scheduled.
                const auto owner = restorationTrigger.takeRestored();
                switch (owner)
                {
                case RestorationOwner::PAGING:
                    ++pagingRestorations;
                    Log("INFO", "Access restoration completed after a network paging indication");
                    break;
                case RestorationOwner::RECOVERY:
                    ++recoveryRestorations;
                    Log("INFO", "Access restoration completed after unexpected S1 access loss");
                    break;
                case RestorationOwner::NONE:
                    break;
                }
                // A controlled idle period of the scenario driver is over the
                // moment the access it opened has been restored. Only a
                // network-triggered restoration completes one: a recovery that
                // ran on its own timer is not a round the driver asked for, so
                // it neither counts as one nor skips one.
                if (scenarioTriggered && owner == RestorationOwner::PAGING)
                {
                    scenarioTriggered = false;
                    ++scenarioRoundsDone;
                    scenarioDeadline = scenarioRoundsDone < config.lifecycle.idleRounds
                                           ? std::chrono::steady_clock::now() +
                                                 std::chrono::milliseconds(config.lifecycle.triggerAfterMs)
                                           : std::chrono::steady_clock::time_point::max();
                    if (scenarioRoundsDone < config.lifecycle.idleRounds)
                        Log("INFO", "Controlled idle period " + std::to_string(scenarioRoundsDone) + " of " +
                                        std::to_string(config.lifecycle.idleRounds) +
                                        " completed; the next one is scheduled");
                }
                if (tun)
                {
                    auto readyFrame = link::Encode({link::MessageType::BEARER_TRANSPORT_READY, ueId,
                        link::EncodeBearerTransportReady(activeEbi, mobility.accessGeneration, assignedIpv4)});
                    socket.Send(enb, readyFrame.data(), readyFrame.size());
                    Log("INFO", "State=ECM_CONNECTED; existing EPS bearer transport and user plane restored");
                }
                else
                    Log("WARN", "State=ECM_CONNECTED; bearer signaling restored in control-plane-only mode");
                continue;
            }
            if (message.type == link::MessageType::DEDICATED_BEARER_RESTORED)
            {
                const auto restored = link::DecodeBearerRestoration(message.payload);
                auto bearer = std::find_if(dedicatedBearers.begin(), dedicatedBearers.end(),
                    [&](const auto &candidate) { return candidate.ebi == restored.first; });
                if (bearer == dedicatedBearers.end() || !tun)
                    throw link::DecodeError("Restoration has no logical dedicated bearer or TUN");
                auto candidate = *bearer;
                candidate.restoreAccess(mobility, restored.first, restored.second);
                auto ack = link::Encode({link::MessageType::BEARER_TRANSPORT_READY, ueId,
                                         link::EncodeBearerTransportReady(restored.first, restored.second,
                                                                          assignedIpv4)});
                socket.Send(enb, ack.data(), ack.size());
                *bearer = std::move(candidate);
                Log("INFO", "Existing dedicated EBI=" + std::to_string(restored.first) +
                            " access restored; retained TFT and NAS security unchanged");
                continue;
            }
            if (message.type == link::MessageType::DATA_DOWNLINK)
            {
                if (!tun || !mobility.canForwardUserPlane())
                {
                    ++bearerInactiveDrops;
                    throw link::DecodeError("Downlink data arrived before TUN readiness");
                }
                const auto ipv4 = ip::Validate(message.payload.data(), message.payload.size(),
                                               static_cast<size_t>(config.tun.mtu));
                if (ipv4.destination != assignedIpv4)
                    throw ip::ValidationError("Downlink destination does not match the assigned UE IPv4 address");
                if (tun->writePacket(message.payload.data(), message.payload.size()))
                {
                    ++tunDownlinkPackets;
                    tunDownlinkBytes += message.payload.size();
                }
                continue;
            }

            if (message.type == link::MessageType::DATA_DOWNLINK_BEARER)
            {
                if (!tun || !mobility.canForwardUserPlane())
                {
                    ++bearerInactiveDrops;
                    throw link::DecodeError("Dedicated downlink data arrived before TUN readiness");
                }
                if (message.payload.size() < 2)
                    throw link::DecodeError("Malformed bearer-aware downlink frame");
                const uint8_t bearerEbi = message.payload[0];
                const auto bearer = std::find_if(dedicatedBearers.begin(), dedicatedBearers.end(),
                                                 [bearerEbi](const DedicatedBearerRuntime &candidate) {
                                                     return candidate.ebi == bearerEbi;
                                                 });
                if (bearer == dedicatedBearers.end() || !bearer->accessReady)
                {
                    ++bearerInactiveDrops;
                    throw link::DecodeError("Downlink names an unknown or access-inactive dedicated bearer");
                }

                std::vector<uint8_t> packet(message.payload.begin() + 1, message.payload.end());
                const auto ipv4 = ip::Validate(packet.data(), packet.size(),
                                               static_cast<size_t>(config.tun.mtu));
                if (ipv4.destination != assignedIpv4)
                    throw ip::ValidationError("Downlink destination does not match the assigned UE IPv4 address");
                if (tun->writePacket(packet.data(), packet.size()))
                {
                    ++tunDownlinkPackets;
                    ++dedicatedDownlinkPackets;
                    ++bearer->downlinkPackets;
                    tunDownlinkBytes += packet.size();
                }
                continue;
            }

            if (message.type == link::MessageType::SIMULATED_HANDOVER_COMMAND)
            {
                // A connected-mode handover command is executed here, in the
                // UE's own production receive path, and every part of it is
                // checked before any transport moves. A refusal therefore
                // leaves this UE serving the cell it is already on: the radio
                // endpoint is redirected only after the last check has passed.
                const auto command =
                    link::DecodeSimulatedHandoverCommand(message.payload.data(), message.payload.size());

                // The command names a cell and never an address. The endpoint
                // is resolved from this UE's own configuration, so a frame
                // cannot redirect it to an endpoint nobody authorized, and a
                // cell this configuration never stated an identifier for is
                // refused rather than accepted on the strength of a command
                // that happens to name the right address and port.
                if (!config.link.targetCell.has_value())
                    throw link::DecodeError("No target cell is authorized for a connected-mode handover");
                const auto &target = *config.link.targetCell;
                if (config.link.enbId == 0 || config.link.servingTac == 0)
                    throw link::DecodeError("This configuration does not state the identity of its serving cell");
                if (target.enbId == 0)
                    throw link::DecodeError("This configuration does not state the identifier of the target cell");
                const auto targetPlmn = enb::s1ap::EncodePlmn(target.plmn);
                if (command.targetPlmn != targetPlmn || command.targetEnbId != target.enbId ||
                    command.targetTac != target.tac)
                    throw link::DecodeError("The handover command names a cell this UE is not authorized to enter");
                // A command naming the cell already being served is not a
                // handover, and acting on one would retire a live access for
                // nothing.
                if (command.targetEnbId == config.link.enbId && command.targetTac == config.link.servingTac)
                    throw link::DecodeError("The handover command names the serving cell as its target");
                // The address is compared against the one the network assigned
                // this UE's own NAS. Nothing here adopts an address from a
                // frame, so a command restating a different one is refused
                // before any transport moves.
                if (command.ueIpv4 != mobility.assignedIpv4)
                    throw link::DecodeError("The handover command names a different PDN address");

                // The S1AP session binding is checked inside, against the MME
                // UE identity this UE already holds, and that call is
                // check-then-mutate: a command naming another UE is refused
                // there with nothing changed.
                mobility.onConnectedHandover(command.mmeUeS1apId);

                enb = InetAddress(target.radioAddress, target.radioPort);
                Log("INFO", "Connected-mode handover command accepted (MME-UE-S1AP-ID=" +
                                std::to_string(command.mmeUeS1apId) + "); radio transport moved to the authorized " +
                                "target cell " + target.plmn.toString() + "/" + std::to_string(target.tac) + " at " +
                                target.radioAddress + ":" + std::to_string(target.radioPort));

                // Both cells are named from this UE's own configuration and
                // never from the command, so the source identity in the arrival
                // is the same one the source eNB states about itself and the
                // same one the target's preparation was verified against.
                link::SimulatedHandoverAccess access;
                access.arrivalToken = command.arrivalToken;
                access.sourcePlmn = enb::s1ap::EncodePlmn(config.plmn);
                access.sourceEnbId = config.link.enbId;
                access.sourceTac = config.link.servingTac;
                access.targetPlmn = targetPlmn;
                access.targetEnbId = target.enbId;
                access.targetTac = target.tac;
                access.mmeUeS1apId = command.mmeUeS1apId;
                access.ueIpv4 = mobility.assignedIpv4;
                auto frame = link::Encode({link::MessageType::SIMULATED_HANDOVER_ACCESS, ueId,
                                           link::EncodeSimulatedHandoverAccess(access)});
                socket.Send(enb, frame.data(), frame.size());
                Log("INFO", "SIMULATED_HANDOVER_ACCESS sent to the target cell; awaiting its access outcome. "
                            "No Attach and no Service Request is started by this UE");
                continue;
            }
            if (message.type == link::MessageType::S1_CONTEXT_ESTABLISHED)
            {
                // The cell already serving this UE states which S1AP identity
                // pair its S1 context is bound to. It is only ever a binding
                // this UE checks a later connected-mode handover command
                // against: no command can establish one, and nothing here
                // adopts an identity out of a frame that is to be checked.
                const auto identity =
                    link::DecodeS1ContextEstablished(message.payload.data(), message.payload.size());
                mobility.onS1ContextEstablished(identity.enbUeS1apId, identity.mmeUeS1apId);
                Log("INFO", "S1 context established (eNB-UE-S1AP-ID=" + std::to_string(identity.enbUeS1apId) +
                                ", MME-UE-S1AP-ID=" + std::to_string(identity.mmeUeS1apId) + ")");
                continue;
            }
            if (message.type != link::MessageType::NAS_DOWNLINK)
                throw link::DecodeError("Data/NAS direction mismatch");
            if (auto outcome = deliverNas(message.payload))
                return *outcome;
            continue;
        }
        catch (const nas::SecurityError &e)
        {
            if (mobility.emm == EmmState::REGISTERED)
            {
                ++malformedDrops;
                Log("WARN", std::string("Dropped unauthenticated/replayed NAS: ") + e.what());
                continue;
            }
            state = State::PROCEDURE_FAILED;
            LogState(state);
            Log("ERROR", std::string("NAS security failure: ") + e.what());
            return 1;
        }
        catch (const std::exception &e)
        {
            if (mobility.emm == EmmState::REGISTERED && state != State::DEFAULT_BEARER_SIGNALING_COMPLETE && state != State::TUN_READY)
            {
                ++malformedDrops;
                Log("WARN", std::string("Dropped invalid LTE radio-link message: ") + e.what());
                continue;
            }
            state = State::PROCEDURE_FAILED;
            LogState(state);
            Log("ERROR", e.what());
            return 1;
        }
    }
    if (!shutdownRequested && mobility.emm != EmmState::REGISTERED)
    {
        state = State::PROCEDURE_FAILED;
        LogState(state);
        Log("ERROR", "Timed out waiting for MME EPS Attach signaling");
        return 1;
    }
    if (pagingWaitArmed)
        // Reaching here with the wait still armed is only possible through the
        // stop request, so this is a shutdown and never a paging timeout.
        Log("INFO", "Paging wait abandoned at shutdown; no Service Request was sent");
    if (mobility.pending != PendingProcedure::NONE)
        // The same rule for a procedure rather than a wait: a stop request
        // abandons it and reports it as abandoned, never as a timeout and
        // never as a completion that did not happen.
        Log("INFO", std::string(ToString(mobility.pending)) + " abandoned at shutdown; no outcome was invented");
    Log("INFO", "User-plane statistics: tun-ul=" + std::to_string(tunUplinkPackets) + "/" +
                    std::to_string(tunUplinkBytes) + " tun-dl=" + std::to_string(tunDownlinkPackets) + "/" +
                    std::to_string(tunDownlinkBytes) + " drops(malformed/inactive)=" +
                    std::to_string(malformedDrops) + "/" + std::to_string(bearerInactiveDrops));
    if (uuTransport)
        Log("INFO", "DRB user-plane statistics: ul=" + std::to_string(uuUplinkPackets) + "/" +
                        std::to_string(uuUplinkBytes) + " dl=" + std::to_string(uuDownlinkPackets) + "/" +
                        std::to_string(uuDownlinkBytes) + " configurations=" +
                        std::to_string(uuDrbConfigurations) + " drops=" + std::to_string(uuDrbDrops));
    uuDrbs.reset();
    Log("INFO", "NAS security counts: UL-next=" + std::to_string(security.ulNasCount) +
                    " DL-last=" + std::to_string(security.dlNasCount));
    Log("INFO", "Paging statistics: indications=" + std::to_string(pagingIndications) +
                    " matched=" + std::to_string(pagingMatched) +
                    " ignored=" + std::to_string(pagingIgnored) +
                    " duplicate-trigger-suppressed=" + std::to_string(pagingSuppressed) +
                    " service-requests=" + std::to_string(pagingServiceRequests) +
                    " restorations=" + std::to_string(pagingRestorations) +
                    " restoration-failures=" + std::to_string(pagingRestorationFailures));
    Log("INFO", "Access-recovery statistics: losses=" + std::to_string(accessLosses) +
                    " restorations=" + std::to_string(recoveryRestorations) +
                    " failures=" + std::to_string(recoveryFailures) +
                    " attempts=" + std::to_string(recoveryAttempts) +
                    " access-unavailable-drops=" + std::to_string(accessUnavailableDrops) +
                    " dedicated-ul=" + std::to_string(dedicatedUplinkPackets) +
                    " dedicated-dl=" + std::to_string(dedicatedDownlinkPackets));
    tun.reset();
    Log("INFO", "LTE UE shutdown complete");
    return 0;
}
} // namespace lte::ue
