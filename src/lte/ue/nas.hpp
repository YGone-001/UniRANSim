//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

// EPS NAS and ESM primitives used by the LTE UE vertical slice.
#pragma once

#include "types.hpp"

#include <array>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <vector>

namespace lte::ue::nas
{

class DecodeError : public std::runtime_error
{
  public:
    using std::runtime_error::runtime_error;
};

struct AuthenticationRequest
{
    uint8_t ksi{};
    std::array<uint8_t, 16> rand{};
    std::array<uint8_t, 16> autn{};
};

enum class AkaFailure
{
    NONE,
    MALFORMED,
    MAC_FAILURE,
    SYNCHRONIZATION_FAILURE
};

struct AkaResult
{
    AkaFailure failure{AkaFailure::MALFORMED};
    std::array<uint8_t, 8> res{};
    SecurityContext context{};
};

std::vector<uint8_t> EncodeImsi(const std::string &imsi);
std::vector<uint8_t> EncodeAttachRequest(const Config &config);
AuthenticationRequest DecodeAuthenticationRequest(const uint8_t *data, size_t size);
std::vector<uint8_t> EncodeAuthenticationResponse(const std::array<uint8_t, 8> &res);
std::vector<uint8_t> EncodeAuthenticationFailureMac();
bool IsSecurityModeCommand(const uint8_t *data, size_t size);
AkaResult Authenticate(const Config &config, const AuthenticationRequest &request);

// --- Phase 2: Security Mode Command -----------------------------------------

// Plain Security Mode Command body (TS 24.301 8.2.10), after the outer
// security header has been stripped and the message body recovered.
struct SecurityModeCommand
{
    IntegrityAlgorithm integrity{IntegrityAlgorithm::EIA0};
    CipheringAlgorithm ciphering{CipheringAlgorithm::EEA0};
    uint8_t ksi{};
    bool nativeContext{true};
    // Exact replayed UE security capability octets (EEA/EIA, and UEA/UIA/GEA
    // when the network echoes a longer form).
    std::vector<uint8_t> replayedCapabilities;
    bool imeisvRequested{};
    bool hashMmePresent{};
    // TS 24.301 9.9.3.50 HashMME is 8 octets.
    std::array<uint8_t, 8> hashMme{};
};

// Decodes the still-plain body of a Security Mode Command. The caller has
// already verified the message identity; this only parses the IEs.
SecurityModeCommand DecodeSecurityModeCommand(const uint8_t *data, size_t size);

// Validates the SMC against the live context and configuration: selected
// algorithms must be supported (EIA0 is rejected), the KSI must be usable, and
// the replayed UE security capabilities must match what the UE advertised.
// Throws DecodeError on any violation. On success the context's algorithm and
// KSI fields are updated (but not yet marked securityActive).
void ValidateSecurityModeCommand(const Config &config, const SecurityModeCommand &command, SecurityContext &context);

// Builds the plain Security Mode Complete body (TS 24.301 8.2.9), including the
// IMEISV when the network requested one.
std::vector<uint8_t> EncodeSecurityModeComplete(const Config &config, bool includeImeisv);

// --- Phase 2: ESM and Attach Accept ----------------------------------------

struct ActivateDefaultEpsBearerContextRequest
{
    uint8_t epsBearerIdentity{};
    uint8_t procedureTransactionId{};
    uint8_t qci{};
    std::string apn;
    std::array<uint8_t, 4> pdnAddress{};
    std::vector<uint8_t> raw;
};

struct EsmInformationRequest
{
    uint8_t procedureTransactionId{};
    std::optional<std::string> apn;
};

struct AttachAccept
{
    uint8_t attachResult{};
    uint8_t t3412{};
    std::vector<uint8_t> taiList;
    std::vector<uint8_t> esmContainer;
    std::optional<std::array<uint8_t, 11>> guti;
    // Embedded default bearer activation, when the ESM container carried one.
    std::optional<ActivateDefaultEpsBearerContextRequest> bearer;
};

struct TauAccept
{
    uint8_t updateResult{};
    std::optional<uint8_t> t3412;
    std::optional<std::vector<uint8_t>> taiList;
    std::optional<std::array<uint8_t, 11>> guti;
    std::optional<uint16_t> bearerContextStatus;
};

// Decoded form of the protected downlink EMM message the UE must react to.
enum class DownlinkEmm
{
    SECURITY_MODE_COMMAND,
    ATTACH_ACCEPT,
    ATTACH_REJECT,
    DETACH_ACCEPT,
    SERVICE_REJECT,
    TAU_ACCEPT,
    TAU_REJECT,
    ESM_INFORMATION_REQUEST,
    OTHER
};

struct DownlinkMessage
{
    DownlinkEmm type{DownlinkEmm::OTHER};
    uint8_t messageType{};
    SecurityModeCommand securityModeCommand{};
    AttachAccept attachAccept{};
    TauAccept tauAccept{};
    EsmInformationRequest esmInformationRequest{};
    uint8_t emmCause{};
};

// Parses a plain EMM/ESM message that has already been security-unprotected.
DownlinkMessage DecodeDownlink(const uint8_t *data, size_t size);

// Encodes the plain Activate Default EPS Bearer Context Accept (TS 24.301
// 8.3.2) for inclusion in the Attach Complete ESM container.
std::vector<uint8_t> EncodeActivateDefaultEpsBearerContextAccept(uint8_t epsBearerIdentity, uint8_t procedureTransactionId);

// Encodes the plain Attach Complete (TS 24.301 8.2.3) carrying the default
// bearer acceptance inside the ESM message container.
std::vector<uint8_t> EncodeAttachComplete(const std::vector<uint8_t> &esmAccept);

// Encodes the plain ESM Information Response (TS 24.301 8.3.11).
std::vector<uint8_t> EncodeEsmInformationResponse(uint8_t procedureTransactionId, const std::optional<std::string> &apn);

// True when the message is an ESM Information Request (used to keep the happy
// path optional while still supporting the procedure).
bool IsEsmInformationRequest(const uint8_t *data, size_t size);

std::vector<uint8_t> EncodeDetachRequest(uint8_t ksi, const std::array<uint8_t, 11> &guti, bool switchOff);
std::vector<uint8_t> EncodeTauRequest(uint8_t ksi, const std::array<uint8_t, 11> &guti,
                                      uint8_t defaultEbi, bool periodic);
std::vector<uint8_t> EncodeTauComplete();

} // namespace lte::ue::nas
