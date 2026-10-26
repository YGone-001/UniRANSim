//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

// EPS NAS security (TS 33.401) used by the Phase 2 LTE UE only.
#pragma once

#include "types.hpp"

#include <array>
#include <cstdint>
#include <stdexcept>
#include <vector>

namespace lte::ue::nas
{

// Algorithm and header-type enums live in types.hpp alongside SecurityContext.
using lte::ue::CipheringAlgorithm;
using lte::ue::IntegrityAlgorithm;
using lte::ue::SecurityHeaderType;

class SecurityError : public std::runtime_error
{
  public:
    using std::runtime_error::runtime_error;
};

bool IsSupported(IntegrityAlgorithm algorithm);
bool IsSupported(CipheringAlgorithm algorithm);
const char *ToString(IntegrityAlgorithm algorithm);
const char *ToString(CipheringAlgorithm algorithm);
const char *ToString(SecurityHeaderType headerType);

// TS 33.401 Annex A.2 / TS 33.220 Annex B.2.0 key derivation with FC 0x15.
// The 128-bit NAS key is the rightmost half of the HMAC-SHA-256 output, matching
// the reference KDF used by the EPC.
std::array<uint8_t, 16> DeriveKnasInt(const std::array<uint8_t, 32> &kasme, IntegrityAlgorithm algorithm);
std::array<uint8_t, 16> DeriveKnasEnc(const std::array<uint8_t, 32> &kasme, CipheringAlgorithm algorithm);

// Wire form of one security-protected NAS message: the outer security header,
// followed by the plain EMM/ESM message that the MAC covers together with the
// sequence number.
struct ProtectedNas
{
    SecurityHeaderType headerType{SecurityHeaderType::PLAIN};
    std::array<uint8_t, 4> mac{};
    uint8_t sequenceNumber{};
    std::vector<uint8_t> plain;
};

// Protects `plain` with the context that is already active (or, for Security
// Mode Complete, the one just accepted). `uplink` selects the COUNT direction.
// `newContext` forces the TS 24.301 "new EPS security context" header types and
// is only valid for the first protected message of a fresh context. The caller
// owns COUNT bookkeeping: the COUNT used is `uplink ? ulNasCount : dlNasCount`
// at entry, and the caller increments it after a successful send/receive.
std::vector<uint8_t> Protect(const SecurityContext &context, bool uplink, bool newContext,
                             const std::vector<uint8_t> &plain);

// Parses the outer header and returns the still-protected payload pieces. The
// caller decides which COUNT to use and then calls UnprotectBody.
ProtectedNas ParseProtectedHeader(const uint8_t *data, size_t size);

// Verifies the MAC over sequenceNumber||body and, when the header says so,
// deciphers `body` in place. Returns the plain NAS message. Throws
// SecurityError on any MAC, algorithm or length failure.
std::vector<uint8_t> UnprotectBody(const SecurityContext &context, bool uplink, SecurityHeaderType headerType,
                                   uint8_t sequenceNumber, const std::array<uint8_t, 4> &mac,
                                   std::vector<uint8_t> body);

// Rebuilds the 24-bit NAS COUNT from a 32-bit running COUNT and the received
// 8-bit sequence number (TS 24.301 4.4.3.1). `lastCount` is the COUNT of the
// previous accepted message in the same direction.
uint32_t EstimateNasCount(uint32_t lastCount, uint8_t sequenceNumber);

// True for the security header types that establish a new EPS security context.
bool StartsNewContext(SecurityHeaderType headerType);
bool IsCiphered(SecurityHeaderType headerType);
// Active-context receive path: verifies integrity and rejects replay/new-context
// headers before committing the accepted downlink COUNT.
std::vector<uint8_t> ReceiveProtectedDownlink(SecurityContext &context, const std::vector<uint8_t> &message);

// TS 24.301 Service Request uses its compact security header (type 12), not a
// normal protected NAS envelope. COUNT is the next uplink NAS COUNT.
std::vector<uint8_t> EncodeServiceRequest(const SecurityContext &context);
uint32_t EstimateServiceRequestCount(uint32_t lastCount, uint8_t shortSequence);
void VerifyServiceRequest(const SecurityContext &context, const uint8_t *data, size_t size,
                          uint32_t lastCount);

} // namespace lte::ue::nas
