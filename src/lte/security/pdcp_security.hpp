//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

// Phase 18-F-B5: the minimum PDCP security foundation the AS security
// procedure needs (TS 36.323 5.5, TS 33.401 5.1.3.2).
//
// One entity is one direction of one bearer: it owns that direction's COUNT,
// its HFN, its keys and its activation state. This repository has no PDCP
// entity on the radio path (the simulator link carries control frames, not
// PDCP PDUs), so this is a library with its own tests rather than a rewrite of
// a stack that does not exist.
//
// It implements exactly what the procedure needs: the 12-bit SN data PDU with
// an optional 32-bit MAC-I, COUNT reconstruction with HFN rollover, EIA
// integrity, EEA ciphering, replay rejection.
#pragma once

#include "kdf.hpp"

#include <array>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

namespace lte::security
{

enum class PdcpSecurityError : uint8_t
{
    NOT_CONFIGURED,
    ALGORITHM_UNSUPPORTED,
    KEY_MISSING,
    PDU_TOO_SHORT,
    NOT_A_DATA_PDU,
    INTEGRITY_FAILURE,
    REPLAY_DETECTED,
    COUNT_EXHAUSTED,
};

const char *ToString(PdcpSecurityError error);

class PdcpSecurityException : public std::runtime_error
{
  public:
    explicit PdcpSecurityException(PdcpSecurityError reason);

    [[nodiscard]] PdcpSecurityError Reason() const noexcept
    {
        return reason_;
    }

  private:
    PdcpSecurityError reason_;
};

// The bearer identities used in the MAC input (TS 33.401 5.1.3.2): SRB1 is 1,
// DRBs start at 3 in this simulator's numbering.
constexpr uint8_t Srb1Bearer = 1;

// The payload of a PDCP data PDU without its header and, when present, its
// MAC-I. TS 36.331 requires a UE to parse the SecurityModeCommand before it can
// verify it (the command carries the algorithm that selects the key), so the
// payload must be reachable without unprotecting anything.
[[nodiscard]] std::vector<uint8_t> ExtractPdcpPayload(const std::vector<uint8_t> &pdu, bool hasMac);

class PdcpSecurityEntity
{
  public:
    PdcpSecurityEntity() = default;
    ~PdcpSecurityEntity();

    // Builds the entity for one direction of one bearer. The integrity and
    // ciphering algorithms are fixed at creation; ActivateIntegrity and
    // ActivateCiphering are what the security-mode procedure moves.
    // `uplink` selects the DIRECTION bit of the MAC input (TS 33.401 5.1.3.2):
    // 0 for uplink, 1 for downlink. One entity handles one direction.
    static PdcpSecurityEntity Create(uint8_t bearer, bool uplink, uint8_t integrityAlgorithm,
                                     uint8_t cipheringAlgorithm, const Key128 &kIntegrity, const Key128 &kCiphering);

    // EIA0/EEA0 are legal but protect nothing; the entity reports that rather
    // than pretending otherwise.
    [[nodiscard]] bool IntegrityProtects() const;
    [[nodiscard]] bool CipheringProtects() const;

    // The normative activation points. Activating with a missing key is
    // refused rather than applied to an empty key.
    void ActivateIntegrity();
    void ActivateCiphering();
    void DeactivateAll() noexcept;

    [[nodiscard]] bool IntegrityActive() const noexcept
    {
        return integrityActive_;
    }
    [[nodiscard]] bool CipheringActive() const noexcept
    {
        return cipheringActive_;
    }
    [[nodiscard]] uint8_t Bearer() const noexcept
    {
        return bearer_;
    }
    [[nodiscard]] uint32_t NextTxCount() const noexcept
    {
        return txCount_;
    }
    [[nodiscard]] uint32_t LastRxCount() const noexcept
    {
        return rxCount_;
    }

    // Protects one SDU and consumes the next COUNT.
    [[nodiscard]] std::vector<uint8_t> Protect(const std::vector<uint8_t> &plain);

    // Verifies and deciphers one PDU. A PDU whose COUNT has already been
    // accepted is a replay and is refused.
    [[nodiscard]] std::vector<uint8_t> Unprotect(const std::vector<uint8_t> &pdu);

  private:
    uint32_t BuildCount(uint32_t sn) const;
    uint32_t MacFor(uint32_t count, const uint8_t *data, size_t length) const;

    uint8_t bearer_{0};
    bool uplink_{true};
    uint8_t integrityAlgorithm_{0};
    uint8_t cipheringAlgorithm_{0};
    Key128 kIntegrity_{};
    Key128 kCiphering_{};
    bool integrityActive_{false};
    bool cipheringActive_{false};
    uint32_t txCount_{0};
    uint32_t rxCount_{0};
    bool rxAny_{false};
};

} // namespace lte::security
