//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

// Phase 18-F-B5-R1: the LTE PDCP bearer profiles of TS 36.323 Release 18.
//
// The B5 foundation used one PDU shape for every bearer and never ciphered the
// MAC-I. Both were wrong for LTE:
//
//   Control plane (SRB):  1-octet header, 5-bit SN, three reserved bits, NO D/C,
//                         32-bit MAC-I always present and CIPHERED with the data.
//   User plane (DRB 12):  2-octet header, D/C = 1, 12-bit SN, NO MAC-I.
//
// One entity is one direction of one bearer and owns that direction's COUNT,
// HFN, keys and activation state. The two profiles never share sequence state.
#pragma once

#include "kdf.hpp"

#include <array>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

namespace lte::security
{

enum class PdcpProfile : uint8_t
{
    SRB,
    DRB12,
};

[[nodiscard]] const char *ToString(PdcpProfile profile);
[[nodiscard]] uint8_t PdcpSnBits(PdcpProfile profile);
[[nodiscard]] uint8_t PdcpHeaderLength(PdcpProfile profile);
[[nodiscard]] bool PdcpHasMacI(PdcpProfile profile);

// TS 36.331 radio bearer identity. The value handed to EEA/EIA is the identity
// minus one (TS 36.323 6.3.5, TS 33.401 5.1.3.2), so SRB1 maps to BEARER 0.
// Keeping the two numbers in one type is what stops them being confused.
struct RadioBearerIdentity
{
    uint8_t rbId{0};

    [[nodiscard]] bool Valid() const;
    [[nodiscard]] uint8_t BearerField() const;

    static constexpr RadioBearerIdentity Srb1()
    {
        return RadioBearerIdentity{1};
    }
    static constexpr RadioBearerIdentity Srb2()
    {
        return RadioBearerIdentity{2};
    }
    static constexpr RadioBearerIdentity Drb(uint8_t id)
    {
        return RadioBearerIdentity{id};
    }
};

enum class PdcpSecurityError : uint8_t
{
    NOT_CONFIGURED,
    ALGORITHM_UNSUPPORTED,
    KEY_MISSING,
    UNSUPPORTED_PROFILE,
    UNSUPPORTED_BEARER,
    PDU_TOO_SHORT,
    MALFORMED_HEADER,
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

// The data field of a PDU without its header and, for SRB, its MAC-I. A UE must
// parse the SecurityModeCommand before it can verify it (the command carries
// the algorithm that selects the key), so the field has to be reachable
// without unprotecting anything.
[[nodiscard]] std::vector<uint8_t> ExtractPdcpPayload(const std::vector<uint8_t> &pdu, PdcpProfile profile);

class PdcpSecurityEntity
{
  public:
    PdcpSecurityEntity() = default;
    ~PdcpSecurityEntity();

    PdcpSecurityEntity(const PdcpSecurityEntity &) = delete;
    PdcpSecurityEntity &operator=(const PdcpSecurityEntity &) = delete;
    PdcpSecurityEntity(PdcpSecurityEntity &&other) noexcept;
    PdcpSecurityEntity &operator=(PdcpSecurityEntity &&other) noexcept;

    static PdcpSecurityEntity Create(PdcpProfile profile, RadioBearerIdentity bearer, bool uplink,
                                     uint8_t integrityAlgorithm, uint8_t cipheringAlgorithm,
                                     const Key128 &kIntegrity, const Key128 &kCiphering);

    [[nodiscard]] PdcpProfile Profile() const noexcept
    {
        return profile_;
    }
    [[nodiscard]] uint8_t BearerField() const noexcept
    {
        return bearer_.BearerField();
    }
    [[nodiscard]] bool IntegrityProtects() const;
    [[nodiscard]] bool CipheringProtects() const;

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
    [[nodiscard]] uint32_t NextTxCount() const noexcept
    {
        return txCount_;
    }
    [[nodiscard]] uint32_t LastRxCount() const noexcept
    {
        return rxCount_;
    }

    [[nodiscard]] std::vector<uint8_t> Protect(const std::vector<uint8_t> &plain);
    [[nodiscard]] std::vector<uint8_t> Unprotect(const std::vector<uint8_t> &pdu);

  private:
    [[nodiscard]] uint32_t BuildCount(uint32_t sn) const;
    [[nodiscard]] uint32_t MacFor(uint32_t count, const uint8_t *data, size_t length) const;
    void Cipher(uint32_t count, uint8_t *data, size_t length, bool encipher) const;

    PdcpProfile profile_{PdcpProfile::DRB12};
    RadioBearerIdentity bearer_{};
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
