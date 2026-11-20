//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//

// Phase 18-F-B6-B1-R2-C3: the LTE AM entity on the simulated Uu bearer.
//
// The transport carries opaque RLC PDUs on DCCH; AMD and STATUS are told apart
// by the D/C bit, which is what the LTE header itself uses. No envelope field is
// added and no RRC shortcut exists.
#pragma once

#include "lte_am.hpp"
#include "uu_transport.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace lte::rlc::am
{

class LteAmBearer
{
  public:
    LteAmBearer() = default;

    // The socket is moved in: one bearer owns one transport endpoint.
    LteAmBearer(uu::Socket socket, uint16_t peerPort, uint32_t association, AmConfig config,
                LteAmEntity::Deliverer deliverer);

    void SubmitSdu(const std::vector<uint8_t> &sdu);
    void SubmitSdus(const std::vector<std::vector<uint8_t>> &sdus);

    // Receives at most one frame and dispatches it by the D/C bit. Returns false
    // on timeout, which is normal and never an error.
    bool Pump(int timeoutMs);

    void Tick();

    [[nodiscard]] AmState State() const;
    [[nodiscard]] uint16_t VtA() const;
    [[nodiscard]] uint16_t VtS() const;
    [[nodiscard]] uint16_t VrR() const;
    [[nodiscard]] size_t Delivered() const;
    [[nodiscard]] size_t Sent() const
    {
        return sent_;
    }
    [[nodiscard]] const uu::Socket &Transport() const
    {
        return socket_;
    }
    [[nodiscard]] uu::Socket &Transport()
    {
        return socket_;
    }

    void Release() noexcept;

  private:
    void Send(const std::vector<uint8_t> &pdu);

    uu::Socket socket_{};
    uint16_t peerPort_{0};
    uint32_t association_{0};
    LteAmEntity entity_{};
    size_t sent_{0};
    size_t delivered_{0};
};

} // namespace lte::rlc::am
