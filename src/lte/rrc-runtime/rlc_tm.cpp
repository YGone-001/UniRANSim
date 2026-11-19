//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//

#include "rlc_tm.hpp"

namespace lte::rlc
{

const char *ToString(TmError error)
{
    switch (error)
    {
    case TmError::OVERSIZED_SDU: return "OVERSIZED_SDU";
    case TmError::EMPTY_SDU: return "EMPTY_SDU";
    case TmError::ENTITY_RELEASED: return "ENTITY_RELEASED";
    }
    return "UNKNOWN_TM_ERROR";
}

TmException::TmException(TmError reason)
    : std::runtime_error(std::string("RLC TM refusal: ") + ToString(reason)), reason_(reason)
{
}

TmEntity TmEntity::Create(uint32_t association)
{
    TmEntity entity;
    entity.association_ = association;
    return entity;
}

std::vector<uint8_t> TmEntity::Submit(const std::vector<uint8_t> &sdu)
{
    if (released_)
        throw TmException(TmError::ENTITY_RELEASED);
    if (sdu.empty())
        throw TmException(TmError::EMPTY_SDU);
    if (sdu.size() > MaxSduBytes)
        throw TmException(TmError::OVERSIZED_SDU);
    return sdu;
}

std::vector<uint8_t> TmEntity::Deliver(const std::vector<uint8_t> &pdu)
{
    if (released_)
        throw TmException(TmError::ENTITY_RELEASED);
    if (pdu.empty())
        throw TmException(TmError::EMPTY_SDU);
    if (pdu.size() > MaxSduBytes)
        throw TmException(TmError::OVERSIZED_SDU);
    return pdu;
}

void TmEntity::Release() noexcept
{
    released_ = true;
}

} // namespace lte::rlc
