//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#include "tai.hpp"

#include <exception>

#include <lte/enb/codec.hpp>

namespace lte::ue
{

namespace
{

// One validated sub-list: the form it took and the explicit TAIs it carries.
struct SubList
{
    TaiListForm form{};
    std::vector<Tai> tais;
};

uint16_t ReadTac(const uint8_t *data)
{
    return static_cast<uint16_t>((static_cast<uint16_t>(data[0]) << 8U) | static_cast<uint16_t>(data[1]));
}

// Parses the whole value. On success returns true and fills `out`; on failure
// returns false and leaves a description of the first defect in `error`,
// having produced no TAIs at all. A value that cannot be trusted in full is
// not trusted in part.
bool Parse(const std::vector<uint8_t> &value, std::vector<Tai> &out, std::string &error)
{
    out.clear();
    error.clear();

    if (value.empty())
    {
        error = "the TAI list value is empty";
        return false;
    }
    if (value.size() > MaxTaiListValueLength)
    {
        error = "the TAI list value exceeds " + std::to_string(MaxTaiListValueLength) + " octets";
        return false;
    }

    std::vector<Tai> parsed;
    size_t offset = 0;
    while (offset < value.size())
    {
        const size_t remaining = value.size() - offset;
        const uint8_t header = value[offset];

        // TS 24.301 9.9.3.33: the header octet is spare:1 | type:2 | num:5
        // from the most significant bit. The spare bit is ignored on receipt
        // per TS 24.007, and num counts one fewer than the TAIs carried.
        const auto type = static_cast<int>((header >> 5U) & 0x03U);
        const size_t count = static_cast<size_t>(header & 0x1FU) + 1U;

        if (type == 3)
        {
            error = "tracking area identity list sub-list type 3 is reserved";
            return false;
        }

        const size_t needed = type == static_cast<int>(TaiListForm::OnePlmnListedTacs)   ? 1U + 3U + 2U * count
                              : type == static_cast<int>(TaiListForm::SeveralPlmns)     ? 1U + 5U * count
                                                                                        : 6U;
        if (remaining < needed)
        {
            error = "a tracking area identity list sub-list is truncated";
            return false;
        }

        SubList sub;
        sub.form = static_cast<TaiListForm>(type);
        try
        {
            if (type != static_cast<int>(TaiListForm::SeveralPlmns))
            {
                // Types 0 and 1 carry a single PLMN ahead of the TAC field(s).
                const enb::Plmn plmn = enb::s1ap::DecodePlmn(value.data() + offset + 1U, 3U);
                if (type == static_cast<int>(TaiListForm::OnePlmnConsecutiveTacs))
                {
                    const uint16_t start = ReadTac(value.data() + offset + 4U);
                    if (static_cast<uint32_t>(start) + static_cast<uint32_t>(count) - 1U > 0xFFFFU)
                    {
                        error = "a type 1 tracking area identity list sub-list range overflows the TAC space";
                        return false;
                    }
                    for (size_t i = 0; i < count; ++i)
                        sub.tais.push_back(Tai{plmn, static_cast<uint16_t>(start + i)});
                }
                else
                {
                    for (size_t i = 0; i < count; ++i)
                        sub.tais.push_back(Tai{plmn, ReadTac(value.data() + offset + 4U + 2U * i)});
                }
            }
            else
            {
                // Type 2 pairs every PLMN with its own TAC.
                for (size_t i = 0; i < count; ++i)
                {
                    const enb::Plmn plmn = enb::s1ap::DecodePlmn(value.data() + offset + 1U + 5U * i, 3U);
                    sub.tais.push_back(Tai{plmn, ReadTac(value.data() + offset + 4U + 5U * i)});
                }
            }
        }
        catch (const std::exception &e)
        {
            error = std::string("a tracking area identity list sub-list carries an invalid PLMN identity: ") + e.what();
            return false;
        }

        if (parsed.size() + sub.tais.size() > MaxParsedTaiCount)
        {
            error = "the TAI list expands to more than " + std::to_string(MaxParsedTaiCount) + " tracking areas";
            return false;
        }
        parsed.insert(parsed.end(), sub.tais.begin(), sub.tais.end());
        offset += needed;
    }

    out = std::move(parsed);
    return true;
}

} // namespace

bool SamePlmn(const enb::Plmn &left, const enb::Plmn &right)
{
    try
    {
        return enb::s1ap::EncodePlmn(left) == enb::s1ap::EncodePlmn(right);
    }
    catch (const std::exception &)
    {
        // A PLMN that cannot be encoded is not a PLMN this module can compare,
        // and it is never equal to anything.
        return false;
    }
}

bool operator==(const Tai &left, const Tai &right)
{
    return left.tac == right.tac && SamePlmn(left.plmn, right.plmn);
}

bool operator!=(const Tai &left, const Tai &right)
{
    return !(left == right);
}

std::string TaiListError(const std::vector<uint8_t> &value)
{
    std::vector<Tai> parsed;
    std::string error;
    Parse(value, parsed, error);
    return error;
}

bool ParseTaiList(const std::vector<uint8_t> &value, std::vector<Tai> &out)
{
    std::string error;
    return Parse(value, out, error);
}

bool TaiListContains(const std::vector<Tai> &list, const Tai &tai)
{
    for (const auto &candidate : list)
        if (candidate == tai)
            return true;
    return false;
}

} // namespace lte::ue
