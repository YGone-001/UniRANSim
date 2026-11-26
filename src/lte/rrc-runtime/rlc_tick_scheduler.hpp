//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//

// Phase 18-F-B6-D10-512-R1A: a deadline scheduler for RLC entities.
//
// The eNB used to tick every DRB and every SRB runtime once per elapsed
// millisecond. With 512 UE contexts that is more than a thousand mostly idle
// entities per tick, and the ticks of the few active entities starve. This
// scheduler holds only entities that have a finite next deadline; an idle
// entity is absent and costs nothing. Entries carry a generation and a version
// so a destroyed or re-created entity can never be ticked by a stale event.
#pragma once

#include <cstddef>
#include <cstdint>
#include <map>

namespace lte::rlc
{

class RlcTickScheduler
{
  public:
    struct Entry
    {
        int64_t deadlineMs{0};
        uint32_t id{0};
        uint8_t subId{0};
        uint64_t generation{0};
        uint64_t version{0};
    };

    // Adds a deadline. The caller owns versioning: a later schedule of the
    // same (id, subId) uses a higher version and leaves the old entry stale.
    void Push(const Entry &entry)
    {
        queue_.emplace(entry.deadlineMs, entry);
    }

    // Removes the earliest entry if it is due. Returns false when the queue is
    // empty or the earliest deadline is still in the future.
    bool PopDue(int64_t nowMs, Entry &out)
    {
        if (queue_.empty() || queue_.begin()->first > nowMs)
            return false;
        out = queue_.begin()->second;
        queue_.erase(queue_.begin());
        return true;
    }

    [[nodiscard]] bool Empty() const
    {
        return queue_.empty();
    }
    [[nodiscard]] size_t Size() const
    {
        return queue_.size();
    }
    [[nodiscard]] int64_t EarliestDeadline() const
    {
        return queue_.empty() ? 0 : queue_.begin()->first;
    }

  private:
    std::multimap<int64_t, Entry> queue_{};
};

} // namespace lte::rlc
