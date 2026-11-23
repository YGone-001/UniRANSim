# LTE RLC AM state machine

Phase 18-F-B6-B1-R2-C3. The observable states, the sequence variables they are
computed from, and the transitions the runtime tests exercise.

## Entity states

| State | Meaning |
|---|---|
| `ACTIVE` | accepts submissions, PDUs and ticks |
| `FAILED` | `maxRetx` reached; buffers dropped; nothing is accepted or processed |
| `RELEASED` | released by its owner; everything is ignored and `SubmitSdu` throws |

`Release()` drops the transmission and reception buffers. `Fail()` drops the
transmission buffer and keeps the state terminal. A released or failed entity
still consumes frames delivered to its socket; it simply does nothing with them,
which is what makes a stale frame harmless after a context is torn down.

## Sequence variables

| Variable | Meaning |
|---|---|
| VT(A) | first SN not yet acknowledged; the transmission window starts here |
| VT(S) | next SN to assign |
| VR(R) | first SN not yet delivered in order; the reception window starts here |
| VR(H) | highest SN received plus one |
| Window | `AmWindow` = 512 outstanding SNs |

Every comparison goes through one `Distance(from, to)` helper over modulus 1024;
no call site compares SNs with `<`.

## Transitions

| Trigger | Effect |
|---|---|
| `SubmitSdu` | segments into `maxPduBytes - 2` byte chunks, stores each with its FI, emits, advances VT(S); refuses when `Distance(VT(A), VT(S)) >= 512` |
| `SubmitSdus` | packs whole SDUs into one PDU with an E/LI chain, refuses if they do not fit |
| `OnPdu`, in window | merges only the byte ranges not already held, updates VR(H), marks a report pending |
| `OnPdu`, `sn == VR(R)` and complete | delivers in order, advances VR(R), keeps reporting |
| `OnPdu`, out of window | counts the drop and marks a report pending |
| `OnStatusPdu` | advances VT(A) over the ACK_SN, then acts on every NACK |
| `OnTick` | t-StatusProhibit, t-Reordering, t-PollRetransmit in that order |
| `maxRetx` reached | `FAILED` |

## Timers

| Timer | Ticks | Action |
|---|---|---|
| t-PollRetransmit | `pollTicks` | resend the oldest unacknowledged PDU with P=1 |
| t-Reordering | `reorderingTicks` | report the gap again; VR(R) does **not** move |
| t-StatusProhibit | `prohibitTicks` | hold a pending report |

t-Reordering expiry is the one behaviour this phase changed. The earlier
implementation moved VR(R) to VR(H), which acknowledged past the hole; because
the STATUS report is computed over `[VR(R), VR(H))`, the missing SN was then
never named again and the SDU was lost silently. The timer now leaves VR(R)
alone and simply makes the pending report due, so the peer retransmits the gap.
TS 36.322 5.2.2.4 updates RX_Highest_Status on expiry, not RX_Next.

## Delivery

Delivery is driven by `VR(R)` and the FI of the first and last segment:

- `COMPLETE/COMPLETE` with no LI: one SDU.
- `COMPLETE/COMPLETE` with an LI chain: split at every LI, the last element
  takes the remainder.
- `FIRST_SEGMENT` starts an assembly, `LAST_SEGMENT` completes it, middle
  segments append. Nothing is delivered piece by piece.
