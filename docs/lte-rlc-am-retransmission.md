# LTE RLC AM retransmission

Phase 18-F-B6-B1-R2-C3. How the transmitter reacts to a STATUS report, and what
the receiver reports.

## What the receiver reports

`STATUS` carries `ACK_SN = VR(R)` and a NACK for every SN in
`[VR(R), VR(H))` that is not fully reconstructed:

| Situation | NACK |
|---|---|
| no byte of the SN arrived | whole-PDU NACK, no SO range |
| some bytes arrived, the last byte did not | `[covered, 0x7FFF]` |
| the last byte arrived but a middle range is missing | each missing range `[start, end]` |
| the SN is complete | no NACK |

`0x7FFF` is the "to the end of the SDU" value: it says the tail is missing.

## What the transmitter does with it

- **ACK_SN** advances VT(A) and erases every stored SN below it. Erasure is the
  only way a transmission leaves the buffer, and VT(A) only moves on an ACK.
- **Whole-PDU NACK** re-sends the stored Data field with its original FI and its
  original LI chain, so the SDU boundaries cannot change in flight.
- **Partial NACK** slices `[SOstart, min(SOend, size-1)]` out of the stored Data
  and sends one replacement AMD segment with `SO = SOstart`, and `LSF` when the
  slice reaches the end of the original data. The SN is unchanged.
- **LI on a replacement.** The LI chain sits at the start of the PDU data, so a
  replacement that starts at offset zero carries it and one that starts later
  does not. It is only sent when the prefix it describes fits inside the slice;
  a longer chain would be refused by the receiver's decode.

Each transmission attempt increments the SN's counter. Reaching `maxRetx` fails
the entity instead of retrying forever, and a failed entity drops its buffer.

## Duplicates and overlap

Reception merges only the byte ranges the receiver does not already hold. A
duplicated PDU that lands before its gap is closed therefore contributes
nothing, and an overlapping retransmission adds only its missing bytes. Without
that rule the reassembly concatenates the duplicate a second time and delivers a
corrupt SDU of twice the length, which is what
`lte/rlc-am-uu/a duplicated pdu that arrives before its gap is delivered once`
pins down.

## Polling

When `pollTicks` expires and something is still unacknowledged, the transmitter
re-sends the oldest stored PDU with P=1. The receiver answers any PDU with a
pending report, so a lost STATUS or a lost NACK is recovered without the
transport retrying anything. The tests cover both cases:

- `a lost status is recovered by the poll timer without a false ack`
- `the poll timer retransmits while the peer is silent`

## Limits

No SDU discard, no re-establishment, no peer status polling (no P=1 on demand
from an upper layer). A reordering expiry reports the gap but does not itself
retransmit anything; only the peer's STATUS or poll can.