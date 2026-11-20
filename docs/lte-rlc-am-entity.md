# LTE RLC AM entity

Phase 18-F-B6-B1-R2. `src/lte/rrc-runtime/lte_am.{hpp,cpp}`, on top of the LTE
codec in `rlc_am.{hpp,cpp}`.

## Why its own entity

`src/lib/rlc/entity_am` is the NR engine: its header-size helper takes the NR
segment-info enum, its segmentation consumes `sdu->si`, and its STATUS path takes
an NR `StatusPdu`. Adapting it would mean inventing NR headers from LTE RF/FI/LSF,
which loses information. This entity therefore owns its own state and reuses only
the protocol-neutral ideas.

## What it implements

| Area | Behaviour |
|---|---|
| Sequence numbers | 10-bit, modulus 1024, one `Distance()` helper for every comparison |
| TX | VT(A), VT(S), 512-window, segmentation into `maxPduBytes - 2` chunks with FI first/middle/last |
| Retransmission | stored Data plus FI per SN; whole-PDU NACK re-sends it; partial NACK re-segments to the requested SO range |
| Polling | t-PollRetransmit on tick re-sends the oldest unacknowledged PDU with P=1 |
| Max retransmission | reaching `maxRetx` fails the entity (`FAILED`) and drops its buffers |
| RX | VR(R), VR(H), in-order delivery, out-of-order buffering, duplicate rejection, SDU reassembly across PDUs by FI |
| t-Reordering | on expiry the receiver advances to VR(H) and reports the gap |
| t-StatusProhibit | gates STATUS transmission after each report |
| STATUS | ACK_SN = VR(R), whole-PDU NACKs for every missing SN in the window |

## Boundaries

No PDCP, no SRB1 activation, no RRC connection state, no NAS and no S1AP. The
entity is driven by a caller that owns the transport and the tick; it has no
clock of its own. Partial NACK *generation* is not implemented: the receiver
reports whole-PDU gaps, while the transmitter does honour a partial NACK it
receives by re-segmenting.

## Limitations

- 10-bit SN and 11-bit LI only; 16-bit SN and 15-bit LI are not implemented.
- No SDU discard, no re-establishment, no status-report polling of the peer.
- The reordering timer discards the gap when it expires rather than continuing to
  wait, which is the LTE behaviour for a missing PDU that never arrives.
