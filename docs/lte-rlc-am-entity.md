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
| t-Reordering | on expiry the receiver reports the gap again and keeps VR(R) at the hole |
| t-StatusProhibit | gates STATUS transmission after each report |
| STATUS | ACK_SN = VR(R), whole-PDU NACKs for every missing SN in the window |

The receiver reports whole-PDU NACKs and, for a partly received PDU, the exact
missing byte range (C1); the transmitter honours either by re-sending the stored
Data field or by re-segmenting it to the requested range. Reception merges only
the bytes it does not already hold, so a duplicate that arrives before its gap is
closed cannot corrupt the reassembly.

## Runtime

The entity no longer runs only through an in-process harness:
`lte_am_bearer.{hpp,cpp}` binds one entity to one `uu::Socket` and one
association, and `test/lte/lte_am_uu.cpp` drives two such endpoints through the
real transport - in one process and in two - with a test-owned link node that
drops, duplicates, delays, reorders or re-segments frames deterministically.

- [lte-rlc-am-engine.md](lte-rlc-am-engine.md) - ownership and data path
- [lte-rlc-am-state-machine.md](lte-rlc-am-state-machine.md) - states, variables, timers
- [lte-rlc-am-retransmission.md](lte-rlc-am-retransmission.md) - NACK handling and duplicates
- [lte-rlc-am-pdu-format.md](lte-rlc-am-pdu-format.md) - octets and evidence fields

## Boundaries

No PDCP, no SRB1 activation, no RRC connection state, no NAS and no S1AP. The
entity is driven by a caller that owns the transport and the tick; it has no
clock of its own.

## Limitations

- 10-bit SN and 11-bit LI only; 16-bit SN and 15-bit LI are not implemented.
- No SDU discard, no re-establishment, no status-report polling of the peer.
- The entity has no generation counter. A released entity ignores what arrives,
  and a replacement binds a new socket, but an in-window frame addressed to a
  live entity is still accepted; only the socket identity separates two
  generations.
