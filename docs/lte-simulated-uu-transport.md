# Simulated Uu bearer transport

Phase 18-F-B6-A. `src/lte/rrc-runtime/uu_transport.{hpp,cpp}`.

This is a **simulator bearer**, not physical radio. It exists so RRC messages can
travel through RLC instead of over a bespoke RRC-over-UDP shortcut.

## Envelope

```text
magic 'U','U' | version 1 | reserved 0 | association (u32 BE)
             | direction (0 uplink, 1 downlink) | logical channel (0 CCCH, 1 DCCH)
             | payload length (u16 BE) | payload
```

The envelope is routing metadata. It never names an RRC message type, so a peer
can only obtain an RRC PDU by delivering the payload through RLC. The payload is
limited to 2048 bytes and is preserved byte for byte.

A frame is rejected for a bad magic, a wrong version or reserved byte, an unknown
direction or channel, a payload above the maximum, or a declared length that does
not match the datagram. Rejections are counted, not delivered.

## Reliability boundary

There is **no** hidden ACK, retransmission, sequence number, reordering or
deduplication. The link model (drop / duplicate / reorder every Nth frame) exists
so tests can make loss observable; nothing in the transport repairs it. RLC TM
does not repair it either, which is why a lost RRCConnectionRequest stays lost and
the UE fails on timeout.

## Association

The transport association is a simulator-owned identifier that routes a frame to
one UE context. It is **not** a C-RNTI: there is no PRACH, no contention
resolution and no MAC scheduling in this simulator. The association is unique per
UE and validated on receive; a frame for an unknown association is not delivered.
