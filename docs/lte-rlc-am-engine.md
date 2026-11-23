# LTE RLC AM engine

Phase 18-F-B6-B1-R2-C3. Where the LTE AM state lives, what owns the socket, and
how a PDU reaches the peer.

## Layers and ownership

| Layer | File | Owns |
|---|---|---|
| AM state | `src/lte/rrc-runtime/lte_am.{hpp,cpp}` | sequence variables, buffers, timers, delivery |
| Wire codec | `src/lte/rrc-runtime/rlc_am.{hpp,cpp}` | LTE AMD, AMD segment and STATUS octets |
| Bearer | `src/lte/rrc-runtime/lte_am_bearer.{hpp,cpp}` | one entity, one socket, one association |
| Transport | `src/lte/rrc-runtime/uu_transport.{hpp,cpp}` | envelope, loopback datagram, test link model |

The entity has no clock and no transport. It is constructed with a sender and a
deliverer:

```cpp
LteAmEntity entity(config, [](std::vector<uint8_t> pdu) { /* send */ },
                   [](std::vector<uint8_t> sdu) { /* deliver */ });
entity.SubmitSdu(sdu);   // may emit several PDUs through the sender
entity.OnPdu(bytes);     // a received AMD PDU
entity.OnStatusPdu(bytes);
entity.OnTick();         // one timer tick; the caller decides how long it is
```

`LteAmBearer` moves a `uu::Socket` in and wires those callbacks to it:
outgoing PDUs become frames on DCCH, and `Pump(timeoutMs)` receives at most one
frame per call and dispatches it on the D/C bit of the first octet - 1 is an AMD
PDU, 0 a control PDU. The envelope carries no RLC or RRC type, so the transport
stays protocol-neutral, and the association is checked on receive: a frame for a
different association is consumed and dropped.

## Endpoint identity

An endpoint is `(association, local port, peer port)`. Two bearer instances with
different associations therefore never share state, and a replacement context
that binds a new socket cannot be confused with the one it replaced: datagrams
queued for the old port have nowhere to go.

## Integration shapes

- **Single process.** Two bearers, one per endpoint, each bound to its own
  loopback socket. A test may put a relay between them; the relay is the link, it
  is not an entity, and it only ever forwards, drops, duplicates, delays,
  reorders or re-segments frames it received.
- **Separate processes.** Each process builds its own bearer and entity. The
  supervisor owns the peer endpoint and the link, and reconciles the two sides by
  comparing the frame log it produced with the report the other process wrote
  about itself. It never reads or writes the peer's entity state.

The tests in `test/lte/lte_am_uu.cpp` use both shapes. No test calls an entity
of the opposite endpoint directly.

## Data path

```text
SubmitSdu -> EncodeAmd -> uu::Frame{D CCH} -> socket -> EncodeFrame -> UDP
UDP -> DecodeFrame -> frame.payload -> D/C dispatch -> OnPdu/OnStatusPdu
                                                 -> deliverer / sender
```

A frame the link model drops is counted by the socket and reported as sent; the
transport never retries. Recovery is the AM entity's job, which is why a lost PDU
must be visible in the STATUS exchange.

## What is not here

No PDCP, no SRB1 binding, no RRC connection, no AS security on this path. The
entity can be exercised end to end without any of them, and
`SRB1_RLC_AM_READY`, `SRB1_PDCP_RUNTIME_READY`, `RRC_CONNECTION_RUNTIME_READY`
and `AS_SMC_RUNTIME_READY` stay false.
