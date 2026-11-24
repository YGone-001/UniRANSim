# The production UE over SRB1 (B6-D3)

This is the record of how the production `lte-ue` process carries EPS NAS over
the simulated Uu link, and of what that does and does not prove.

## One downlink entry

`src/lte/ue/app.cpp` has a single NAS downlink function. Both transports deliver
into it:

```text
legacy enbLink datagram (NAS_DOWNLINK)
        \\
         >-- deliverNas() -> handleNasDownlink() -> the one NAS state machine
        /
UuNasTransport callback -> queue -> deliverNas()
```

The callback only appends the NAS bytes to a queue; the loop calls
`handleNasDownlink` on the UE thread after `Pump`. No application state is
mutated from inside the RRC runtime, and a message cannot be handled twice: each
transport delivers its own datagram once and the queue is drained once per
iteration.

## Ownership and startup order

When `uu` is configured the application constructs and owns one
`lte::ue::UuNasTransport`, registers the downlink callback, binds the configured
local endpoint and starts `RRCConnectionRequest`. A bind failure throws: there is
no loopback substitution and no fallback to `enbLink`.

```text
UuNasTransport::Start (bind + RRCConnectionRequest)
  -> RRCConnectionSetup
  -> RRCConnectionSetupComplete carrying the first NAS (Attach Request)
  -> RRC_CONNECTED
  -> later NAS in ULInformationTransfer
```

The Attach Request is built at startup but is not handed to the transport until
`SendNas` accepts it, which it only does once the RRC connection can carry it.
No sleep is used to order the two.

## One uplink interface

`sendNas` is the only path for Attach Request, Authentication Response, Security
Mode Complete and Attach Complete. In Uu mode it calls the transport; a false
return fails the run, it is never retried on the legacy link. In legacy mode it
sends the same frames as before.

When NAS security activates, the application calls
`UuNasTransport::PrepareAsSecurity(KASME, uplink NAS COUNT, generation)` so the
RRC runtime expects the `SecurityModeCommand` and derives the same KeNB the MME
put in the Initial Context Setup Request.

## Poll loop

The existing loop calls `Pump(0)` and `Tick()` on the transport every iteration.
With a transport present the legacy receive timeout is bounded to 5 ms instead of
50/250 ms, so RRC/RLC timers advance rather than sleeping inside the legacy
socket. The loop is not made busy: `Pump(0)` is a `poll` with zero timeout.

## What is deliberately not migrated

`uu.enabled` accepts `lifecycle.scenario = ATTACH_ONLY` and
`ATTACH_DETACH`; any other scenario is refused at startup rather than silently
sending its NAS over the legacy link. The Detach that closes the same session is
covered in `docs/lte-production-ue-srb1-detach.md`. Paging, recovery, TAU, the
default bearer user plane and GTP-U remain legacy.
`LTE_DEFAULT_BEARER_OVER_SRB1_READY` and `LTE_OPEN5GS_ATTACH_ACCEPTED` stay
false.

## Two-process acceptance

`tools/lte-uu-attach-peer.cpp` is the second process. It hosts the production
`EnbRrcBridge` over a real Uu socket and a deterministic MME that runs Milenage
EPS AKA, NAS security (EIA2/EEA0) and the Attach exchange. It verifies the
Authentication Response, the Security Mode Complete and the Attach Complete with
the production NAS encoders and MAC verification, then writes a result file.

`test/lte/production_uu_attach.cpp` starts both halves: the peer first, then the
real `lte-ue` configured with a `uu` block, running unprivileged so the Attach is
control-plane-only. The case is opt-in:

```bash
UNIRANSIM_RUN_TWO_PROCESS_ATTACH=1 ./cmake-build-release/nr-tests \
  --test-case="lte/uu/acceptance: a separate production ue process attaches through srb1"
```

It asserts, from the peer result and the UE log: the Initial UE Message carries
the production Attach Request, Authentication Response verified, Security Mode
Complete verified, Initial Context Setup Response after AS security, RRC AS
security active, Attach Accept protected and delivered, Attach Complete verified,
and the UE logging `NAS security activated` and `EPS Attach complete`. Without the
environment variable the case reports NOT_EXERCISED and claims nothing.
