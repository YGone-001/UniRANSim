# The production UE Detach over SRB1 (B6-D4)

This is the record of how the production `lte-ue` process closes an EPS session
it attached itself, on the same Uu/SRB1 transport, and of what that proves.

## Scenario

`lifecycle.scenario` now supports `attach-detach` (an alias of `detach`) for a Uu
configuration. It runs the whole lifecycle in one process and one session:

```text
ATTACH -> Authentication -> NAS Security Mode -> Attach Accept -> Attach Complete
       -> EPS REGISTERED
       -> (triggerAfterMs) UE-initiated Detach Request
       -> protected Detach Accept
       -> EMM_DEREGISTERED, process exits 0
```

`attach-only` keeps its D3 behaviour: it stops at Attach Complete and stays
registered. Any other scenario with `uu` is refused at startup; nothing is
silently moved between transports.

## One send interface

The Detach Request goes through the same `sendNas` lambda as the Attach
exchange, so in Uu mode it leaves in `ULInformationTransfer` on SRB1:

```text
mobility.startDetach()
  -> nas::EncodeDetachRequest(ksi, GUTI, switchOff)
  -> nas::Protect(security, uplink, newContext=false, plain)
  -> sendNas() -> UuNasTransport::SendNas -> ULInformationTransfer
```

The protected bytes are kept in `pendingWire` so a bounded retransmission repeats
exactly the message that was sent. A transport refusal fails the run; it is never
retried over `enbLink`.

The legacy switch-off notification (`EPS_SESSION_DELETED`) is a control frame for
the legacy eNB and is not emitted when the session ran over Uu. The UE does not
invent an S1 release message on another transport: the S1 UE context release
that follows a Detach is the MME's decision.

## Security and COUNT continuity

The Detach reuses the context the Attach established; nothing is re-created.

| Message | Direction | COUNT |
|---|---|---|
| Security Mode Complete | UL | 0 |
| Attach Complete | UL | 1 |
| Attach Accept | DL | 1 |
| Detach Request | UL | 2 |
| Detach Accept | DL | 2 |

The peer verifies the Detach Request MAC with the active EIA2 key and refuses
anything whose recovered COUNT is not 2. The UE's `ReceiveProtectedDownlink`
rejects a replayed or already-used downlink COUNT, so a duplicate Detach Accept
cannot deregister the UE twice.

## Completion and resource lifecycle

`EMM_DEREGISTERED` is set only after a protected Detach Accept has been verified.
On that path the UE clears the NAS security context, the AS security context, the
bearer set, the TUN device and `pendingWire`, logs
`EPS Detach accepted; State=EMM_DEREGISTERED, bearer and TUN released`, and exits
0. The `UuNasTransport` is released by RAII when the process leaves `Run`, which
clears the NAS callback before the runtime and socket are destroyed.

A Detach that is not accepted leaves the UE registered and fails the run: an
unverified message can never make it deregister.

| Situation | Observable outcome |
|---|---|
| Detach Accept received and verified | EMM_DEREGISTERED, exit 0 |
| Duplicate Attach Accept / Detach Accept | dropped as a replayed COUNT, session continues |
| Corrupted Detach Accept MAC | `EPS NAS integrity verification failed`, dropped, run fails |
| Peer exits during Detach | explicit send refusal or bounded retransmission timeout, exit 1 |
| Unreachable Uu peer | bounded failure, nothing sent to the legacy eNB |
| Switch-off Detach | local deregistration without waiting for an Accept |

## Two-process acceptance

`tools/lte-uu-attach-peer.cpp` is process 2: the production `EnbRrcBridge` plus a
deterministic MME. It assigns a GUTI in the Attach Accept, then verifies the
Detach Request with the production decoder and MAC, answers with a protected
Detach Accept and releases the eNB association through `OnS1AssociationLost()`.

Modes:

| Mode | Behaviour |
|---|---|
| `attach-only` | stops after Attach Complete (D3 behaviour, default) |
| `attach-detach` | completes Attach and Detach in one session |
| `duplicate-attach-accept` | sends the protected Attach Accept twice |
| `exit-on-detach` | leaves without answering the Detach Request |
| `bad-detach-mac` | answers with a deliberately corrupted MAC |

`test/lte/production_uu_attach.cpp` starts both processes on dynamically chosen
ports. The cases are opt-in:

```bash
UNIRANSIM_RUN_TWO_PROCESS_ATTACH=1 ./cmake-build-release/nr-tests --no-skip \
  --test-case="lte/uu/lifecycle: the production ue attaches and detaches the same session over srb1"
```

The GitHub Actions job `Production UE Attach-Detach (two processes)` sets the
variable and runs every `lte/uu/lifecycle` case, plus the D3 attach and
unreachable-peer cases, in its own job so the ordinary matrix stays free of child
processes.

## What this does not prove

The MME is deterministic, not Open5GS; the RRC/S1 release after the Detach is not
exercised; no user plane crossed SRB1. `LTE_DEFAULT_BEARER_OVER_SRB1_READY` and
`LTE_OPEN5GS_ATTACH_ACCEPTED` stay false.

## Scope

Still on the legacy link and out of this phase: TAU, Recovery,
network-initiated Detach, the default bearer user plane, GTP-U, multi-UE scale
and throughput. Service Request and Paging moved to the Uu path in B6-D5; see
`docs/lte-production-ue-ecm-idle.md`. They remain the direction of the project,
not abandoned capabilities.
