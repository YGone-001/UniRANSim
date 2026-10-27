# LTE S1-MME Association Recovery — Ownership Audit and Design

This document records the mandatory source audit performed before the recovery
implementation was written, and the resulting ownership split. It answers the
twelve audit questions against the actual code as it stood at the accepted
baseline, then states the rules the implementation follows.

## 1. Baseline defect

`src/lte/enb/app.cpp` created the SCTP client, the `IS1apSender` handler and the
`EnbMultiplexer` inside one `try` block, and the multiplexer inside the
successful `S1 Setup Response` branch:

```cpp
sctp::SctpClient client(...);          // attempt scope
Handler handler(client);               // attempt scope, IS1apSender
...
EnbMultiplexer multiplexer(config, handler);   // S1-setup scope
while (!shutdownRequested && !handler.associationLost) { ... }
multiplexer.shutdown();
return shutdownRequested ? 0 : 1;      // <-- the running eNB exits
```

When the association was lost the running loop exited and `Run` returned `1`.
The eNB process did not recover: the radio endpoint, the shared S1-U socket and
the whole per-UE registry were destroyed with it. Recovery therefore required
restarting the process, which is explicitly not "automatic reconnection".

## 2. Audit answers

### Q1 — Which objects currently die with the SCTP association?

| Object | Scope at baseline | Fate |
|---|---|---|
| `sctp::SctpClient client` | per-attempt `try` block | destroyed |
| `Handler handler` (`sctp::ISctpHandler` + `IS1apSender`) | per-attempt `try` block | destroyed |
| `EnbMultiplexer multiplexer` | S1-Setup-success branch | destroyed |
| `udp::UdpServer m_ueLink` (simulated radio) | owned by the multiplexer | destroyed |
| `UeRegistry m_registry` and every `EnbUeEntry` | owned by the multiplexer | destroyed |
| `S1uEndpoint m_s1u` (shared GTP-U socket) | owned by the multiplexer | destroyed |
| `PagingCounters`, per-UE `UserPlaneCounters` | owned by the multiplexer | destroyed |
| `ConnectionStateMachine state` | `Run` scope | survives, but the process exits anyway |

### Q2 — Which should survive a transport reconnection?

Long-lived, per the required ownership split:

* the simulated-radio UDP endpoint;
* the shared S1-U GTP-U socket and its TEID demultiplexing indexes;
* the per-UE registry and each `EnbUeEntry` (radio identity, verified UDP peer);
* confirmed logical EPS bearer identities (EBI, linked EBI, QCI/ARP/GBR);
* per-UE NAS security, GUTI, TAI list and PDN IPv4;
* the UE-side TFT and TUN;
* counters and bounded recovery state.

Short-lived, recreated per association:

* the SCTP socket and its negotiated stream count;
* the `IS1apSender` handler;
* per-UE S1AP transport mappings (`enbUeS1apId`, `mmeUeS1apId`);
* local receiving TEIDs;
* association-scoped procedure state.

### Q3 — Which references become invalid when the SCTP handler is destroyed?

Exactly one: `EnbMultiplexer::m_sender`, declared as `IS1apSender &` and bound
to the stack-allocated `Handler`. At baseline this is safe only because the
multiplexer is destroyed before the handler. Hoisting the multiplexer across
reconnects without changing this member would leave a dangling reference on the
first reconnection. `IS1apSender` is therefore rebound through an explicit,
epoch-validated binding object instead of a plain reference.

The `streamFor(entry)` result is also association-scoped: it is derived from
`m_outboundStreams`, which is negotiated per association.

### Q4 — How are all outstanding UE S1AP IDs invalidated?

`UeRegistry::releaseS1(entry)` erases both indexes and zeroes both fields:

```cpp
if (entry.enbUeS1apId != 0) m_byEnbUeS1apId.erase(entry.enbUeS1apId);
if (entry.mmeUeS1apId != 0) m_byMmeUeS1apId.erase(entry.mmeUeS1apId);
entry.enbUeS1apId = 0;
entry.mmeUeS1apId = 0;
```

After that, `findByEnbUeS1apId` and `findByMmeUeS1apId` cannot resolve an
identifier from the dead association. `allocateEnbUeS1apId` is monotonic and
skips live identifiers, so a new context never receives an old one.

### Q5 — How are all old local receiving TEIDs removed?

Also `releaseS1`: it erases the default and every dedicated local TEID from
`m_byLocalTeid`, then calls `releaseAccessTransport()` on each bearer, which
zeroes `localTeid`, `sgwTeid` and `sgwAddress`. The process-wide
`AllocateLocalTeid()` is monotonic and random-seeded, so a fresh allocation can
never reproduce a live or recently released TEID.

### Q6 — How are all in-flight S1AP procedures abandoned?

At baseline, implicitly: `releaseS1` moves the entry to `IDLE_RETAINED`
regardless of `CONTEXT_PENDING`, so a half-completed Initial Context Setup
simply never completes. That is correct for state but silent for observability.
The recovery path makes it explicit: `EnbUeEntry` keeps its `accessGeneration`,
the multiplexer counts affected UEs and invalidated TEIDs, and a bearer that has
not received its generation-bound `BEARER_TRANSPORT_READY` confirmation stays
`restorationPending()` and therefore `active() == false`. Nothing becomes
forwardable.

### Q7 — How does each UE learn that access transport is unavailable?

Baseline: only through `S1_CONTEXT_RELEASED`, which is sent after a *completed*
3GPP `UEContextReleaseCommand`/`Complete` exchange. Unexpected SCTP loss is not
that procedure, so it must not reuse that message. The implementation adds a
new simulated-radio message `S1_ACCESS_LOST`, documented as an **internal
software-radio access-loss notification** — not a NAS message, not an RRC
message, and not evidence of any S1AP release procedure. It carries the same
`EBI(1) || access-generation(4)` binding so the existing generation validation
in `MobilityContext::acceptAccessRelease` applies unchanged (G19).

Notification is per-UE and per-UE failures are caught individually, so one
unreachable radio peer cannot block cleanup of the others.

### Q8 — How is a new SCTP association distinguished from the old one?

Baseline: only by object identity of the destroyed `Handler`. There is no
epoch. The implementation introduces a monotonically advancing **association
epoch** owned by `EnbMultiplexer`:

* it advances when an association is torn down, so every callback, sender and
  stream assignment of the dead association is stale by construction;
* it is additionally stamped on the sender binding, so a stale `IS1apSender`
  cannot transmit through a rebound one;
* it is kept separate from the per-UE `accessGeneration`, which continues to
  count *access* restoration attempts for one UE.

### Q9 — How are negotiated SCTP streams updated?

Baseline: `multiplexer.setOutboundStreams(handler.outboundStreams)` once, at
construction. The implementation calls the same setter from
`bindAssociation(sender, epoch, outboundStreams)` on every successful S1 Setup,
so the new negotiated count takes effect before any UE-associated signalling is
sent. `SctpStreamForUe` is re-evaluated against the new count.

### Q10 — How are responses from an obsolete association rejected?

Three independent layers:

1. the old `SctpClient` and `Handler` are destroyed, so no socket can transmit;
2. `S1apSenderBinding::send(epoch, ...)` refuses a send whose epoch is not the
   currently bound one and counts the rejection;
3. `EnbMultiplexer` refuses to dispatch when no association is bound
   (`unboundSenderRejects`).

Stale radio confirmations are rejected by the existing
`accessGeneration` checks in `handleRadioFrame`
(`restored.second != entry->accessGeneration`), which the new epoch does not
weaken.

### Q11 — Can UE logical EPS contexts and TFTs remain intact?

Yes. `releaseS1` deliberately retains the logical bearer contexts and only
drops access transport; the comment in `ue_registry.cpp` records why. The UE
side keeps `nas::EpsBearerConfiguration` (QoS + TFT) inside
`DedicatedBearerRuntime` and only flips `accessReady = false`. `releaseAccessTransport()`
never touches EBI, linked EBI, QoS or TFT.

### Q12 — What if the MME has already deleted the UE's EPS context?

Then the MME, not the simulator, decides. A compact Service Request whose
context the MME does not hold is answered with a reject carrying a real cause,
or with no answer at all. The simulator records the actual outcome, reports the
cause where the network supplied one, applies its bounded retry budget and
stops. It never fabricates an `InitialContextSetupRequest`, never synthesises a
`Service Accept`, and never counts a fresh Attach as continuity of the original
session.

## 3. Ownership split implemented

```
EnbRuntime (lifetime: process)
├── EnbMultiplexer
│   ├── udp::UdpServer m_ueLink          long-lived
│   ├── UeRegistry m_registry            long-lived (logical EPS state)
│   ├── S1uEndpoint m_s1u                long-lived (access TEID index)
│   ├── S1apSenderBinding m_sender       rebound per association epoch
│   ├── uint32_t m_associationEpoch      monotonically advancing
│   └── RecoveryCounters                 long-lived
├── ConnectionStateMachine               long-lived
└── FailureInjector                      opt-in, disabled unless configured

per SCTP association epoch
├── sctp::SctpClient
├── Handler (IS1apSender)                bound to one epoch only
└── negotiated outbound stream count
```

## 4. Failure model and state machine

```
DISCONNECTED ──CONNECT_STARTED──▶ SCTP_CONNECTING ──SCTP_CONNECTED──▶ SCTP_ASSOCIATED
     ▲                                    │                                │
     │                               (failure)                       SETUP_REQUEST_SENT
     │                                    │                                │
     │                                    ▼                                ▼
     └────────CONNECTION_LOST──── S1_SETUP_FAILED ◀──SETUP_REJECTED── S1_SETUP_PENDING
     │                                                                    │
     │                                                            SETUP_ACCEPTED
     │                                                                    ▼
     └──RECOVERY_STARTED── RECOVERING                          S1_SETUP_ESTABLISHED
                                       any ──SHUTDOWN_REQUESTED──▶ STOPPING
```

* `RECOVERING` is entered after a loss when a reconnection will be attempted; a
  further `CONNECT_STARTED` leaves it for the next attempt.
* `STOPPING` is terminal and interrupts backoff promptly.
* `CONNECTION_LOST` is accepted from every state and returns to
  `DISCONNECTED`, which keeps the existing transition test valid.

Retry policy:

* before the first successful S1 Setup, attempts are bounded by
  `sctp.maxAttempts` and the process exits with an error when exhausted — an
  initial connection failure is not silently retried forever;
* after a successful S1 Setup, reconnection attempts are bounded by
  `recovery.maxAttempts` (`0` = until shutdown) with exponential backoff from
  `recovery.delayMs` to `recovery.delayMaxMs`;
* `S1 Setup Failure` with `TimeToWait` raises the backoff floor to that value;
* `S1 Setup` timeout is a failed attempt and never enters `S1_SETUP_ESTABLISHED`.

Failure classes A–I from the design brief are covered as follows: A by the
bounded initial retry; B by the setup-deadline check; C by honouring
`TimeToWait`; D and E by `invalidateAccess` (which only touches UEs that
actually hold access transport); F and G by leaving every unconfirmed bearer
`restorationPending()` and therefore non-forwardable; H by never publishing a
partial NAS/TFT/QoS transition; I by the epoch, the monotonic TEID/S1AP-ID
allocators and the leak tests.

## 5. Recovery trigger

After an unexpected access loss the UE retains EPS registration, security, GUTI,
logical bearers, TFT, PDN IPv4 and TUN. It does **not** invent a deregistration
and does **not** silently re-Attach.

Access restoration is then driven by genuine signalling only:

* **UE-initiated**: a compact EPS Service Request protected by the existing NAS
  security context, sent after a configurable bounded delay with bounded
  retransmission. This is the TS 24.301 Service Request of TS 23.401 §5.3.4.
* **Network-initiated**: real downlink traffic produces a Data Notification, a
  genuine S1AP Paging, S-TMSI matching and the same compact Service Request.

Neither path fabricates an S1AP message, and a rejected Service Request is
recorded with its real cause.

## 6. Failure injection seam

Scoped exclusively to the test-owned eNB and **off unless explicitly configured**:

* the eNB configuration may name a `failureInjection.controlFile`;
* if the field is absent or empty, the injector is inert and no injection code
  path runs;
* writing `loss` to that file tears down the simulator's own SCTP association
  immediately;
* writing `loss-before-s1ap-response` arms a one-shot injection that drops the
  next S1AP PDU the eNB would have sent and tears the association down instead,
  which deterministically produces an in-flight interruption
  (e.g. during Initial Context Setup).

The file is consumed (truncated) after each command. No firewall rule, no
process kill, no EPC interaction and no always-on production failpoint is
involved.

## 7. Safety rules enforced by the implementation

* unexpected SCTP loss never emits `UEContextReleaseCommand` or `Complete`;
* `S1_ACCESS_LOST` is an internal simulator abstraction and is documented as
  such at every use site;
* no bearer becomes forwardable without a generation-bound confirmation;
* a dedicated bearer confirmation is rejected before default-bearer readiness;
* old local TEIDs stop resolving the moment the association dies;
* dedicated TFT traffic is never silently rerouted to the default bearer — an
  unready dedicated bearer is a counted drop;
* no EPC service is restarted and no subscriber material is touched.
