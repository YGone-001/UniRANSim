# S1-based connected-mode handover: protocol foundation

Design record for the first standards-aligned, independently testable S1-based
Connected-Mode Handover protocol foundation in UniRANSim LTE: which S1AP
messages exist, what each one may and may not carry, how a target eNB decides
whether to admit a handover before it commits anything, and what the tests
actually proved.

This record covers the LTE eNB path in `src/lte/`. It does not describe a
completed handover. Nothing here has been run against a live EPC, and no
user-plane traffic has been forwarded through a handover.

Three kinds of evidence appear below and are never mixed:

* **Deterministic** — the ordinary doctest suite, driven by offline fixtures
  and by frames whose bytes an independent dissector confirmed.
* **Dissector-confirmed wire form** — Wireshark tshark 4.2.2 reading the
  encoded frames back over SCTP (PPID 18). This is what pins the APER spelling.
* **Live EPC** — none. Phase 18-A performed no live experiment and none is
  claimed anywhere in this record.

A test fixture is not the network. Where this record says "the network states",
it means the fixture carries the network's statement of the EPS session.

## 1. Current capabilities

What the repository can do today, in production code, and prove with a test:

| Capability | Where | Proven by |
|---|---|---|
| Encode and decode Handover Required | `src/lte/enb/codec.cpp` | `lte/handover/wire: handover required matches the cross-checked aper vector` |
| Encode and decode Handover Command | `src/lte/enb/codec.cpp` | `lte/handover/wire: handover command matches the cross-checked aper vector` |
| Encode and decode Handover Preparation Failure | `src/lte/enb/codec.cpp` | `lte/handover/wire: handover preparation failure matches the cross-checked aper vector` |
| Encode and decode Handover Request | `src/lte/enb/codec.cpp` | `lte/handover/wire: handover request matches the cross-checked aper vector` |
| Encode and decode Handover Request Acknowledge | `src/lte/enb/codec.cpp` | `lte/handover/wire: handover request acknowledge matches the cross-checked aper vector` |
| Encode and decode Handover Failure | `src/lte/enb/codec.cpp` | `lte/handover/wire: handover failure matches the cross-checked aper vector` |
| Encode and decode Handover Notify | `src/lte/enb/codec.cpp` | `lte/handover/wire: handover notify matches the cross-checked aper vector` |
| Carry a data forwarding endpoint list in a Handover Command | `src/lte/enb/codec.cpp` | `lte/handover/wire: data forwarding endpoints keep their e-rab identity and byte order` |
| Refuse a malformed, truncated or unsupported handover message | `src/lte/enb/codec.cpp` | `lte/handover/reject:*` |
| Evaluate a Handover Request for admission without committing anything | `src/lte/enb/handover_admission.cpp` | `lte/handover/resource: a decoded request allocates nothing on the target` |
| Keep default and dedicated bearer identity independent of E-RAB order | `src/lte/enb/handover_admission.cpp` | `lte/handover/bearer:*` |
| Build a Handover Request Acknowledge only from transport a commit step bound | `src/lte/enb/handover_admission.cpp` | `lte/handover/resource: an acknowledge names only transport a commit step bound` |
| Turn a refused admission into a Handover Failure with a standard cause | `src/lte/enb/handover_admission.cpp` | `lte/handover/resource: a refused admission reports a failure and acknowledges nothing` |
| Commit an admitted plan into real, owned target transport, atomically across the bearer set | `src/lte/enb/handover_preparation.cpp` | `lte/handover/preparation: a commit binds real allocator teids and owns a provisional context` |
| Hold a prepared bearer established and not forwardable | `src/lte/enb/handover_preparation.cpp` | `lte/handover/preparation: a g-pdu for a prepared teid is dropped as inactive, not as unknown or retired` |
| Roll a failed commit back without leaving a live mapping | `src/lte/enb/handover_preparation.cpp` | `lte/handover/preparation: a failure on the second bearer leaves nothing of the first` |
| Recognise a duplicate, a conflicting duplicate and a stale association epoch | `src/lte/enb/handover_preparation.cpp` | `lte/handover/preparation: a repeated request is one transaction and allocates nothing twice` |

What the repository cannot do today: move a UE between two eNBs. There is no
handover procedure state machine, no recognition of a UE arriving at a target,
no source-side release after Handover Notify, no data forwarding path and no
user-plane switchover. A target that has committed resources owns real
transport for a UE that has not arrived and nothing more. §2, §27 and §14 say
exactly where the boundary is.

## 2. Missing implementation areas

The following are deliberately absent. Each is a real gap, not an implicit
behaviour.

* **No procedure driver.** The codecs, the admission evaluator and the
  preparation owner are pure functions, a pure evaluation and a deterministic
  transaction record. Nothing orders a Handover Required, waits for a Handover
  Command, or starts a Handover Request on a target. There is no state machine
  that could drive a handover to completion.
* **No target-side establishment for a UE that arrived.** What exists is the
  preparation slice: a provisional context, real local S1-U transport, and
  bearers that are established and not UE-ready. What does not exist is the
  promotion of such a context into a reached UE session. Nothing calls
  `activateUe` on a prepared bearer and nothing recognises an arrival.
* **No source-side release.** Handover Notify is decoded and nothing follows.
  No bearer is released, no TEID is retired, no access generation advances.
* **No data forwarding.** A Handover Command may *carry* forwarding endpoints
  and a Handover Request Acknowledge may *carry* them, and both are preserved
  byte for byte. Nothing opens a forwarding tunnel and no G-PDU is ever
  forwarded during a handover.
* **No X2.** There is no X2 interface, no Handover Request over X2 and no Path
  Switch Request. §4 explains why the last one is not a substitute.
* **No inter-RAT, no inter-MME, no S10.** `HandoverType` values other than
  `intralte` are refused at decode and at encode. A `targetRNC-ID` or a `cGI`
  TargetID is refused as an invalid context identity rather than decoded.
* **No RRC reconfiguration.** The transparent containers are opaque. §9.
* **No security derivation.** The `SecurityContext` is carried, never
  generated, never defaulted and never logged. §10.
* **No live EPC handover.** Nothing in this phase contacted Open5GS.

## 3. Normative protocol references

| Reference | What it fixes |
|---|---|
| TS 36.413 V16.4.0 (Release 16) | S1AP: procedure codes, message ASN.1, IE identifiers, criticality. The authoritative ASN.1 used to check this implementation is `36413-g40.asn` in the Open5GS ASN.1 support tree. |
| TS 36.413 §9.1.3.1 | Handover Preparation (procedure code 0), Handover Resource Allocation (procedure code 1), Handover Notification (procedure code 2). |
| TS 36.413 §9.1.4.1 | The PDU categories: `initiatingMessage`, `successfulOutcome`, `unsuccessfulOutcome`. |
| TS 36.413 §9.2.1.15 | E-RAB Level QoS Parameters: ARP lives here, not in the NAS EPS QoS. |
| TS 36.413 §9.2.1.18 | GBR QoS Information: GBR and MBR, present for a GBR bearer only. |
| TS 24.301 §9.9.4.3 | NAS EPS quality of service: QCI and, for the extended form, bitrates. It carries **no ARP**. |
| TS 29.281 V14.0.0 | GTP-U. Untouched by this phase; the End Marker and retired-TEID rules in `docs/gtpu-end-marker-retired-tunnel-lifecycle.md` still hold. |
| X.691 / APER | The aligned packed encoding rules the S1AP wire form is expressed in. |

No procedure code and no IE identifier was invented. Every identifier in
`src/lte/enb/codec.cpp` that this phase added is one the above assigns.

## 4. S1-based versus X2-based distinction

S1-based and X2-based handover are two different procedures that end in the
same place and start nowhere alike.

* **S1-based handover** is prepared through the MME. The source eNB sends
  Handover Required (procedure 0, `initiatingMessage`) to the MME, the MME
  sends Handover Request (procedure 1, `initiatingMessage`) to the target eNB,
  the target answers Handover Request Acknowledge (procedure 1,
  `successfulOutcome`) or Handover Failure (procedure 1, `unsuccessfulOutcome`),
  the MME returns a Handover Command (procedure 0, `successfulOutcome`) or a
  Handover Preparation Failure (procedure 0, `unsuccessfulOutcome`) to the
  source, and the target reports Handover Notify (procedure 2,
  `initiatingMessage`) once the UE has arrived. The MME owns the bearer path
  update that follows.
* **X2-based handover** is negotiated directly between the two eNBs. The
  target reports the completed handover to the MME with a **Path Switch
  Request** (procedure code 3).

This phase implements the S1 family and only the S1 family. The work order
forbids a Path Switch Request standing in for Handover Notify and the
MME-controlled bearer path update, and this repository does not contain one.
The two are not interchangeable: a Path Switch Request makes the target ask the
MME to redirect the bearer after the fact, whereas Handover Notify tells the MME
that the S1-based procedure it is already managing has reached its target. A
simulator that only emits a Path Switch Request has not implemented S1-based
connected-mode handover, whatever its message names suggest.

## 5. Message flow

The S1-based connected-mode handover this phase models, with the messages that
exist today in bold and the steps that do not exist yet in italics.

```
source eNB                  MME                     target eNB
    |                        |                          |
    |-- Handover Required -->|                          |   (procedure 0)
    |                        |-- Handover Request ----->|   (procedure 1)
    |                        |                          |
    |                        |   EvaluateHandoverAdmission  (pure; binds nothing)
    |                        |                          |
    |                        |<-- Handover Request Ack --|   (procedure 1)
    |                        |       or Handover Failure    (procedure 1)
    |<-- Handover Command ---|                          |   (procedure 0)
    |       or Handover Preparation Failure                (procedure 0)
    |                        |                          |
    |  *source sends the UE the handover command*           not implemented
    |  *UE accesses the target cell*                        not implemented
    |                        |                          |
    |                        |<-- Handover Notify -------|   (procedure 2)
    |                        |                          |
    |  *MME updates the bearer path*                       not implemented
    |  *MME tells the source to release*                   not implemented
    |  *source releases the UE context*                    not implemented
```

Every bold line is a codec in `src/lte/enb/codec.cpp` with a byte-exact test.
Every italic line is absent from the repository. There is no code that
*transmits* any of these messages; the codecs produce and consume a frame, and
the S1AP transport that would carry it is not part of this phase.

## 6. Message ownership

Which side owns each message, and what that message is allowed to decide.

| Message | Direction | Owned by | May decide | May not decide |
|---|---|---|---|---|
| Handover Required | source → MME | source | That a handover is desirable; which cell is the named target | Whether the target has resources |
| Handover Request | MME → target | MME | Which bearers and what QoS the target is asked to set up | Which target is the recipient — the recipient *is* the target |
| Handover Request Acknowledge | target → MME | target | Which E-RABs it admitted and the transport it bound for each | The bearer roles; the QoS; anything about the source |
| Handover Failure | target → MME | target | That it admits nothing, with a cause | A partial admission; a cause that invents a resource |
| Handover Command | MME → source | MME | What the source must send the UE; what forwarding is offered | Whether the UE has reached the target |
| Handover Preparation Failure | MME → source | MME | That preparation failed, with a cause | Any bearer transition |
| Handover Notify | target → MME | target | That the UE has arrived at the named CGI and TAI | That the source may release; that the bearer path is updated |

The one asymmetry worth stating plainly: **Handover Request carries no
TargetID.** The target is the recipient of the message. The only message in
this family that names a target is Handover Required, and the only check that a
named target matches the eNB evaluating it is `CheckNamedTarget`, which applies
to that message. An admission evaluator that compared a Handover Request
against a "target identity" would be inventing a field the standard does not
give it.

## 7. Source/target identity model

An eNB identity in this code is `EnbIdentity{Plmn, uint32_t enbId, uint16_t
tac}` and is always taken from signalling, never defaulted.

* **Global-ENB-ID** carries the PLMN identity and the eNB-ID. Only the
  `macroENB-ID` choice is supported; a `homeENB-ID` or an extended choice is
  refused as an invalid context identity rather than guessed at.
* **selected-TAI** carries the PLMN identity again and the TAC. It is a
  separate field on the wire and can disagree with the Global-ENB-ID's PLMN.
  When the two PLMNs differ, the target is not a coherent target and
  `ReadEnbIdentity` refuses it as `INVALID_CONTEXT_IDENTITY`. The test
  `lte/handover/reject: a source or target that names two networks is refused`
  builds exactly that frame.
* **SourceContext** is what the target knows about the eNB that sent the UE.
  It has an `identityKnown` flag, because a target that cannot attribute a
  Handover Request to a source must refuse it rather than admit an unknown one.
  `AdmissionRefusal::SOURCE_CONTEXT_UNKNOWN` is that refusal.
* **TargetContext** is what the target knows about itself: its own identity,
  its own S1-U address, and the encryption and integrity algorithm sets it
  supports. It is not read out of the message.

Two identities are never compared for anything except coherence and equality.
There is no ordering, no "nearest cell" and no TAC-based ranking anywhere in
this code.

## 8. Bearer admission model

`EvaluateHandoverAdmission(request, source, target, roles)` is a pure function
of its four arguments. It reads no global state, allocates nothing and has no
side effect. This is the whole point: **a decoded but not admitted Handover
Request must not allocate an active S1-U tunnel, forward a G-PDU, retire a
source TEID, release an existing bearer, or create a live UE session.**

The fourth argument, `roles`, is the network's own statement of the EPS
session: one `BearerRoleBinding` per E-RAB, naming the E-RAB, its role
(`DEFAULT` or `DEDICATED`), its linked default E-RAB for a dedicated bearer,
its QCI and its ARP. **The role is never inferred from the QCI and never from
the order the E-RABs are listed in.** A binding that calls the higher-ECI E-RAB
the default is honoured; a reordered E-RAB list produces the same result with
the default bearer still first.

Evaluation order, in full:

1. `HandoverType` must be `intralte`.
2. The target identity must be coherent: a non-zero eNB-ID, a non-empty PLMN
   MCC, a non-zero TAC.
3. The source identity must be known and non-zero, and must differ from the
   target's.
4. The encryption and integrity algorithm sets must intersect.
5. The E-RAB list must be non-empty, with no zero and no duplicate E-RAB IDs.
6. Every E-RAB must have a `BearerRoleBinding`. One that the network never
   classified is `BEARER_ROLE_UNCONFIRMED`, not assumed.
7. Every E-RAB's QoS must match the negotiated one. A mismatch is
   `BEARER_QOS_MISMATCH` with cause `invalid-qos-combination`.
8. A dedicated bearer must name a linked default; a dedicated bearer whose
   linked default is not itself admitted is `LINKED_DEFAULT_MISSING`.
9. The set must contain at least one default bearer.

The result is ordered **defaults first, then dedicated**, whatever order the
E-RABs arrived in — which is what makes a dedicated bearer's readiness
dependent on the default it is linked to.

The result binds nothing. Each `AdmittedBearer` carries a `targetTransport`
whose address is the target's own S1-U address and whose TEID is zero and whose
`bound` flag is false. `HandoverAdmission::holdsTransportResources()` is the
testable predicate that it stays that way, and it is false for every admission
this code can produce.

### Bearer and TEID invariants a connected handover must keep

What must survive, unchanged, across any future handover:

* The default bearer's EBI and the dedicated bearer's EBI.
* The dedicated bearer's linked-default EBI.
* Each bearer's QoS — QCI and ARP — as the network stated it.
* Each dedicated bearer's **non-empty TFT**.
* Access-generation tracking.
* The retired local TEID ledger.
* Validated GTP-U forwarding.

What a future connected handover must never do:

* Reuse a retired source TEID.
* Assign bearer roles by QCI, or by E-RAB ordering.
* Activate an uncommitted target bearer.
* Release the source's context during preparation.
* Route traffic through a partially initialized target.
* Lose the NAS security context.
* Replace a handover with an Attach.
* Replace a handover with an idle-mode Service Request.
* Mutate an unrelated UE's session.

Categories C, D and E of the test suite are the checks on the first two rows;
`lte/handover/resource: a decoded request allocates nothing on the target`
checks the "never" list against a real `UeRegistry`.

## 9. Transparent-container boundary

`Source-ToTarget-TransparentContainer` (IE 104) and
`Target-ToSource-TransparentContainer` (IE 123) are plain unbounded
`OCTET STRING` in TS 36.413: "coded according to the specifications of the
target system". This code treats them as exactly that.

* They are carried **byte for byte**. Nothing parses, trims, re-encodes or
  validates their contents.
* Nothing inside one may be read as a security field or an RRC field. An opaque
  container is not authority to invent either.
* The receiver bound is `MaxTransparentContainerSize` (4096 octets). An empty
  container is refused (`INVALID_TRANSPARENT_CONTAINER`), and one octet past the
  bound is refused **whole** — it is never truncated to the bound and accepted.
* The encoder refuses the same two shapes rather than writing them.
* The secondary containers (IE 138, IE 139) are refused in an intra-LTE
  handover: a secondary container is an inter-RAT element, and this code does
  not implement inter-RAT.

A consequence worth stating because it shows up in the cross-check: tshark
attempts to parse the RRC payload inside a transparent container and reports
`Malformed` for the deliberately non-RRC test bytes used in the fixtures. That
is a statement about the fixture's payload, not about the S1AP framing. The
S1AP envelope and every IE around the container were confirmed correct, and the
full dissection is retained as acceptance evidence.

## 10. Security-context boundary

`UESecurityCapabilities` (IE 107) and `SecurityContext` (IE 40) are carried,
never created.

* The `SecurityContext` holds `nextHopChainingCount` and the 256-bit
  `nextHopParameter`. Both come from the MME's signalling.
* No code in this repository generates, defaults, derives or logs either. The
  values in the tests are fixed test constants and are not UE security keys.
* A Handover Request with no `UESecurityCapabilities` is refused
  (`MISSING_MANDATORY_IE`): a target with no algorithm set has nothing to
  protect the UE with and must not guess.
* The admission evaluator refuses a target whose algorithm sets do not
  intersect the request's (`SECURITY_ALGORITHMS_NOT_SUPPORTED`) rather than
  picking one.
* A security-context failure is a refusal of the message. It never reaches a
  bearer, a TEID or a registry.

## 11. TEID ownership and lifecycle

Phase 18-A adds **no** new TEID lifecycle. All of the existing rules in
`docs/gtpu-end-marker-retired-tunnel-lifecycle.md` and in `AGENTS.md` continue
to hold unchanged:

* A local S1-U TEID is active, retired, or unknown, and every release of a live
  tunnel goes through `UeRegistry::retireLocalTeid`.
* Uniqueness comes from the allocator alone, never from the retirement record.
* An End Marker is recorded and nothing else moves.

What the admission evaluation adds is only a *plan* for transport:

* `AdmittedBearer::targetTransport.address` is the target's own S1-U address.
* `AdmittedBearer::targetTransport.teid` is zero and `bound` is false until a
  commit step says otherwise. Phase 18-A left that step unimplemented; the
  preparation slice of Phase 18-B implements it, in
  `src/lte/enb/handover_preparation.{hpp,cpp}`, and it is the only thing that
  turns a plan into a binding.
* `BuildHandoverRequestAcknowledge` takes that commit output as an explicit
  `std::vector<CommittedTransport>` and refuses to invent an address or a TEID.
  It refuses when the committed set does not cover the admitted bearers, when a
  committed TEID is zero, and when a committed endpoint is not on the target's
  own S1-U address.

A TEID that the commit actually binds is bound through
`UeRegistry::allocateLocalTeid` and `bindLocalTeid`, on a provisional target
context, and it stops resolving only through `unbindLocalTeid` — retirement for
a bound identifier, reservation-drop for one that never became a tunnel. The
allocation, ownership and rollback rules are in sections 17, 19 and 21 below.

Local S1-U TEIDs remain a fresh pair on every access restoration, and remain so
for any future connected handover: the previous pair must stop resolving, a
delayed G-PDU for an old TEID must not reach the new tunnel, and an old End
Marker must not release or modify the new bearer. Bearer packet counters
accumulate across access restorations by design, so a fresh TEID must not be
credited with traffic it never carried.

## 12. Failure and rollback semantics

### Connected-mode lifecycle

The lifecycle a completed S1-based handover would drive, and the event that
authoritatively enters each state. **It is documented, not implemented.** No
code asserts any of these transitions, and the repository contains no state
machine that could make them.

```
SOURCE_CONNECTED
      |  Handover Required sent by the source, with a named target
      v
HANDOVER_PREPARATION
      |  Handover Request Accept received: the target admitted every E-RAB
      v
TARGET_RESOURCES_PREPARED
      |  Handover Command received by the source, carrying the target container
      v
HANDOVER_COMMAND_RECEIVED
      |  the source has sent the UE its handover command
      v
UE_TARGET_ACCESS_PENDING
      |  Handover Notify sent by the target, naming the reached CGI and TAI
      v
TARGET_ACCESS_CONFIRMED
      |  the MME has updated the bearer path to the target's transport
      v
CORE_BEARER_PATH_UPDATED
      |  UE Context Release Command received by the source
      v
SOURCE_CONTEXT_RELEASED
      |  the source context is gone and the target holds the UE alone
      v
TARGET_CONNECTED
```

Each arrow's event is the *only* authority for that transition. The two that
matter most for this phase:

* `TARGET_RESOURCES_PREPARED` is entered on a Handover Request Acknowledge and
  means the target has planned and committed resources. It does **not** mean
  the UE has arrived.
* `TARGET_CONNECTED` is entered only after a Handover Notify, never after a
  Handover Request Acknowledge, and only after the MME has performed the bearer
  path update. A decoded-but-unadmitted Handover Request leaves every UE in its
  existing state; nothing in Phase 18-A can enter any of these states.

Phase 18-A implements the *messages* on three of these arrows — Handover
Required, Handover Request, Handover Request Acknowledge, Handover Command,
Handover Notify — and none of the transitions.

### Failure and rollback behaviours

Each of the ten below is a named behaviour a future implementation must have.
Phase 18-A implemented none of them. The preparation slice of Phase 18-B
implements the *target-side resource* part of four of them, as marked below;
the rest, and every part of a behaviour that needs a message to be sent or a UE
to arrive, is still unimplemented and nothing here claims it operational.

| # | Behaviour | Required outcome |
|---|---|---|
| 1 | Target admission rejection | Handover Failure with a standard cause. No bearer, no TEID, no session created on the target. |
| 2 | Missing Handover Request Acknowledge | The source keeps the UE context; no Handover Command is issued; the source times out and reports the failure to the MME. |
| 3 | Handover Preparation Failure | The source keeps the UE context and stays in `SOURCE_CONNECTED`. Nothing about the bearer changes. |
| 4 | Handover Command rejection | The source does not reconfigure the UE; the source reports the failure; the bearer path is untouched. |
| 5 | Target access failure | The target does not send Handover Notify; the target releases any transport it committed; the source context survives. |
| 6 | Duplicate Handover Notify | Idempotent. The second notify changes nothing and is not a second handover. |
| 7 | Stale source association | A message from a source the target no longer associates with the UE is refused and disturbs no live context. |
| 8 | Stale target association | A message for a target the source no longer expects is refused and disturbs no live context. |
| 9 | Source release before successful target completion | The UE context is not destroyed; the handover is reported failed; the retired-TEID ledger records only what was genuinely released. |
| 10 | Partial admission of multiple E-RABs | Not permitted. Admission is all-or-nothing across the bearer set; a target that cannot admit every E-RAB admits none and reports Handover Failure. |

What the two phases implement of that table, and what they do not:

* **1 — target admission rejection.** The target side is implemented. A refused
  admission or a refused commit creates no bearer, no TEID and no session, and
  `RefusalAsHandoverFailure` / `CommitRefusalAsHandoverFailure` produce a
  Handover Failure that names a standard cause and no eNB-UE-S1AP-ID.
  Transmitting it is still the caller's job.
* **5 — target access failure.** Only the release half is implemented:
  `HandoverPreparationOwner::cancel` and `expireDue` release everything the
  preparation committed, through `unbindLocalTeid`, and the source context is
  untouched. There is no Handover Notify to withhold, because no arrival is
  ever recognised.
* **7 — stale source association.** Implemented at the preparation boundary: a
  request or a commit under an association epoch the owner no longer holds is
  refused as `STALE_ASSOCIATION` before it can touch a resource.
* **10 — partial admission of multiple E-RABs.** Implemented twice over:
  `EvaluateHandoverAdmission` is all-or-nothing, and the commit validates the
  complete admitted set before allocating anything and rolls back the whole
  attempt if any one bearer fails.
* **2, 3, 4, 6, 8, 9.** Not implemented. All of them need either a message to
  be sent, a message to be received, or a UE to arrive, and none of those
  happens in this repository.

### Refusal representation

A refusal is a typed value, not a log line. `HandoverRefused` is a
`CodecError` carrying a `HandoverRefusal`:

| `HandoverRefusal` | Meaning |
|---|---|
| `MISSING_MANDATORY_IE` | A mandatory IE is absent, or present with the wrong criticality |
| `UNSUPPORTED_HANDOVER_TYPE` | Not `intralte`, or an extended value |
| `INVALID_CONTEXT_IDENTITY` | A zero or out-of-range UE identifier, or an incoherent eNB identity |
| `UNSUPPORTED_ERAB_LIST` | An empty, duplicated, wrongly-identified, half-specified or non-GBR-with-GBR E-RAB list |
| `INVALID_TRANSPARENT_CONTAINER` | An empty or oversized transparent container, or a secondary one |

`EvaluateHandoverAdmission` uses a parallel `AdmissionRefusal` record, which
also carries a standard `Cause` category and value, so that
`RefusalAsHandoverFailure` can produce a Handover Failure without inventing a
cause.

## 13. Deterministic test evidence

`test/lte/handover_s1.cpp`, 40 cases and 376 assertions. Categories A–F of the
work order map to the test-title prefixes `lte/handover/wire:`,
`lte/handover/reject:`, `lte/handover/bearer:`, `lte/handover/isolation:` and
`lte/handover/resource:`.

| Category | Cases | What it proves |
|---|---|---|
| A. Handover message wire compatibility | 10 | Eight byte-exact frames, asserted both directions, plus the envelope's procedure code and criticality read from raw bytes, plus the test-local writer pinned against the dissector-confirmed inner values |
| B. Invalid message rejection | 15 | Truncation, wrong procedure code, wrong PDU category, missing/duplicate mandatory IE, invalid UE identifier, invalid E-RAB list, unsupported handover type, empty/oversized container, unknown critical IE, wrong IE criticality, missing security capability, incoherent eNB identity, a Handover Failure carrying an eNB-UE-S1AP-ID, and the fixed diagnostic names of every handover refusal and role |
| C. Bearer identity preservation | 8 | One default and one dedicated bearer keep role and QCI; the same result under a reversed E-RAB list; a QCI never decides a role; an unclassified, mismatched, unlinked or wrongly-linked bearer is refused |
| D. Context isolation | 3 | Two eNB identities and two UE contexts; a malformed message for one UE changes neither; a target that does not match the named one is refused |
| E. Resource safety | 4 | A decoded and admitted request holds no transport; an acknowledge names only committed transport; a refusal acknowledges nothing and reports a standard cause; a freshly allocated local TEID set is distinct from the source's and retires nothing |
| F. Existing regressions | the whole suite | 668 ordinary cases pass, 130949 assertions, 0 failures |

### Independent APER vectors

The eight fixtures are byte-pinned and were cross-checked with **Wireshark
tshark 4.2.2**, which registers 902 `s1ap.*` fields. S1AP is not bindable on
`udp.port`; each frame was wrapped in Ethernet/IPv4/SCTP with PPID 18 and
dissected with `tshark -d sctp.port==9999,s1ap -V`. The full dissection is
retained as acceptance evidence.

This cross-check is what found three genuine APER bugs that an encode-then-decode
round trip could not have caught, because each was symmetric in the encoder and
the decoder:

1. `Direct-Forwarding-Path-Availability` was encoded as a two-bit enum. The
   ASN.1 has one root value, so the root index is **zero bits** and the IE's
   *presence* is the statement.
2. The presence bitmap of `E-RABAdmittedItem` and `E-RABDataForwardingItem` was
   written after the mandatory `e-RAB-ID`. APER puts the presence bitmap
   **before** the mandatory fields.
3. `E-RABDataForwardingItem` omitted `e-RAB-ID` entirely; tshark read an
   E-RAB-ID out of the forwarding presence bits.

The negatives are built with a deliberately separate bit writer at the bottom
of the test file. It shares no code with `src/lte/enb/codec.cpp`, and its
output is pinned against the dissector-confirmed inner values by
`lte/handover/wire: the test-local writer agrees with the dissector on inner
values`. A rejection this suite proves therefore cannot be an artefact of the
encoder and the decoder agreeing on the same mistake.

## 14. Implemented versus deferred

| Area | Status |
|---|---|
| S1AP Handover message codecs (7 messages) | **Implemented and byte-exact** |
| Fail-closed refusal for malformed frames | **Implemented** |
| Target admission evaluation (pure) | **Implemented** |
| Bearer role binding from the network's statement | **Implemented** |
| All-or-nothing admission across a bearer set | **Implemented** |
| Handover Request Acknowledge from committed transport | **Implemented** |
| Handover Failure from a refused admission | **Implemented** |
| Target-side resource commit, atomic across the bearer set | **Implemented** |
| Provisional target context ownership | **Implemented** |
| Prepared-but-not-forwardable bearer state | **Implemented** |
| Preparation transaction lifecycle: duplicate, stale, expiry, cancel | **Implemented** |
| Deterministic rollback of a failed commit | **Implemented** |
| Handover procedure state machine | **Deferred** |
| Target-side bearer establishment for a UE that arrived | **Deferred** |
| Source-side release after Handover Notify | **Deferred** |
| MME-controlled bearer path update | **Deferred** |
| Data forwarding path and user-plane switchover | **Deferred** |
| X2 handover and Path Switch Request | **Out of scope** |
| Inter-RAT, inter-MME, S10 | **Out of scope** |
| Real LTE PHY/RRC reconfiguration | **Out of scope** |
| Live Open5GS S1 handover | **Out of scope** |

`docs/lte-performance-scalability-roadmap.md` is unchanged. Its milestones stay
`DEFERRED — NOT IMPLEMENTED — NOT BENCHMARKED`.

## 15. Next-stage integration plan

The plan this section recorded has its first step done: Phase 18-B implemented
the commit step, in `src/lte/enb/handover_preparation.{hpp,cpp}`, and sections
16 to 28 below are what it does. The remaining steps are unchanged and are
still the work of a later phase.

1. **Commit step.** *(Done.)* A `CommitHandoverResources` that takes a
   `HandoverAdmission` and produces the `std::vector<CommittedTransport>`
   `BuildHandoverRequestAcknowledge` already consumes — allocating local S1-U
   TEIDs from `UeRegistry::allocateLocalTeid`, binding them, and refusing
   partial commitment. Admission and commitment stay separate.
2. **Target session creation.** Create the target-side UE entry only once the
   commit succeeded, and only for the UEs that arrived, not for the UEs that
   were merely planned. Phase 18-B creates the *provisional* half of that: the
   resources a plan owns before an arrival, kept apart from reached UEs. The
   promotion of a provisional context into a reached one is not implemented.
3. **Handover Notify handling.** On Handover Notify, verify the named CGI and
   TAI against the target's own identity before anything else moves.
4. **Source release.** Release the source context and retire its local S1-U
   TEIDs through `UeRegistry::retireLocalTeid` only after a Handover Notify for
   that UE, so an old TEID stops resolving exactly when it stops being valid.
5. **Bearer path update.** The MME-controlled update is the point of the S1
   family; it is not to be replaced by a Path Switch Request.
6. **Data forwarding.** Only after the above, and only with a defined
   forwarding model. No GTP-U End Marker behaviour is to be introduced before
   that model exists.

A test and a report may still not describe a handover as having happened. A
codec that can represent Handover Notify is not a handover, an admission that
binds nothing is not a target, and a target that owns prepared transport for a
UE that has not arrived is not a connected UE.

## 16. Target preparation architecture

The preparation slice is two production pieces and no third:

* `src/lte/enb/handover_preparation.{hpp,cpp}` — commitment and the
  transaction lifecycle, namespace `lte::enb::s1ap`;
* the provisional target contexts of `UeRegistry` — `allocateProvisional`,
  `isProvisional`, `removeProvisional` — the only new registry surface.

It owns no registry, no allocator and no bearer class of its own. It drives the
existing `UeRegistry` allocator and the existing `DefaultBearerContext` /
`BearerContext` classes, so every TEID rule of
`docs/gtpu-end-marker-retired-tunnel-lifecycle.md` applies to a prepared tunnel
exactly as it does to a reached UE's.

A provisional context is what a target owns while the UE is still at the
source. `registerPeer` demands a simulated radio identity and a verified UDP
peer precisely so that no caller can manufacture an arrival, and a prepared
handover has neither. `allocateProvisional` therefore creates an entry with
`radioUeId == 0`, a value `registerPeer` refuses and no reached UE can hold:

* it is absent from the radio-identity and the peer indexes, so `find` and
  `findByPeer` never return it;
* its S1AP identifiers and its local TEIDs are indexed exactly like a reached
  UE's, which is what lets the shared S1-U endpoint recognise its transport and
  refuse to forward to a bearer that has not been made UE-ready;
* it is counted against the same `maxUes` bound, so a full registry refuses it
  and allocates nothing;
* it is held apart from the reached UEs, keyed by a local ordinal that is not
  an S1AP identifier, not a TEID and not a UE identity.

`UeRegistry::size()` counts reached UEs only. A provisional context is real
against capacity and invisible against the UE count, and `isProvisional` is
what tells the two kinds apart.

## 17. The actual resource-commit algorithm

`CommitHandoverResources(admission, target, registry, transaction, faults)` is
all-or-nothing in five steps.

1. **Validate the whole set, allocate nothing.** Every bearer must be
   classifiable — an E-RAB identity one may hold, a non-zero QCI, a non-zero
   SGW TEID — the target identity must name the receiving eNB, the target must
   have an S1-U address, each admitted transport endpoint must be that address,
   no two bearers may share an E-RAB, a default bearer may not name a linked
   default, and each dedicated bearer must name a default of this same set and
   not itself. There must be exactly one default bearer: none is
   `LINKED_DEFAULT_MISSING`, more than one is `MULTIPLE_DEFAULT_BEARERS`, and
   the set is refused whole rather than having one silently dropped. A decoded
   but unadmitted admission, an empty bearer set, an absent transaction
   identity, and an admission that already holds transport are refused here.
2. **Capacity.** Registry capacity is checked before a context is made, and the
   `CAPACITY_EXHAUSTED`, `CONFLICTING_TRANSACTION` and `STALE_ASSOCIATION`
   fault points fire here, before any identifier is reserved.
3. **Readiness plan.** Default bearers first, then dedicated bearers, each
   group in the order the admission planned them. The order is a readiness
   order and never the wire order, and a deliberately reordered E-RAB list
   still produces it.
4. **Prepare, in that order.** `allocateProvisional()` for the context; then
   per bearer `allocateLocalTeid()` → the preparation fault point →
   `BearerParameters` carrying the network's own EBI, QoS, SGW address and SGW
   TEID → `establish` for a default or `addDedicatedBearer` for a dedicated one
   → `bindLocalTeid`. Nothing calls `activateUe`, so nothing becomes
   forwardable.
5. **Publish.** An eNB-UE-S1AP-ID is allocated and bound, the MME identity is
   recorded, and only then is the commit marked successful and the prepared set
   filled in. A result is either the complete set or nothing;
   `TargetResourceCommit` never carries a partial success.

The readiness order exists because `addDedicatedBearer` requires the linked
default to be established first. A set that lists a dedicated bearer before its
default is still prepared correctly, and the roles come from the network's own
statement — never from QCI and never from the order the E-RABs were listed in.

## 18. Transaction identity

`HandoverTransactionId` is `{mmeUeS1apId, associationEpoch, sequence}`. What
names the transaction is the pair `(mmeUeS1apId, associationEpoch)`; the
sequence is the owner's own tag and has no protocol meaning. `find` resolves on
the pair and ignores the sequence, so a caller that presents the right identity
with a stale or absent sequence is still talking about the same transaction and
cannot start a second one. `operator==` compares the whole triple so a recorded
transaction can be checked exactly.

Deliberately none of: EBI, TEID, a timestamp, the UE's address, a TAC. Each is
either shared with another UE, reused over time, or not the target's to decide.

Duplicate handling is part of the identity, not an extra rule beside it:

* a repeat of a request already known with the same plan returns the existing
  record and allocates nothing, whatever state that record has reached;
* a repeat that disagrees with a live preparation is a conflicting duplicate,
  refused as `CONFLICTING_TRANSACTION` and starting nothing;
* a different request after an earlier preparation reached a terminal state is
  a genuinely new preparation, and is recorded as one.

`find` scans newest-first, so where an identity has more than one record — an
earlier one that finished and a later one — the current transaction is the one
returned.

## 19. Temporary resource ownership

A record owns exactly two things: the provisional entry
(`PreparationRecord::entry`) and the identifiers bound or reserved on its
behalf (`ownedTeids`). Everything else in the record is a description of them.

`releaseOwned` is the only release path. It walks `ownedTeids` through
`unbindLocalTeid` — a live mapping is retired, a reservation is dropped — then
calls `removeProvisional`, which erases the entry and every index it owns. It
is idempotent and never reaches an identifier the record does not own.

A commit that cannot clean up after itself does not pretend it did. The record
keeps the entry and the whole outstanding set — bound and reserved-only alike —
and the caller is told `CLEANUP_FAILED`, so a later `cancel` can try again. A
retry that cannot see one of those identifiers would leak it; a retry must
never reissue one. Those identifiers stay spent: no code rewinds the allocator,
and no code withdraws a retirement record.

`~HandoverPreparationOwner` releases what is left and never throws, because a
destructor cannot report a cleanup failure. A caller that cares cancels
explicitly and reads the result.

## 20. Prepared-state forwarding restriction

The restriction is the existing bearer readiness gate, reused rather than
reimplemented. `establish` sets the bearer established and leaves it not
UE-ready, so `active()` is false; nothing in this slice calls `activateUe`.

A G-PDU whose TEID resolves to a prepared bearer is dropped at
`S1uEndpoint::handleGPdu` with `bearerInactiveDrops` counted on that entry. It
is not an unknown TEID, not a retired TEID and not a malformed packet: the
endpoint's `unknownTeidDrops`, `retiredTeidDrops` and `malformedDrops` stay at
zero. It never reaches the UE link, the frame encoders or the user-plane packet
counters, and it never becomes a user-plane credit.

`PreparedBearersNonForwardable` reads the real `BearerContext::active()` of the
real contexts through the registry entry rather than any flag this module kept,
so it cannot be made true by a description of a bearer that was never
established: a bearer that was never prepared answers false there.

## 21. TEID allocation and rollback semantics

There is no new TEID lifecycle. A prepared tunnel's identifier comes from
`UeRegistry::allocateLocalTeid` like any other, and:

* `allocateLocalTeid` reserves a value and `bindLocalTeid` accepts only a
  reserved one, so no caller can attach an identifier of its own choosing;
* a zero, a live or a retired identifier is refused, and nothing revives a
  retired one;
* the allocator is monotonic over a bounded issuance window, never reissues a
  value, and fails closed with `TeidExhausted`.

Rollback distinguishes the two kinds of thing an attempt may hold. A TEID that
was bound is a live mapping and is released through `unbindLocalTeid`, which
retires it so it becomes identifiable as retired rather than merely missing. A
TEID that was only reserved has never been a tunnel: `unbindLocalTeid` drops
the reservation and retires nothing, because there is nothing to retire.
Neither case erases history, and neither rewinds the allocator. A failed
attempt has spent its identifiers, and that is not a leak.

## 22. Admission-to-commit data flow

```
HandoverRequest + SourceContext + TargetContext + BearerRoleBinding[]
        |
        v  EvaluateHandoverAdmission          pure, allocates nothing
HandoverAdmission  (holdsTransportResources() == false)
        |
        v  HandoverPreparationOwner::admit    records ADMITTED / ADMISSION_REFUSED
PreparationRecord
        |
        v  HandoverPreparationOwner::commit   -> CommitHandoverResources
TargetResourceCommit { prepared, ownedEntry, outstandingTeids }
        |
        v  HandoverPreparationOwner::acknowledge
HandoverRequestAcknowledge                    via BuildHandoverRequestAcknowledge
```

The two things this flow must not conflate are the ones the module header
states: admission is not commitment, and prepared is not arrived. The admission
never holds transport; the commit owns it; the acknowledge reports it.

The record's resource ladder — `ADMISSION_EVALUATED`, `RESOURCES_RESERVED`,
`RESOURCES_COMMITTED_PREPARED`, `AWAITING_UE_TARGET_ACCESS` — is target-local
bookkeeping and is not the eight-state connected-mode lifecycle of section 12.
`awaitUeAccess` is the last step this slice defines, and it is a declaration
that the target is waiting, not a statement that a UE arrived. No code in this
repository recognises an arrival.

## 23. Handover Request Acknowledge integration

`HandoverPreparationOwner::acknowledge` builds the message from what the commit
actually bound:

* the MME-UE-S1AP-ID of the transaction, and the eNB-UE-S1AP-ID the commit
  allocated and bound — a caller cannot send an identifier this target never
  allocated;
* the committed transport set, one entry per admitted bearer, each naming the
  target's own S1-U address and the local TEID bound for that bearer;
* the failed list and the container behaviour of Phase 18-A, unchanged.
  `BuildHandoverRequestAcknowledge` still echoes the admission's
  `sourceToTarget` into `targetToSource`; that is accepted Phase 18-A
  behaviour pinned by the wire vectors, and producing a real Target-ToSource
  container is a later phase's work.

A transaction that is not prepared throws `HandoverRefused`: no record, or no
bound eNB-UE-S1AP-ID, is `INVALID_CONTEXT_IDENTITY`, and a transaction that has
not reached `TARGET_PREPARED` is `MISSING_MANDATORY_IE`. Repeating the call
produces the same message and gains no resource. The failure form is
`CommitRefusalAsHandoverFailure`, which carries the MME identity and names no
eNB-UE-S1AP-ID, because a failed commit bound none that survives.

## 24. Failure and cancellation behaviour

Every refusal is a typed `CommitRefusalRecord` carrying a detail and the
standard Cause it would be reported under, not a log line.

| `CommitRefusal` | Cause | Meaning |
|---|---|---|
| `ADMISSION_NOT_ADMITTED` | — | the admission handed in was not a successful one |
| `EMPTY_BEARER_SET` | — | no admitted bearer at all |
| `TARGET_IDENTITY_MISMATCH` | — | the target does not name the receiving eNB |
| `TARGET_TRANSPORT_ADDRESS_ABSENT` | — | the target has no S1-U address |
| `DUPLICATE_ERAB_ID` | — | two admitted bearers name the same E-RAB |
| `LINKED_DEFAULT_MISSING` | `radioNetwork` | a dedicated bearer names no default of this set, or there is no default |
| `BEARER_PARAMETERS_INVALID` | — | an E-RAB identity out of range, a zero QCI, or a zero SGW TEID |
| `MULTIPLE_DEFAULT_BEARERS` | — | a set that would need two default bearers |
| `TRANSACTION_IDENTITY_ABSENT` | — | the transaction names no UE |
| `CAPACITY_EXHAUSTED` | `radioNetwork`/20 | per-UE or registry capacity would be exceeded |
| `TEID_ALLOCATION_FAILED` | `transport`/13 | the local allocator could not produce a usable identifier |
| `DEFAULT_BEARER_PREPARATION_FAILED` | — | the default bearer could not be prepared |
| `DEDICATED_BEARER_PREPARATION_FAILED` | — | a dedicated bearer could not be prepared |
| `CONFLICTING_TRANSACTION` | — | another live preparation owns these resources |
| `STALE_ASSOCIATION` | — | the caller works under an association epoch no longer bound |
| `ALREADY_COMMITTED` | — | this transaction has already been committed |
| `WRONG_STATE` | — | the operation does not accept this state |
| `EXPIRED` | — | the preparation's deadline has passed |
| `CLEANUP_FAILED` | — | rollback did not complete, and is reported as such |

Failure injection is a `CommitFaultInjector` argument and never a global: an
ordinary call cannot be made to fail by anything outside its own preconditions.
The fault points are `CAPACITY_EXHAUSTED`, `DEFAULT_BEARER_PREPARATION`,
`DEDICATED_BEARER_PREPARATION`, `CONFLICTING_TRANSACTION`, `STALE_ASSOCIATION`
and `CLEANUP_FAILURE`. Two can be passed at once, because a rollback cannot
fail unless something makes one be attempted: `CLEANUP_FAILURE` alone is a
no-op on a commit that would otherwise succeed. TEID-allocation failure is
deliberately not a fault point; it is injected through the `UeRegistry`
allocator seam, where the existing exhaustion and boundary cases already live.

Cancellation is explicit and idempotent. `cancel` releases whatever the record
still owns and names it `PREPARATION_CANCELLED` unless it already had a
terminal name of its own, so a commit failure is never rewritten into a
cancellation. `expireDue(now)` is a deterministic call with an explicit clock,
not a timer: every record past its deadline and not already terminal is expired
and released. A completion after cancellation fails closed.

## 25. Verified source/target isolation

Preparing at a target touches the target's registry alone.

The source-continuity case builds a real source UE through the production
bearer path — `registerPeer`, `establish`, `activateUe`, `bindLocalTeid` on a
default and a dedicated bearer — and then prepares a handover at a second,
independent registry. After it, the source's local TEIDs still resolve, its
bearers are still `active()`, its `accessGeneration`, its `s1` state and its
`sessionRetained` are unchanged, and no source TEID has been retired. The
target's identifiers are all distinct from the source's.

Multi-UE isolation is the same shape with two transactions: four distinct local
TEIDs, each resolving to its own entry, and cancelling one preparation leaves
the other's TEIDs resolving and its acknowledge buildable. A preparation also
leaves an unrelated reached UE in the same registry untouched.

Source eNB identity is not derived anywhere in this slice: not from the
MME-facing SCTP association the target holds, not from the UE's TAC, not from a
matching EBI or TEID, and never by parsing the opaque RRC container. A
preparation that needs an identity it cannot establish from a documented
contract is refused.

## 26. Actual tests and evidence

`test/lte/handover_preparation.cpp`, **24 cases and 515 assertions**, driving
the commit and the preparation owner against real registry resources and the
isolated S1-U receive path.

| Category | Cases | What it proves |
|---|---|---|
| A. Real target commit | 1 | the identifiers are the allocator's own, and the commit owns a provisional context |
| B. Acknowledge from committed transport | 1 | the acknowledge names exactly the transport the commit bound |
| C. Multi-bearer ordering | 2 | a reversed E-RAB list still commits default first; three bearers in a scrambled order commit in readiness order |
| D. Atomic failure | 5 | a failure on the second bearer leaves nothing of the first; a failure on the first reserves one identifier and drops it; a rollback that cannot complete is surfaced and never reported as success; capacity exhaustion is a refusal and not a half-built context; a plan that cannot be committed whole is refused before anything is allocated |
| E. Non-forwardable preparation | 3 | a prepared bearer is established and not ready for the UE; a G-PDU for a prepared TEID is dropped as inactive, not as unknown or retired; an old TEID stops resolving when the preparation is cancelled |
| F. Source continuity | 1 | preparing at a target leaves the source eNB untouched |
| G. Duplicate and stale operations | 7 | a repeated request is one transaction and allocates nothing twice; a conflicting duplicate is refused and starts nothing; a new request after a finished preparation is a new transaction; work begun under a stale association epoch is refused; an expired preparation releases what it owned; a commit after the deadline expires the transaction instead; a completion after cancellation fails closed |
| H. Multi-UE isolation | 2 | two UEs prepared together stay independent; a preparation leaves a reached UE in the same registry alone |
| I. Regression preservation | 1 | the accepted Phase 18-A contracts are unchanged |
| Refusal surface | 1 | a refused commit reports a failure that names no surviving identifier |

The whole suite after the slice: **693 cases, 131493 assertions, 0 failed, 2
skipped**, up from 669 cases and 130978 assertions. The two skipped cases are
the two privileged TUN cases of the CI matrix, which have no ordinary `ctest`
entry and run only under the privileged job. The Phase 18-A handover slice is
unchanged at 40 cases and 376 assertions.

The evidence kinds are kept apart on purpose. The commit cases read an
identifier's fate from the production structures — the allocator's issued
sequence and the registry's own retirement record — rather than from a flag
this module set. The forwarding case drives `S1uEndpoint::handleDatagram`
against a loopback UDP endpoint and reads the endpoint and entry counters. No
case claims a packet capture, a live rejection result or a UE arrival.

## 27. Unsupported runtime behaviour

Nothing in this family runs a complete handover against a live or a simulated
MME. Specifically not implemented, and not claimed:

* no S1AP dispatcher integration for preparation: no Handover Request received
  by a running eNB starts a preparation, because the source identity cannot be
  established there and the path fails closed;
* no source context release, no source TEID retirement, no bearer path update;
* no data forwarding, direct or indirect;
* no RRC handover command, no Target-ToSource container of the target's own,
  and no security key derivation;
* no X2 handover, no Path Switch Request, no inter-RAT or inter-MME handover;
* no live Open5GS handover and no PCC policy change.

What *is* implemented now, and only against isolated deterministic tests and
the existing permitted privileged CI environments, is the target side of the
arrival: a handover-specific simulated radio frame is decoded by the production
radio handler, correlated to a committed preparation, and the prepared context
is promoted to a reached UE whose bearers are activated and whose Handover
Notify is gated on that arrival.

Prepared target transport is not completed handover, and a sent Handover Notify
is not one either. Do not claim otherwise.

## 28. Phase 18-C prerequisites

The remaining steps of section 15 were the prerequisites of the arrival phase.
This phase took up the first two; the last three are still open.

1. **Arrival.** *Taken up.* See section 29 onward. A documented contract
   recognises a UE at the target and promotes a provisional context into a
   reached one, re-binding its prepared bearers and activating them for a real
   verified peer.
2. **Handover Notify.** *Taken up.* See section 35. The named CGI and TAI are
   verified against the target's own identity before anything else moves, and
   the send is gated on the arrival.
3. **Source release.** *Still open.* Release the source context and retire its
   local S1-U TEIDs only after a Handover Notify for that UE.
4. **Bearer path update.** *Still open.* The MME-controlled update, which is
   the point of the S1 family and must not be replaced by a Path Switch
   Request.
5. **Data forwarding.** *Still open.* Only after the above, and with a defined
   forwarding model.

A handover is still not an Attach and not an idle-mode Service Request, and
none of these prerequisites may be reached by substituting one.

## 29. Target-arrival trust model

A provisional context becomes a reached UE through
`HandoverPreparationOwner::acceptArrival` and nothing else. The evidence it
requires is built from two halves that are deliberately separate: what the UE
said, and what this eNB is.

What the UE said arrives as one `SIMULATED_HANDOVER_ACCESS` frame: the arrival
binding, the source cell whose command it is executing, the target cell it is
announcing itself to, the MME-UE-S1AP-ID it claims and the PDN address it
restates.

What this eNB is, the target reads from its own `EnbConfig`: its cell identity,
its E-UTRAN CGI and the association epoch it is currently bound to. None of
that comes from the frame. The frame names the cell so a disagreement is
detectable rather than silently adopted.

The binding is a correlation value and not a credential. It is issued once per
committed preparation by `AllocateArrivalToken` — process-lifetime monotonic,
never zero, never repeated — and it has no S1AP representation: nothing puts one
into a transparent container or any other information element, and nothing
reads one out of one. In this phase it is handed from the target's preparation
to the source eNB's simulated handover command by a test harness that has
verified both ends. That hand-off is explicitly test-harness-verified
provenance and is not a production trust path; it becomes a Phase 18-D
prerequisite.

The optional `TargetArrivalEvidence::sourceCommand` is the corroboration a
two-eNB harness can supply: the source's own statement of what it authorised,
checked field by field against the arrival. It is absent on the ordinary radio
receive path, because a target does not see the command its source sent and
there is no information element in this repository that carries one. When it is
absent the target falls back to the agreement it can establish on its own and
does not pretend to a corroboration it does not have.

Twelve things must hold together: an existing committed transaction; its
current association epoch; its exact MME-UE-S1AP-ID; its committed target
eNB-UE-S1AP-ID; the target's own cell identity; the source-authorized command
or an equivalent verified transition; a handover-specific arrival through the
real radio path; a unique radio UE identity; an unowned radio peer; a binding
protected against stale and cross-transaction reuse; the original prepared
bearer set; and the absence of a conflicting reached-UE context. Each has its
own refusal, so a rejected arrival names what disagreed.

## 30. Simulated radio message and transport contract

Two message types were added to the existing simulated radio link, using its
envelope, its length discipline and its `DecodeError` refusals unchanged.

`SIMULATED_HANDOVER_COMMAND = 21`, downlink only, source eNB to the UE it
already serves. Twenty-one octets with no variable part:

```text
targetPlmn(3) || targetEnbId(4) || targetTac(2) || arrivalToken(4)
              || mmeUeS1apId(4) || ueIpv4(4)
```

`SIMULATED_HANDOVER_ACCESS = 22`, uplink only, the UE to the target eNB it
reached. Thirty octets with no variable part:

```text
arrivalToken(4) || sourcePlmn(3) || sourceEnbId(4) || sourceTac(2)
                || targetPlmn(3) || targetEnbId(4) || targetTac(2)
                || mmeUeS1apId(4) || ueIpv4(4)
```

Both refuse a zero binding, a zero eNB identifier, a zero MME-UE-S1AP-ID and a
zero PDN address at encode and at decode: none of the four names anything a
target could correlate against or forward to. The PLMN fields are three opaque
octets produced by `EncodePlmn`, never a string.

The MME-UE-S1AP-ID is the second half of the correlation. The target holds one
from the admission, and an arrival under a different one is a detectable
disagreement rather than a silent acceptance. The PDN address is a UE
restatement, at the same trust level as the existing `BEARER_READY` payload and
`BearerTransportReady`: a cell that never saw the session's Attach cannot learn
it without decrypting NAS, and it is never invented on the way.

These are simulator control frames and not 3GPP RRC. They are never placed in a
transparent container, never sent to an MME, and the exchange they form does
not implement full LTE RRC.

## 31. Provisional promotion algorithm

`UeRegistry::promoteProvisional` moves one provisional entry into the reached-UE
indexes. It is a move of the same `EnbUeEntry`, not a re-establishment.

Before anything is published it validates: the entry is still provisional, the
radio identity is non-zero and unused, the peer is unowned, and every
established bearer is not `active()` and is bound to the identity the move is
about to change. It refuses the whole promotion if the entry's `mmeUeS1apId` is
zero while any bearer is established, because there would be nothing to re-bind
them back to.

The move then re-binds every prepared bearer to the arrived radio identity
through `DefaultBearerContext::rebindAccessIdentity`, which refuses a bearer
that is not established, one that is already UE-ready, a zero destination and a
`from` that does not name the identity the bearer is currently bound to. This
is necessary because `CommitHandoverResources` binds a prepared bearer to the
MME-UE-S1AP-ID — the only identity the target has before a UE arrives — and
`S1uEndpoint::forwardUplink` validates against `entry.radioUeId`. The two are
not interchangeable.

Publication claims the peer index and then the radio-identity index. Any
failure unwinds the re-bindings in reverse, recovers the `unique_ptr` and
restores the provisional map, so no half-published index survives.

`UeRegistry::demoteToProvisional` is the exact inverse, for an arrival whose
later step did not complete. It validates the same preconditions from the other
side, erases both indexes, clears the radio identity and the peer, re-binds the
bearers back to the `mmeUeS1apId`, and re-inserts under a fresh provisional key.
Its own rollback restores the reached indexes if the re-binding fails.

No TEID, no S1AP identifier and no capacity slot moves in either direction.

## 32. Registry indexing and capacity ownership

A provisional context lives in `m_provisional` alone. It has `radioUeId == 0`,
which `registerPeer` refuses, and it is absent from the radio-identity index
and the peer index. `UeRegistry::all()` deliberately returns reached entries
only, which is why `holdsProvisional` exists: an arrival has to be able to prove
the prepared context is still held as provisional before promoting it.

A provisional context consumes per-UE resources and per-TEID capacity against
the same `maxUes` bound as a reached UE. Promotion consumes no second slot: it
moves the entry from the provisional map into `m_byRadioUeId`, and the test
evidence for that is a registry at capacity minus one admitting an arrival that
leaves `size()` exactly one larger than before and the provisional map one
smaller.

## 33. Preparation-owner handoff

`HandoverPreparationOwner` is owned by `EnbMultiplexer` as `m_preparations`, is
created in `bindAssociation` with the epoch that association allocated, and is
destroyed in `unbindAssociation`. A preparation therefore cannot outlive the
association it was made under, and a caller presenting an older epoch is refused
as stale rather than served.

On a successful arrival the record sets `ownershipTransferred`, clears `entry`
and `ownedTeids`, and keeps only immutable audit scalars: `reachedRadioUeId`,
`reachedEnbUeS1apId` and `reachedUeIpv4`. Those values never resolve to
anything; they are what was reached, not a handle to it.

From that moment the preparation layer can release nothing.
`releaseOwned` early-returns with `WRONG_STATE`, `expireDue` skips the record,
and the owner's destructor — which is what a failed association teardown runs —
therefore cannot destroy a reached UE or retire its current TEIDs. This is the
mandatory rule of the phase: a successful promotion transfers ownership away
from preparation cleanup exactly once.

## 34. Bearer activation

`acceptArrival` validates the whole prepared set before the first `activateUe`:
the default bearer and every dedicated one must be signalling-established, not
already UE-ready, bound to the arrived radio identity, and non-zero in its E-RAB
identity. Because `activateUe` re-checks exactly those conditions plus a
non-zero address, the activation loop cannot stop half way. That is what makes
`demoteToProvisional`'s refusal to touch an active bearer safe.

The default is activated first whatever order the E-RABs arrived in, and a
dedicated bearer only after the default it is linked to. The readiness is read
from the real `BearerContext` objects, so a record that described readiness it
does not have cannot pass.

Nothing is re-established and no TEID is allocated at arrival. The prepared
pair is carried into the reached UE untouched. `BearerRuntime::restoreAccess`
is not involved and stays TUN-gated.

## 35. Handover Notify gate

`HandoverPreparationOwner::notify` is the only route to a transmitted Handover
Notify, and `EnbMultiplexer::notifyHandover` is the only route to that. The
gate, in order:

1. the transaction exists;
2. it belongs to the association the caller is working under;
12. it has not already been notified — checked early so a duplicate is refused
    as a duplicate rather than as something else that also happens to hold;
3. its resources were committed;
4. the UE's arrival was verified;
5. the promotion succeeded and the reached registry, not the record, owns the
   context;
11. the source and the target name two distinct cells;
7, 8, 6. the identities the message would carry are cross-checked against the
    live reached context, and every prepared bearer is read as ready from the
    real contexts;
9, 10. the cell the caller names is the one the transaction was admitted for,
    so the CGI and the TAI are this cell's and not a caller's assertion.

Then the real codec builds the message and the real sender transmits it. An
encode failure and a send failure are both reported as failures; a failed send
leaves `notifySent` false so a later attempt is still possible and a duplicate
arrival still cannot produce a second successful one.

The message itself is Handover Notification, procedure 2, an initiating
message, carrying the MME-UE-S1AP-ID and the eNB-UE-S1AP-ID the transaction
bound and the target's own CGI and TAI. It carries no CriticalityDiagnostics.

## 36. Security limitations

The arrival binding is not a cryptographic authentication key and proves nothing
on its own. No NAS or AS security key is derived or fabricated anywhere in this
slice: `nextHopParameter` and `nextHopChainingCount` are carried from
signalling, never generated, defaulted, derived or logged.

The source-to-target command is a simulator control exchange. It is not
authenticated, it is not confidential, and its binding is only as good as the
state the target holds about the transaction that issued it.

The `SourceContext` is test-harness-verified provenance and must not silently
become trusted production information in a live S1AP dispatcher. The dispatcher
does not start a preparation for that reason.

## 37. Transparent-container limitations

`SimulatedHandoverCommand` and `SimulatedHandoverAccess` are not RRC and are
never put in a transparent container. The opaque handover container continues
to be preserved byte for byte and never parsed for RRC or security content; an
opaque container is not authority to invent fields.

`BuildHandoverRequestAcknowledge` echoes the admission's `sourceToTarget` into
`targetToSource`. That is accepted Phase 18-A behaviour pinned by the wire
vectors and is deliberately unchanged: the acknowledge still carries no
container of the target's own. Producing a real Target-ToSource container is
later work.

## 38. Replay and stale transaction protection

A binding is issued once and spent once. A repeat of a frame whose binding has
already been consumed is `ARRIVAL_TOKEN_CONSUMED`, not a second promotion. A
binding nothing ever issued is `ARRIVAL_TOKEN_UNKNOWN`, and the allocator never
reissues a value, so a token from a cleaned-up transaction cannot be reissued to
another one.

An arrival naming a different MME-UE-S1AP-ID, a different source cell, a
different target cell or — where the caller has seen the command — a different
PDN address is refused with its own name and disturbs nothing. An arrival under
a radio identity a live UE already holds is `RADIO_IDENTITY_CONFLICT`; one from
a peer that already owns a UE is `RADIO_PEER_CONFLICT`. An arrival presented
under an association epoch that is not the bound one is `STALE_ASSOCIATION`.

Every refusal is classified and counted through the production radio handler's
existing rejection path. None of them creates, disturbs or releases any bearer
or UE state, and none of them touches an unrelated transaction.

## 39. Failure and rollback evidence

Two deterministic fault seams, both arguments and never production switches.

`PromotionFaultInjector` sits inside the registry: `PEER_INDEX_PUBLICATION`
fails after the peer index has been claimed, and `RADIO_INDEX_PUBLICATION`
after both have. Both roll the move back completely.

`ArrivalFaultInjector` sits in the preparation layer: `REGISTRY_PUBLICATION`
maps onto the registry's reached-index publication, and `BEARER_READINESS`
fires after the complete bearer set has been validated and before the first
`activateUe` — which is the only place it can, given that the activation loop
cannot stop half way. On that failure the arrival demotes the context back to
provisional and resets the resource state to awaiting access.

In every injected case the evidence is the same: nothing in the reached
indexes, the prepared context still provisional and still owning its transport,
its TEIDs still resolving to it, its bearers still not `active()`, and a real
G-PDU for the prepared TEID still dropped as `bearerInactiveDrops` rather than
delivered.

## 40. Source continuity

Preparing at a target and arriving at one touch the target's registry alone.
The source eNB's contexts, its local TEIDs, its bearer identities, its access
generation and its session state do not move, and no source TEID is retired.

The evidence for this is a two-eNB fixture: a reached UE on the source with a
live TEID, a failed arrival at the target, and the source still holding the same
entry, the same resolvable TEID and the same active bearer afterwards. The
other UE's prepared resources at the target are equally untouched.

The simulated handover command is the only thing that leaves the source, and it
is not an S1AP message and not a bearer transition.

## 41. Multi-UE isolation

Two preparations at one target are two transactions with two bindings, and a
failed arrival for one of them leaves the other exactly as it was: still
provisional, still owning its transport, its TEID still resolving to it and its
bearer still not forwardable. A second UE arriving under a radio identity a
reached UE already holds is refused rather than merged into that UE's context,
because the arrival is handled before any entry lookup and can therefore never
fall into `registerPeer`.

A reached UE's ownership transfer does not make another record's cleanup touch
it: the preparation owner's destructor runs against records, and a transferred
record is a no-op.

## 42. Test results

`test/lte/handover_target_arrival.cpp`, twelve cases under
`lte/handover/arrival:*`, covering the required set:

| Required | Case |
|---|---|
| A | a prepared context is not a reached ue and cannot forward a g-pdu |
| B | an access frame through the production receive path correlates to the prepared transaction |
| C | promotion moves the same entry and preserves every prepared identifier |
| D | default and dedicated bearers activate with their prepared identity |
| E | the same prepared teid refuses forwarding before arrival and delivers after it |
| F | a handover notify is built from a proven arrival and sent through the real association |
| G | a notify attempted before the arrival gate is refused without sending |
| H | replayed, conflicting and wrong-target arrivals disturb nothing |
| I | a promotion that cannot complete leaves no half-promoted context |
| J | destroying the preparation owner leaves a reached ue alone |
| K | a failed arrival leaves the source and another ue untouched |
| L | the accepted gtpu and teid contracts are unchanged |

Every arrival in these cases is a real encoded radio frame delivered to
`EnbMultiplexer::handleRadioFrame`. There is no `arrived=true` flag in the
tests or in the production code.

## 43. Remaining Phase 18-D prerequisites

What this phase established, and what a later phase still needs.

Established: the arrival evidence contract, the atomic promotion with its
rollback, the ownership transfer away from preparation cleanup, the activation
of the prepared bearers and the Handover Notify gate wired to the real
association-aware send.

Still open:

* **Source release.** Nothing releases a source context or retires a source
  TEID. A source eNB that has sent a handover command still serves the UE.
* **MME-controlled bearer path update.** The point of the S1 family. A Handover
  Notify is the trigger and is now gated; the update it triggers is not
  implemented, and must not be replaced by a Path Switch Request.
* **Data forwarding.** Neither direct nor indirect, and no defined model yet.
* **A production path for the arrival binding.** In this phase the binding is
  handed target to source by a test harness that has verified both ends. That
  is explicitly test-harness-verified provenance. A live two-eNB run needs a
  real mechanism, and until one exists the runtime path must fail closed rather
  than treat a guessed source as verified.
* **A production path for the source context.** Same finding as Phase 18-B,
  unchanged: the MME-facing SCTP association does not prove the source eNB
  identity.

A handover is not an Attach and not an idle-mode Service Request, and none of
these may be reached by substituting one. A sent Handover Notify is not
end-to-end S1 handover completion.

## 44. Phase 18-D: two-eNB coordination and UE-side execution

This stage put the preparation slice and the arrival slice into one executed
sequence between two independently instantiated LTE eNBs and one running LTE UE.

New in the tree:

* `src/lte/enb/handover_orchestration.{hpp,cpp}` — the coordination contract,
  the orchestration state machine and the isolated MME relay.
* `S1_CONTEXT_ESTABLISHED` in `src/lte/ue/radio_link.{hpp,cpp}` and its handlers
  in `src/lte/enb/multiplexer.{hpp,cpp}` and `src/lte/ue/app.cpp`.
* UE-side execution of `SIMULATED_HANDOVER_COMMAND` in the UE's own production
  radio receive path.
* `test/lte/handover_orchestration.cpp` and `test/lte/handover_acceptance.cpp`.

### The isolated MME relay

`IsolatedMmeRelay` is a transport between two simulator-owned eNBs and nothing
more. Every message that crosses it is a real encoded S1AP PDU produced and
consumed by the accepted production codec. It holds no subscriber state, it is
not an MME and it performs no core procedure: it relays a Handover Request to
the target, relays the Acknowledge or the Failure back to the source, observes
the Handover Notify the target really sends, and advances the state machine.

What its acceptance of a Handover Notify proves is that the target sent one and
that the two eNBs agree about the transaction. It does not prove, and must not
be reported as, any of the following: that a live EPC executed a Modify Bearer
Request, that real downlink traffic was redirected to the target, that a bearer
path was updated by an MME, or that there is live EPC continuity. There is no
Path Switch Request in this repository and none is added to reach one.

### Source identity and target selection

The source context is supplied by the caller and is verified against the live
source registry before a transaction opens. It is not derived from the
MME-facing SCTP association, from TAC or PLMN equality, from a matching EBI or
TEID, or by parsing an opaque container. The live S1AP dispatcher still starts
no preparation, because it cannot establish that provenance.

Target selection is explicit configuration in a `HandoverTargetBinding`: the
target's Global-ENB-ID, CGI, TAI, radio endpoint, S1-U address, the security
algorithm sets, the association epoch, and the one source it permits. Nothing
is discovered. A target identity whose PLMN halves disagree is refused as an
invalid context identity, and a target that does not permit this source is
refused.

### The session binding the UE checks a command against

A connected-mode handover command names an MME-UE-S1AP-ID. The UE checks it
against the identity it already holds; it never adopts one. Until this stage
the production UE had no way to learn that identity, so `onConnectedHandover`
was unreachable and the check could not be honoured.

The fix is one internal simulator frame, `S1_CONTEXT_ESTABLISHED`, eight octets
carrying a non-zero eNB-UE-S1AP-ID and a non-zero MME-UE-S1AP-ID. The serving
cell sends it at the moment it makes a bearer UE-ready, which is exactly when
its own registry entry holds the pair: from `onBearerReady` on a fresh attach
and from the default-bearer branch of `BEARER_TRANSPORT_READY` on a
restoration. Both placements are the same event in production terms — a new S1
context with a new identity pair — and neither is a statement about bearer
roles.

The frame is downlink only and both halves are refused at encode and at decode
when zero. It states a binding; it does not grant one. No command establishes
one, and nothing adopts an identity out of a frame that is to be checked. It is
a simulator abstraction and not 3GPP: it never leaves the simulator's radio
layer and it is never described as RRC or NAS.

### How the UE consumes a command

The command is handled in the UE's own production radio receive path, in
`app.cpp`, and every part of it is checked before any transport moves. The
command names a cell and never an address: the radio endpoint is resolved from
the UE's own `targetCell` configuration, so a frame cannot redirect a UE to an
endpoint nobody authorized. The PDN address is compared against the one the UE's
own NAS was assigned. The MME identity is checked inside
`MobilityContext::onConnectedHandover`, which is check-then-mutate. A refusal
therefore leaves the UE serving the cell it is already on.

Only after the last check passes does the UE change its radio peer, and the
`SIMULATED_HANDOVER_ACCESS` it then transmits comes from its own socket and
names both cells from the UE's own configuration rather than from the command.
The target correlates that frame against the committed preparation: the arrival
token, both cells, both S1AP identities and the PDN address must all agree. The
token is a correlation value and not a credential; it has no S1AP
representation and nothing derives a key from it.

The UE starts no NAS procedure. A run of this sequence reports exactly one
Attach and no Service Request.

## 45. The acceptance sequence

`test/lte/handover_acceptance.cpp` drives the whole of it against two real
`EnbMultiplexer` instances, the real `lte::ue::Run()`, an isolated MME relay and
a scripted EPS peer that is moved up one layer from radio to S1AP. The eighteen
steps end in `AWAITING_CORE_PATH_UPDATE`, and every step is observed in the
run's own transcript:

| Step | Observation |
|---|---|
| 1 | `State=UE_CONNECTED_TO_ENB` |
| 2 | `Dedicated EPS bearer 6 ready for forwarding on LTE UE 7` |
| 3–5 | Handover Required, then a Handover Request on the wire to the target |
| 6–7 | admission, a real committed transport set and its Acknowledge |
| 8 | the Handover Command relayed back to the source |
| 9–10 | `Connected-mode handover command accepted (MME-UE-S1AP-ID=201)` |
| 11 | `radio transport moved to the authorized target cell 460/02/2` |
| 12 | `SIMULATED_HANDOVER_ACCESS sent to the target cell` |
| 13 | `Verified handover arrival of LTE UE 7 to this cell from eNB 74565` |
| 14–15 | promotion preserving the prepared TEIDs and S1AP identities |
| 16–17 | the Handover Notify observed on the real association and accepted |
| 18 | the transaction reaches `AWAITING_CORE_PATH_UPDATE` |

The run closes through the UE's own clean shutdown and reports
`tun-ul=2/128 tun-dl=2/132` and `dedicated-ul=1 dedicated-dl=1`, and it reports
exactly one `State=ATTACH_REQUEST_SENT` and one `State=ATTACH_COMPLETE_SENT`.

## 46. User-plane boundary

Before the trigger the case moves real traffic on both of the source's active
bearers. After verified arrival it moves two test-owned downlink G-PDUs through
the isolated production S1-U receiver, one per bearer, and checks each delivered
datagram's payload and source four-tuple at the application socket. The kernel
only hands a datagram to a socket after checking the IPv4 header and the UDP
checksum of the whole datagram the UE wrote into its TUN, so a delivered
payload and source four-tuple is delivery evidence and not a loopback
assertion.

What this shows: the prepared TEIDs are the ones that carry the traffic, they
are active only after arrival, the downlink reaches the UE now associated with
the target, the PDN IPv4 is unchanged and the default and dedicated roles are
correct. What it does not show, and must not be claimed: that a real SGW
redirected anything, that an MME Modify Bearer Request was executed, or that
there is live EPC continuity.

A benign `[WARN] Dropped invalid LTE TUN uplink packet: Packet is not IPv4`
appears in every run of the acceptance. It is kernel IPv6 noise in the private
network namespace, counted as `drops(malformed/inactive)=1/0`, and it is not
part of the sequence.

## 47. What the handover must not disturb

Two focused cases in `test/lte/handover_orchestration.cpp` close the negative
side of the sequence.

* A handover of one UE leaves a second UE on the same cell alone: the same S1
  context, the same access generation, the same bearers, the same local
  transport, and a working downlink data path on the same TEIDs. The moved UE's
  source transport is likewise untouched — it still resolves, it is unretired
  and its own tunnel still forwards, because source release is deferred work
  and is not simulated by retiring anything early.
* A delayed G-PDU for a source TEID reaches no tunnel the handover created. The
  target never bound that identifier, so the packet is refused before it can
  touch the reached UE's bearers or its radio endpoint and no counter of the
  reached UE moves. An End Marker is still only recorded: for an identifier the
  cell never held and for its own active tunnel alike, it releases nothing and
  starts nothing.

## 48. Implemented versus deferred after Phase 18-D

Implemented: the two-eNB coordination contract, the relayed preparation with
real S1AP bytes on every hop, the source Handover Command gate, the UE-side
execution of the command in the production receive path with a checked MME
session binding, the correlated arrival, the promotion, and the Handover Notify
gate. The end of the slice is `AWAITING_CORE_PATH_UPDATE` and it stays there.

Still deferred, unchanged:

* **Source release.** Nothing releases a source context or retires a source
  TEID, and a source eNB that has sent a handover command still serves the UE.
* **MME-controlled bearer path update.** A Handover Notify is the trigger and
  is gated; the update it triggers is not implemented and must not be replaced
  by a Path Switch Request.
* **Data forwarding.** Neither direct nor indirect.
* **A production arrival-binding path.** The binding is still produced by the
  preparation and repeated by the UE from the command; a live two-eNB run
  against a real core needs a mechanism this repository does not have.
* **Chained handovers.** One connected-mode handover at a time per access; a
  second command while one is executing is refused.

## 49. Test coverage

`test/lte/handover_orchestration.cpp`, twenty-eight cases under
`lte/handover/orchestration:*`, covering source provenance, coordinator binding
and its refusal set, the source Handover Command gate, the isolated MME relay
and its refusals, multi-UE isolation and the source-lifetime invariants.

`test/lte/handover_acceptance.cpp`, one privileged case,
`lte/handover/acceptance: a connected-mode handover executes end to end between
two real eNBs`. It needs a real kernel TUN, so it is a `doctest::skip()` case
with no `ctest` entry at all, and the privileged CI job runs it as its own
invocation with its own log and its own sentinels,
`UNIRANSIM-PHASE18D-PRIVILEGED-EXECUTED` and
`UNIRANSIM-PHASE18D-PRIVILEGED-COMPLETE`. The privileged job runs three
invocations, one per skipped case, so one case's pass cannot be mistaken for
another's.

Every Phase 17 and Phase 18-A/B/C case file is unchanged and still runs in the
ordinary suite: `test/lte/ue_mobility_target.cpp`, `test/lte/handover_s1.cpp`,
`test/lte/handover_preparation.cpp` and `test/lte/handover_target_arrival.cpp`.

## 50. Phase 18-E: the isolated core path and the source release

Phase 18-D ended at `AWAITING_CORE_PATH_UPDATE` on purpose. This stage is the
continuation: the isolated MME dispatches a verified bearer path update, the
isolated SGW installs it atomically, the MME confirms it against the map the
SGW actually holds, and only then does a bounded guard allow the MME to release
the source context with a real encoded UE Context Release Command.

New in the tree:

* `src/lte/enb/handover_core_path.{hpp,cpp}` — the isolated SGW's forwarding
  map, its sender, the MME's request/commit/confirmation contract and the
  reconciliation of an answer that was never observed.
* `src/lte/enb/handover_source_release.{hpp,cpp}` — the source's own record of
  a handover it executed, the MME's verified release decision, the
  handover-specific release and the MME's release steps.
* `UeRegistry::removeHandoverSource` — the handover-specific counterpart of
  `releaseS1`.
* `DecodeUeContextReleaseComplete` in the S1AP codec.
* `test/lte/handover_core_path.cpp` and `test/lte/handover_core_phase.cpp`,
  and a second privileged case in `test/lte/handover_acceptance.cpp`.

The Phase 18-D acceptance, its relay and its state machine are unchanged. The
only extension to the shared state machine is one authorized continuation out
of `AWAITING_CORE_PATH_UPDATE`, and the coordinator offers it only to a record
that has entered the isolated core phase. A Phase 18-D transaction still stops
where it did and is still terminal there.

## 51. What the isolated core path is, and what it is not

It is a real forwarding map with real sockets. `IsolatedSgw::sendDownlink`
reads the destination out of the installed map at send time and sends a genuine
GTP-U T-PDU to that endpoint tuple. A test that builds a target-bound packet
itself proves nothing about a path migration, so the sender belongs to the map
and the caller only ever names a bearer.

It is **not** S11 GTPv2-C. The MME/SGW exchange is an explicitly labelled
simulator-internal typed contract:

```
IsolatedPathUpdateRequest   the MME's dispatch: transaction, session, epoch,
                            target identity, target S1-U address, expected
                            generation, one accepted endpoint per E-RAB
IsolatedPathUpdateCommit    what the SGW actually installed: generation,
                            owning transaction, per-bearer destination and the
                            original source mapping it replaced
```

No Modify Bearer Request is encoded, decoded or claimed, no GTP-C message exists
in the tree, and a confirmed mapping says nothing about a live EPC. The
procedure codes and information elements of the S1AP messages that *are*
encoded come from TS 36.413 and are unchanged.

## 52. The forwarding map

The map is keyed by the verified EPS session identity — the MME-UE-S1AP-ID plus
the PDN address the UE's own NAS was assigned — and, within a session, by EBI.
Each entry holds:

| Field | Meaning |
|---|---|
| `sgwTeid` | The SGW-side tunnel identity the eNB sends uplink to. Part of the key: a bearer whose uplink TEID changed is not the same bearer. |
| `endpoint` | Where downlink goes now: IPv4 address, port and the eNB-local TEID. |
| `originalSource` | Where it went before the update. It is what an End Marker is sent to and what a confirmation names as replaced. |
| `generation` | Bumped once per published replacement of the whole session. |
| `owner` | The transaction that installed the set. |

The destination is an endpoint tuple and never a TEID on its own. Two eNBs can
legitimately hold the same numeric local TEID — each allocates from its own
registry and the number means nothing outside that registry — so a map keyed by
TEID alone would deliver one cell's traffic to the other. The deterministic
suite contains exactly that case: two sessions, one numeric TEID, two cells, and
each downlink arrives at the cell the map names.

A session enters the map only through `installSession`, which is how the source
mapping measured before the handover comes into existence. Nothing else creates
one.

## 53. The atomic multi-bearer update

`IsolatedSgw::apply` is all-or-nothing, and the ordering is the guarantee:

1. **Mode.** A live-EPC instance refuses every entry point.
2. **Completeness.** The request must name a session, a transaction, an MME
   association epoch, a target identity, the target's own S1-U address, the
   generation it was written against, and at least one bearer.
3. **Session.** An unknown session has no source path to replace. Another
   transaction's ownership is a conflict.
4. **Staleness.** The association epoch and the expected generation must be the
   ones the session holds.
5. **The whole proposed set,** before anything is written: every EBI must exist
   in the session; every SGW-side TEID must be the installed one; every
   destination must be a complete endpoint on the target's own S1-U address;
   every role and linked-default relationship must match the session's
   inventory; no EBI may appear twice; the set must cover every bearer of the
   session and no others; and there must be exactly one default bearer with
   every dedicated bearer's linked default inside the same set.
6. **Publication.** A complete replacement `SessionState` is built and assigned
   to the session in one step. There is no intermediate state in which the
   default bearer is on the target and the dedicated one is still on the
   source.

An exact repeat of the replacement a transaction already installed is a replay:
it reports the installed generation and publishes nothing. A repeat that
disagrees with it is a conflicting replacement and is refused.

## 54. The MME's decision, confirmation and the indeterminate case

The MME's precondition set, checked by `BeginIsolatedCorePathUpdate` before
anything is dispatched:

* isolated-simulator mode;
* a transaction at `AWAITING_CORE_PATH_UPDATE`, not cancelled, with its
  arrival token bound and its coordination record complete;
* a target that still holds the reached UE under the verified arrival's radio
  identity and this transaction's MME identity;
* every admitted bearer present, established, `active()` and agreeing with the
  transaction's own EBI, QCI, role and linked-default statement;
* exactly one default bearer and every dedicated bearer's linked default inside
  the set;
* an isolated SGW that really holds this session's source path.

Only then is the request recorded and the transaction moved to
`CORE_UPDATE_REQUESTED`. `ApplyIsolatedBearerPathUpdate` moves it to
`CORE_UPDATE_COMMITTING` before the SGW is entered, asks the SGW, and then
reads the installed map back through `ReadIsolatedPathState`. The confirmation
is verified against the request: session, transaction, MME association epoch,
generation (exactly the request's expected generation plus one), the exact EBI
set, every destination, every SGW-side TEID, every role relationship and every
original source mapping.

Three outcomes, and only one is a success:

* `CORE_PATH_UPDATED` — the SGW's installed map matched the request exactly.
* `CORE_UPDATE_FAILED` — the SGW refused and published nothing.
* `CORE_UPDATE_INDETERMINATE` — a replacement may be installed but this MME
  cannot prove it. Nothing is released, no second update is applied, and
  `cancel` refuses the transaction.

`ReconcileIsolatedPathUpdate` is the only way out of the indeterminate state. It
re-reads the map, verifies the same confirmation, and moves the transaction to
`CORE_PATH_UPDATED` only when the exact transaction and the complete endpoint
set can be proven. It never re-applies the request, so a lost answer cannot
cause a second publication.

## 55. The source release

Two facts must agree before a UE Context Release Command takes the handover
path:

1. **The source's own record.** When the source's production radio sender
   delivers the simulated handover command, it records the transaction, the
   UE's radio identity, the S1AP pair, the access generation, the association
   epoch and the target. A cell that never commanded a UE holds no such record,
   and no message can supply one.
2. **The MME's verified decision.** `BuildHandoverSourceReleaseDecision` can
   only be built from a record whose core path was confirmed; it names the
   transaction, both S1AP identities, the access generation, the association
   epoch, the confirmed path generation, the target and the exact source
   transport. The source verifies every one of them against its live context
   before it retires anything.

The command must additionally state `radioNetwork`/`successful-handover`. The
cause corroborates; it never authorizes.

`ReleaseHandoverSourceContext` then calls `UeRegistry::removeHandoverSource`,
which retires the default and dedicated local TEIDs through the ordinary
ledger, erases the S1AP identity indexes, releases the bearer contexts and
erases the entry, its radio identity and its peer. Nothing is retained. The
handler sends a real encoded `UeContextReleaseComplete` and no
`S1_CONTEXT_RELEASED`.

The ordinary ECM-IDLE path in `onUeContextReleaseCommand` is unchanged: any
release that is not a successful-handover release still goes through
`releaseS1`, still retains the session, still keeps the entry in
`IDLE_RETAINED`, and still tells the UE.

Timing is a bounded guard. `EnterSourceReleaseWait` arms a deadline the caller
supplies; a release before it is refused as `RELEASE_GUARD_NOT_SATISFIED`. A
sent command is not a release: only a decoded Complete whose identity pair
matches the transaction produces `ISOLATED_HANDOVER_COMPLETE`. If the Complete
is lost, `ReconcileSourceRelease` confirms only when the source's registry no
longer holds the context and every TEID the decision named is recorded as
retired, and it reports that as `RECONCILED_REGISTRY`, never as a received
Complete.

## 56. The accepted sequence

The privileged case
`lte/handover/acceptance: mme-controlled core path migration and source release complete an isolated s1 handover`
drives 31 steps and ends in `ISOLATED_HANDOVER_COMPLETE`:

| Step | Observation |
|---|---|
| 1–2 | the running UE is attached to the source; both bearers are active |
| 3 | the isolated SGW holds a source mapping for both bearers |
| 4–5 | the SGW's own sender delivers a default and a dedicated downlink that the source UE receives, and the source's uplink reaches the SGW's socket on both bearer TEIDs |
| 6–9 | Handover Required, the relayed preparation, the committed target transport and the simulated command |
| 10–12 | the UE runtime moves its radio endpoint, the target verifies the arrival, promotes and activates |
| 13–14 | the target's real Handover Notify is accepted and the transaction reaches `AWAITING_CORE_PATH_UPDATE` |
| 15–17 | the MME requests the migration, the SGW publishes generation 2 atomically, the MME verifies it against the installed map |
| 18–20 | the same SGW instance sends the default and the dedicated downlink to the target's local TEIDs; the target UE receives both with its PDN address unchanged |
| 21 | an End Marker on the old source path is recorded as a control message and changes no release state |
| 22–27 | the guard elapses, the MME sends the real Release Command, the source releases and retires its TEIDs, and the MME verifies the real Complete |
| 28 | a delayed G-PDU for the retired source TEID is rejected as retired |
| 29–30 | the target's downlink and uplink still work on both bearers, and no other context changed |
| 31 | the transaction reaches `ISOLATED_HANDOVER_COMPLETE` |

The run reports `tun-ul=4/...` and `tun-dl=6/...`, exactly one
`ATTACH_REQUEST_SENT` and one `ATTACH_COMPLETE_SENT`, and no Service Request.

## 57. Implemented versus deferred after Phase 18-E

| Area | Status |
|---|---|
| Isolated MME-owned update decision | **Implemented** |
| Isolated SGW forwarding map with per-bearer endpoint tuples | **Implemented** |
| Atomic multi-bearer replacement | **Implemented** |
| Confirmation read back out of the installed map | **Implemented** |
| Indeterminate handling and reconciliation | **Implemented** |
| SGW-originated downlink before and after the switch | **Implemented, with real UDP** |
| End Marker on the old path | **Implemented (isolated SGW producer, eNB recorder)** |
| MME-authorized, handover-specific source release | **Implemented** |
| Real encoded UE Context Release Command/Complete | **Implemented** |
| Source TEID retirement and delayed-packet rejection | **Implemented** |
| Target preservation after source cleanup | **Implemented** |
| Real MME integration | **Deferred** |
| Real SGW control-plane signalling (GTPv2-C) | **Deferred** |
| Standards-valid RRC transparent containers | **Deferred** |
| Real source/target coordination (an over-the-air arrival binding) | **Deferred** |
| Live Open5GS authorization for a handover | **Deferred, and not requested** |
| Optional forwarding and packet-loss handling | **Deferred** |
| Chained handovers | **Deferred** |

## 58. Retained interoperability gaps

Nothing here narrows the gaps the earlier sections recorded, and this stage adds
no new claim about a live core:

* **Real MME integration.** The isolated MME is a relay between two simulator
  eNBs. It holds no subscriber state, performs no core procedure, and is not
  reachable from a live S1AP association.
* **Real SGW control-plane signalling.** No GTPv2-C message exists. The path
  update is a typed in-process contract between two components the simulator
  owns, and it must not be described as a Modify Bearer Request.
* **Standards-valid RRC transparent containers.** The source-to-target
  container is the simulator's own labelled bytes, echoed by the acknowledge.
  No RRC message is produced or parsed.
* **Real source/target coordination.** The arrival binding is a correlation
  value handed from the target's preparation to the source by a harness that
  verified both ends. It is not a credential and it has no S1AP representation.
* **Live Open5GS authorization.** Phase 18-E performed no live experiment and
  none is claimed. No PCC rule, subscriber record, HSS datum or EPC process was
  touched, and a successful isolated simulation authorizes no live handover.
* **Optional forwarding and loss handling.** There is no direct or indirect
  data forwarding. The End Marker this stage sends is the isolated SGW's
  statement that the old path ended; it is not a forwarding mechanism, it does
  not drain a tunnel, and no packet is reordered, replayed or recovered.
* **Chained handovers.** One connected-mode handover per access. A second one
  while the first is executing is refused, and a completed transaction is
  terminal.

## 59. Test coverage

`test/lte/handover_core_path.cpp`, sixteen cases under
`lte/handover/core-path:*`, drives the map and its sender against real UDP
sockets standing in for two cells: provisioning, atomic publication, reverse
bearer order, partial and malformed replacements, a mapping without exactly one
default bearer, the same numeric TEID on two cells, duplicates and conflicting
duplicates, stale generation and association, the sender before and after the
update, the confirmation and its refusals, the End Marker and the live-mode
refusal.

`test/lte/handover_core_phase.cpp`, thirteen cases under
`lte/handover/core-phase:*`, drives the full production pipeline — two real
`EnbMultiplexer` instances, the isolated MME relay, a real encoded radio
arrival and the isolated SGW — through the notify, the update, the confirmation,
the End Marker, the guard, the release and the reconciliation, plus the
refusals: an update before the notify, an update without a reached target, a
lost answer before and after the SGW published, an unreadable installation, a
second update, an unverified or stale release decision, an unchanged ordinary
idle release, a duplicate release command, a release whose Complete was never
observed and multi-UE isolation.

The privileged case is the second one in `test/lte/handover_acceptance.cpp`. It
is a `doctest::skip()` case with no `ctest` entry, run by the privileged CI
job as its own invocation with its own log and its own sentinels,
`UNIRANSIM-PHASE18E-PRIVILEGED-EXECUTED` and
`UNIRANSIM-PHASE18E-PRIVILEGED-COMPLETE`. The job runs four invocations, one
per skipped case.


## 60. Phase 18-F-A: the live S1AP ingress

Every earlier section describes an isolated procedure. This one describes what a
real MME's messages meet when they arrive on a live association, and why the
answer is a refusal.

The gap was concrete. `EnbMultiplexer::handleS1ap` dispatched Initial Context
Setup, Downlink NAS, UE Context Release, E-RAB Setup/Modify/Release and Paging,
and answered everything else — including Handover Request, Handover Command and
Handover Preparation Failure — with `Unexpected S1AP procedure code`. A real
MME's first handover message would have produced a generic rejection and an
incremented `staleMessagesRejected` count, with nothing recording that a
handover had even been attempted.

`src/lte/enb/handover_live_ingress.{hpp,cpp}` now classifies the family, checks
what a target or a source may legitimately check, and refuses the message with a
typed reason. It is the same dispatcher, not a second one: the classification
happens after the ordinary procedures have not matched.

Nothing about the isolated path changed. The isolated coordinator still reaches
its target through `EnbMultiplexer::prepareHandover`, which the raw dispatcher
still does not call; the acceptance cases are untouched.

## 61. The ingress matrix

| Message | PDU category | Procedure | Stream | What the ingress does | Label |
|---|---|---|---|---|---|
| Handover Request | initiating | 1 | UE-associated | Decodes, validates type/container/E-RAB/security, assesses capabilities, sends a Handover Failure with `radioNetwork/6` when an identity is available | `RECOGNIZED_BUT_NOT_EXECUTABLE` |
| Handover Command | successful outcome | 0 | UE-associated | Decodes, matches the live source context and its own pending-handover record, refuses because no RRC container can be consumed | `RECOGNIZED_BUT_NOT_EXECUTABLE` |
| Handover Preparation Failure | unsuccessful outcome | 0 | UE-associated | Decodes, matches the context, changes nothing (there is no live transaction to cancel) | `RECOGNIZED_BUT_NOT_EXECUTABLE` |
| Handover Cancel | initiating | 4 | UE-associated | Recognised by procedure code; no codec exists and no response is invented | `REJECTED / UNSUPPORTED_PROCEDURE` |
| Handover Notify | initiating | 2 | — | Never accepted from the MME: it is the eNB's message. It does not classify and falls through to the unknown-procedure rejection | `REJECTED` by the ordinary path |
| Handover Required | initiating | 0 | — | eNB-to-MME; never accepted from the MME. Same fall-through | `REJECTED` by the ordinary path |

The streams are the ordinary UE-associated ones; a target that has not bound an
eNB-UE-S1AP-ID yet answers on `SctpStreamForUe(outbound, mmeUeS1apId)`.

A message that is not a handover message returns `NOT_A_HANDOVER_MESSAGE` and
the dispatcher's existing behaviour is unchanged.

## 62. The capability model

`AssessLiveHandoverCapabilities()` returns ten entries, each with the fact it
rests on. Three are true because the code and its tests exist; six are false
because the code they would need does not; the tenth is derived.

| Capability | Value | Evidence |
|---|---|---|
| `ISOLATED_SIMULATOR_READY` | true | the 18-D and 18-E acceptance cases |
| `S1AP_CODEC_READY` | true | the byte-pinned, tshark-checked codecs |
| `S1AP_RUNTIME_INGRESS_READY` | true | this phase's ingress and its `lte/handover/live` cases |
| `SOURCE_PROVENANCE_READY` | false | no standards-compliant source identity reaches a target |
| `TARGET_CONTEXT_READY` | false | a provisional context needs a `SourceSession` from the source's registry |
| `RRC_CONTAINER_READY` | false | no TS 36.331 codec exists |
| `HANDOVER_SECURITY_READY` | false | the UE has KASME and NAS keys only |
| `UE_RADIO_EXECUTION_READY` | false | the UE executes a simulator frame, not an RRC reconfiguration |
| `MME_PATH_UPDATE_OBSERVABLE` | false | the eNB cannot see the SGW's map |
| `LIVE_HANDOVER_EXECUTION_READY` | false | derived: the conjunction of the nine above |

There is no switch. Nothing in the configuration, the command line or an S1AP
message sets one of these values: the assessment is computed on every call from
the state of this build.

## 63. Real-MME identity provenance

The isolated coordinator's `SourceSession` comes from `ExtractSourceSession`,
which reads one live source-registry entry. A target eNB has no such entry for
the source, and TS 36.413 gives a Handover Request no source-eNB field: the
message names the target (by being addressed to it) and carries an opaque
container whose RRC content names a physical cell and a C-RNTI, not an eNB
identity.

So the live target has three options, and this repository takes the third:

1. infer a source from the MME's SCTP peer, the TAC, a PLMN match or a bearer
   identity — every one of which the accepted contract forbids;
2. trust whatever an opaque container appears to say — which is not verification;
3. record `SOURCE_PROVENANCE_NOT_ESTABLISHED` and refuse.

The consequence is that a live Handover Request is refused before any target
resource exists, and no promotion or Notify can follow from one. A future phase
that wants to accept a live request has to define an ownership contract that
does not exist in S1AP today, and it has to be explicit about its trust
assumption rather than borrowing the isolated one.

## 64. RRC container requirements

TS 36.413 makes both handover containers opaque OCTET STRINGs "coded according
to the specifications of the target system", and TS 36.331 says what that coding
is:

* **Source-ToTarget** carries `SourceeNB-ToTargeteNB-TransparentContainer`,
  whose `rRC-Container` is a `HandoverPreparationInformation` message: the UE's
  `AS-Config` (source radio resource configuration, security algorithm, UE
  capability), `sourcePhysCellId`, `sourceUeIdentity`, and the mobility state.
* **Target-ToSource** carries `TargeteNB-ToSourceeNB-TransparentContainer`,
  whose `rRC-Container` is an `RRCConnectionReconfiguration` containing
  `mobilityControlInfo`: target physical cell identity, carrier frequency,
  `t304`, the new `radioResourceConfigCommon` and `radioResourceConfigDedicated`,
  and the security configuration derived from the NCC/NH the MME sent.

This build has neither. `src/asn/rrc` is NR RRC (38.331), there is no TS 36.331
module, and the only handover container the simulator produces is the labelled
`SIM-HOv1` frame. tshark demonstrates the difference: dissecting the Phase 18-A
request fixture, it decodes the container as
`SourceeNB-ToTargeteNB-TransparentContainer` and reports the inner bytes as
`Malformed` — which is exactly what a real target eNB or a real UE would do with
a simulator container.

| Container | Format implemented | Standards-compatible | Independently decoded | Populated from trustworthy state | Consumable by the UE |
|---|---|---|---|---|---|
| Source-ToTarget | no | no | no | no | no |
| Target-ToSource | no | no | no | no | no |

Carrying a container byte-for-byte is not generating one. The ingress validates
only its presence and its size bound, and never its contents.

## 65. Security provenance

The MME derives the handover security material itself: it increments its NCC and
recomputes `NH = KDF(KASME, NH)` before sending the request, then sends
`nextHopChainingCount` and a 32-octet `nextHopParameter` plus the UE's algorithm
bitmaps.

`lte::ue::SecurityContext` holds KASME, CK, IK, KNasInt and KNasEnc — the NAS
keys. There is no KeNB, no NH, no KRRCint/KRRCenc/KUPenc, and no RRC to protect.
The `nextHopParameter` therefore reaches the eNB and stops there: it is carried,
never applied. A request whose NH is all zero, or whose algorithm bitmaps state
no algorithm, is refused as `SECURITY_CONTEXT_INVALID` — the opposite of
accepting a zero-filled key as a success.

`HANDOVER_SECURITY_READY` is false, and no test in this repository may make it
true by supplying fixture keys.

## 66. What a live deployment would still need

In the order the ingress refuses them:

1. a source-ownership contract for the target, with a stated trust assumption;
2. a provisional target context that can exist before a `SourceSession` does;
3. an LTE RRC codec for both containers, and a UE that can execute the
   reconfiguration it carries;
4. TS 33.401 AS key derivation and RRC/UP security in the UE runtime;
5. a way for the eNB to obtain evidence that the core moved the downlink path —
   which is the core's own state, not the eNB's;
6. a fresh, separately scoped authorization for any live experiment.

Until then `LIVE_S1_HANDOVER_EXECUTION_READY` is false, a live handover message
is refused with a typed reason, and the isolated path remains the only one that
executes.


## 67. Phase 18-F-B1: the LTE RRC codec

The containers Phase 18-D and 18-E carried as opaque bytes now have a standards
codec behind them. `src/lte/rrc/rrc_handover.{hpp,cpp}` encodes and decodes
`HandoverPreparationInformation` and the RRC `HandoverCommand` wrapping an
`RRCConnectionReconfiguration` with `mobilityControlInfo`, using the
asn1c-generated types in `src/asn/lte-rrc` and UPER.

The pinned module is TS 36.331 V15.6.0 (`tools/lte-rrc-15.6.0.asn1`,
SHA-256 `9f85c0ef…4a94`), the newest release the available asn1c 0.9.29 parses.
Release 16 fails to compile: its extension-addition groups appear inside a
CHOICE, which asn1c's grammar does not admit. The full record, including the
generation command and the licensing position, is
`docs/lte-rrc-handover-codec.md`.

### 67.1 The two layers that were one layer

The S1AP IE is an OCTET STRING, but its contents are a 36.413 SEQUENCE whose
first field is the RRC message. Phase 18-F-B1 implements the RRC layer and
proves, by dissection, that the outer 36.413 wrapper is still missing:

```
S1AP Source-ToTarget-TransparentContainer (OCTET STRING)
  └── SourceeNB-ToTargeteNB-TransparentContainer   (36.413 SEQUENCE)  ← missing
        └── rRC-Container (OCTET STRING)
              └── HandoverPreparationInformation   (36.331, UPER)      ← implemented
```

Wrapping the codec's octets in a real S1AP Handover Required and dissecting the
frame, tshark reads the container as the 36.413 SEQUENCE, takes a nonsense
`rRC-Container` from the first length octet and reports the rest as
`Malformed`. The isolated simulator is unaffected — its container is
`SIM-HOv1`, which is its own format and never leaves the simulator.

### 67.2 What the codec does and does not carry

Implemented: the UE capability list; AS-Config with security algorithms, C-RNTI,
MIB, SIB1, SIB2, antenna ports and DL carrier frequency; `mobilityControlInfo`
with the target PCI, t304, the new C-RNTI and the mandatory members of
`radioResourceConfigCommon`.

Not modelled, and omitted or encoded as legal empty structures:
`sourceMeasConfig`, `sourceRadioResourceConfig`, the optional members of
MIB/SIB1/SIB2 and of `radioResourceConfigCommon`, `carrierFreq`,
`carrierBandwidth`, `additionalSpectrumEmission`, `rach-ConfigDedicated`, and
the measurement, dedicated-radio and security-handover IEs of the
reconfiguration.

### 67.3 Readiness is still a statement about execution

The codec does not move a UE. `RRC_CONTAINER_READY` stays false in the live
capability model because the container that carries these octets is still not
produced; `HANDOVER_SECURITY_READY` and `UE_RADIO_EXECUTION_READY` stay false
because no AS keys and no RRC execution exist. The live verdict remains
`LIVE_S1_HANDOVER_NO_GO`.

### 67.4 What the next phase must add

1. the two 36.413 container SEQUENCEs, with real `uE-HistoryInformation` and
   `targetCell-ID` from the source — the target container is the smaller of the
   two and could come first;
2. the remaining AS-Config members, so a source can state its real measurement
   and dedicated radio configuration;
3. AS security (KeNB/NH derivation, RRC/UP keys) before any container is
   presented as executable.


## 68. Phase 18-F-B2: the transparent container

Section 67.1 recorded that the repository produced the `rRC-Container` payload
and not the 36.413 SEQUENCE around it. That is now closed:
`src/lte/enb/transparent_container.{hpp,cpp}` encodes and decodes both
`SourceeNB-ToTargeteNB-TransparentContainer` and
`TargeteNB-ToSourceeNB-TransparentContainer`, and the four S1AP handover
messages carry them as opaque OCTET STRINGs exactly as before.

### 68.1 The three layers, verified independently

```
LTE RRC message            UPER   rrc_handover.cpp
transparent container      APER   transparent_container.cpp
S1AP message               APER   codec.cpp
```

tshark 4.2.2 dissects a generated Handover Required and finds the container
SEQUENCE, its `rRC-Container`, the `HandoverPreparationInformation` inside it,
`targetCell-ID`, `subscriberProfileIDforRFP` and both UE history entries with
their cell sizes and stay times. A generated Handover Command dissects
end to end down to `mobilityControlInfo`'s `targetPhysCellId: 42`,
`t304: ms150` and `newUE-Identity: 1234`.

### 68.2 Target-cell and UE-history provenance

The container's typed model carries provenance for both mandatory fields. A
target EUTRAN-CGI states whether it came from a fixture, a verified simulator
cell or a running target cell; a UE history entry states whether the runtime
recorded it, it is fixture data, it is stale or the preceding cells are
unknown. Nothing here is inferred from a TAC, a PLMN, a UDP address or a TEID,
and no history is invented: a source container with missing history is refused.

### 68.3 What is still not modelled

`e-RABInformationList` and `iE-Extensions` are refused when supplied rather than
silently dropped. The AS-Config assessment names the remaining model gaps; a
syntactically valid message with legal empty optional structures is not a
complete runtime handover configuration.

### 68.4 A B1 defect, found by dissection

TS 36.331 defines `handoverCommandMessage` as `OCTET STRING (CONTAINING
DL-DCCH-Message)`. B1 stored the bare `RRCConnectionReconfiguration` there. The
historical codec and its pinned vectors are preserved; the conformant payload
(`EncodeHandoverCommandPayload`) is what the container carries, and the
dissection above is the evidence.

### 68.5 Live readiness

Unchanged: `LIVE_S1_HANDOVER_NO_GO`. A complete container is not proof that a
UE can perform a handover; `HANDOVER_SECURITY_READY` and
`UE_RADIO_EXECUTION_READY` remain false, and the live ingress still fails
closed on every handover message.

## 69. Phase 18-F-B3: runtime provenance

Section 68.3 recorded the remaining model gaps. The runtime now supplies the
handover inputs from state it owns: the UE's serving-cell history is recorded
from real serving-cell transitions on a monotonic clock, the target CGI comes
from the authorized simulator inventory with its generation, and a source
snapshot can only be assembled from live runtime components. See
`docs/lte-handover-runtime-provenance.md`.

Two corrections came with it. Decoded wire data is no longer labelled fixture
data: it is `WIRE_UNVERIFIED` until a runtime authority raises it. And the
capability model now separates what is implemented (RRC UPER codec, transparent
containers, simulator runtime inputs) from what is not (AS-Config completeness,
source provenance at the target, AS security, UE RRC execution), with core-path
evidence reported as external acceptance evidence rather than an eNB execution
prerequisite. `liveExecutionReady()` remains false and the live ingress remains
fail-closed.

A synthetic but structurally valid `UE-EUTRA-Capability` is now carried in a
`HandoverPreparationInformation`, wrapped in the complete container and
embedded in an S1AP Handover Required; Wireshark dissects every nested layer
with zero malformation. It is labelled synthetic: no capability in it is a real
UE measurement.
