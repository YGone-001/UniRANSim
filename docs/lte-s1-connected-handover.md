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

Nothing in this slice runs in a live or a simulated eNB procedure. Specifically
not implemented, and not claimed:

* no S1AP dispatcher integration: no Handover Request is received by a running
  eNB, and no acknowledge or failure is transmitted;
* no Handover Notify, and no recognition of a UE arriving at the target —
  `TARGET_PREPARED` and `AWAITING_UE_TARGET_ACCESS` are the end of this slice;
* no promotion of a provisional context into a reached UE session;
* no source context release, no source TEID retirement, no bearer path update;
* no data forwarding, direct or indirect, and no GTP-U End Marker behaviour;
* no RRC handover command, no Target-ToSource container of the target's own,
  and no security key derivation;
* no X2 handover, no Path Switch Request, no inter-RAT or inter-MME handover;
* no live Open5GS handover and no PCC policy change.

Prepared target transport is not completed handover. Do not claim otherwise.

## 28. Phase 18-C prerequisites

The remaining steps of section 15 are the prerequisites of a later phase, and
this slice deliberately leaves each of them open:

1. **Arrival.** A documented contract for recognising a UE at the target, and
   the promotion of a provisional context into a reached one through
   `registerPeer` and `activateUe` on a real verified peer. Until then nothing
   may call `activateUe` on a prepared bearer.
2. **Handover Notify.** Verify the named CGI and TAI against the target's own
   identity before anything else moves.
3. **Source release.** Release the source context and retire its local S1-U
   TEIDs only after a Handover Notify for that UE.
4. **Bearer path update.** The MME-controlled update, which is the point of the
   S1 family and must not be replaced by a Path Switch Request.
5. **Data forwarding.** Only after the above, and with a defined forwarding
   model.

A handover is still not an Attach and not an idle-mode Service Request, and
none of these prerequisites may be reached by substituting one.
