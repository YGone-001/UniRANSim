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

What the repository cannot do today: move a UE between two eNBs. There is no
handover procedure state machine, no target-side bearer establishment, no
source-side release after Handover Notify, no data forwarding path and no
user-plane switchover. §2 and §14 say exactly where the boundary is.

## 2. Missing implementation areas

The following are deliberately absent. Each is a real gap, not an implicit
behaviour.

* **No procedure driver.** The codecs and the admission evaluator are pure
  functions and a pure evaluation. Nothing orders a Handover Required, waits
  for a Handover Command, or starts a Handover Request on a target. There is no
  state machine, and Phase 18-A deliberately did not add one.
* **No target-side bearer establishment.** `EvaluateHandoverAdmission` plans.
  It allocates no S1-U transport, binds no TEID, opens no session and touches no
  `UeRegistry`. The only path to a `HandoverRequestAcknowledge` is
  `BuildHandoverRequestAcknowledge`, which requires a separate
  `CommittedTransport` set that no code in this phase produces.
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

What the handover foundation adds is only a *plan* for transport:

* `AdmittedBearer::targetTransport.address` is the target's own S1-U address.
* `AdmittedBearer::targetTransport.teid` is zero and `bound` is false until a
  commit step this phase does not implement says otherwise.
* `BuildHandoverRequestAcknowledge` takes that commit output as an explicit
  `std::vector<CommittedTransport>` and refuses to invent an address or a TEID.
  It refuses when the committed set does not cover the admitted bearers, when a
  committed TEID is zero, and when a committed endpoint is not on the target's
  own S1-U address.

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
**None is implemented, and none is claimed operational.**

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

Behaviour 10 is the one this phase *does* implement, in the narrow sense that
`EvaluateHandoverAdmission` is all-or-nothing: a single unclassifiable,
mismatched or unlinked E-RAB refuses the whole set and the `HandoverAdmission`
holds no bearers at all.

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
| Handover procedure state machine | **Deferred** |
| Target-side bearer establishment | **Deferred** |
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

The next stage is the one this phase deliberately did not start: a target-side
establishment that turns an admitted plan into committed transport.

1. **Commit step.** A `CommitHandoverResources` that takes a
   `HandoverAdmission` and produces the `std::vector<CommittedTransport>`
   `BuildHandoverRequestAcknowledge` already consumes — allocating local S1-U
   TEIDs from `UeRegistry::allocateLocalTeid`, binding them, and refusing
   partial commitment. Admission and commitment stay separate.
2. **Target session creation.** Create the target-side UE entry only once the
   commit succeeded, and only for the UEs that arrived, not for the UEs that
   were merely planned.
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

Until step 1 exists, no test and no report may describe a handover as having
happened. A codec that can represent Handover Notify is not a handover, and an
admission that binds nothing is not a target.
