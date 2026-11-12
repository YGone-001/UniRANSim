# AGENTS.md

Development and safety requirements for working in this repository. It records
only what the repository itself establishes: the build and test entry points,
what must never be committed, the commit style used on `develop`, the GTP-U
message-handling rules the eNB receive path must keep, and the constraints that
apply when the LTE path is driven against a live EPC.

## Layout

| Path | Contents |
|---|---|
| `src/` | NR and LTE simulator sources (`src/lte/` is the LTE path) |
| `test/` | doctest suites, driven through `ctest` |
| `config/` | example configurations; `*.local.yaml` are private and git-ignored |
| `docs/` | design records for the LTE slices |
| `tools/` | fixture generators and protocol references |
| `.github/workflows/test.yml` | the five-job CI matrix |

`docs/lte-performance-scalability-roadmap.md` tracks the deferred performance
milestones. It is a roadmap, not a task list: its milestones stay
`DEFERRED — NOT IMPLEMENTED — NOT BENCHMARKED` until they are deliberately
taken on, and it is otherwise left alone.

`docs/gtpu-end-marker-retired-tunnel-lifecycle.md` is the design record for the
eNB GTP-U receive path: message types, End Marker rules, tunnel lifecycle and
TEID reuse protection.

## Build and test

```bash
make build          # Release build; copies the run binaries into build/
make test           # Release build of the test binary, then ctest
```

`make build` clears `build/` first and reconfigures `cmake-build-release`. The
test binary is `cmake-build-release/nr-tests`; it accepts doctest filters:

```bash
./cmake-build-release/nr-tests --no-version --test-case="lte/paging/wait:*"
```

The CI matrix is the acceptance bar. A change is not done until all five jobs
pass on the exact pushed commit:

1. Build and test (GCC).
2. Build and test (Clang).
3. Test (ASan + UBSan).
4. Coverage.
5. Privileged LTE Mobility TUN Integration.

The local equivalents are a Release build per compiler, a Debug build with
`-DUERANSIM_SANITIZE=address,undefined`, a Debug build with
`-DUERANSIM_COVERAGE=ON`, and the privileged cases run under `unshare --net`
with `UNIRANSIM_RUN_PRIVILEGED_TUN_TESTS=1`. On a machine where the sanitizer
build faults on `vm.mmap_rnd_bits`, that sysctl step can be skipped locally; CI
sets it.

A `doctest::skip()` case has no `ctest` entry at all, so the ordinary suite
cannot run it. That is what makes a privileged case safe to keep in the tree.
The privileged job runs **one invocation per skipped case**, each with its own
log and its own execution and completion sentinels, so one case's pass cannot
be mistaken for another's. A skipped case is never a pass: if its sentinels are
absent the run failed, whatever the exit code says. Each privileged case is run
as `nr-tests --no-skip --test-case="<exact title>"` inside a private network
namespace that has a real `/dev/net/tun` and root capability.

## Testing rules

- Do not assert on a `LogCapture` while it is still capturing: a failed
  assertion prints into the captured buffer and becomes invisible. Record
  observations, `finish()` the capture, then assert.
- A test that ends a production run must use the run's own clean shutdown. A
  run that exits through a failure path prints no statistics block, so a
  missing statistics line is not evidence of anything.
- Tests may not close a requirement with a hand-built success state that skips
  the production transition under test.
- A positive Paging test must build a valid S1AP Paging PDU and deliver it
  through the eNB's actual S1AP dispatcher on the non-UE-associated SCTP
  stream zero, so the real fan-out runs and each UE matches its own S-TMSI.
  Do not close a positive Paging requirement by injecting a
  `PAGING_INDICATION` straight into the UE.
- A retransmission of an outstanding Service Request is not another Paging
  round. Count restorations by the access epochs that actually completed, not
  by the number of answers the UE produced.
- A restoration is only proven by independent user-plane traffic on **every**
  bearer it claims to restore. For a default and a dedicated bearer that is
  two flows, and the dedicated flow must travel the dedicated bearer's TEID.
  A control-plane-only pass is not a restoration pass, and a loopback packet
  that never left a socket pair is not user-plane evidence.

## GTP-U message handling

The eNB S1-U receive path is `S1uEndpoint::handleDatagram`, and its dispatch is
a safety boundary. These rules are what a change must not weaken.

- `gtpu::Decode` accepts exactly four message types: Echo Request (1), Echo
  Response (2), End Marker (254) and G-PDU (255). Anything else is rejected at
  decode. Do not widen the whitelist without a rule for the new type in the
  dispatch switch below.
- The dispatch switch sends Echo Request to `handleEchoRequest`, End Marker to
  `handleEndMarker`, and **only** G-PDU to `handleGPdu`. A G-PDU is the only
  message type that may reach the UE link, the frame encoders or the user-plane
  packet counters. Do not let a control message fall through into forwarding.
- An End Marker carries the TEID of the tunnel whose payload stream is ending.
  It is not a release, not a bearer transition and not a handover
  authorisation: handling one must never release a bearer, advance an access
  generation, or start any procedure. It is recorded and nothing else moves.
  No eNB code path generates or transmits an End Marker. The only producer in
  this repository is the isolated SGW simulator, which builds one in
  `handover_core_path.cpp` and sends it to the old source endpoint and nowhere
  else; that is core-side traffic, not an eNB behaviour, and it stays confined
  to the isolated simulator.
- The S flag of an End Marker must be clear (TS 29.281 V14.0.0 §5.1). An End
  Marker with the S flag set is refused at decode, and there is no runtime
  switch that relaxes it.
- TEID rules differ per message type and must stay that way. A G-PDU needs a
  non-zero TEID and a non-empty payload and may contain no information element.
  An End Marker needs a non-zero TEID and, beyond an empty information-element
  area, only well-formed Private Extension information elements. Echo carries a
  zero TEID. Reject rather than guess at anything else.
- A Private Extension is Type `0xFF`, a **16-bit** Length, a **16-bit**
  Extension Identifier and the Extension Value (TS 29.281 figure 8.6-1).
  Length excludes the Type and Length fields, so it counts the Extension
  Identifier and the whole Extension Value: `Length >= 2` and the element
  occupies `3 + Length` octets. The Extension Identifier is an IANA Private
  Enterprise Number and is never interpreted. Do not let a one-octet-length
  reading back into the parser: it accepts `FF 02 AA BB`, which the
  specification rejects as truncated.
- A local S1-U TEID is active (in `UeRegistry::m_byLocalTeid`), retired (in the
  `RetiredTeidLedger`), or unknown. Every path that releases a live tunnel goes
  through `UeRegistry::retireLocalTeid`, so an identifier cannot stop resolving
  without also becoming identifiable as retired. The one exception is the
  rollback of an establishment that never bound anything, where
  `unbindLocalTeid` drops the reservation and retires nothing — no tunnel ever
  existed to retire.
- Uniqueness of a local S1-U TEID comes from the allocator alone, never from
  the retirement record. `allocateLocalTeid` reserves a value and `bindLocalTeid`
  accepts only a reserved one, so no caller can attach an identifier of its own
  choosing. The allocator is monotonic over a bounded issuance window, never
  reissues a value, and fails closed with `TeidExhausted` rather than rolling
  over. The guarantee is process-lifetime only; nothing is persisted.
- `UeRegistry::allocateLocalTeid` must keep refusing an identifier that is zero,
  live, or still recorded as retired, and `bindLocalTeid` must keep refusing one
  that is not reserved, or is still retired. There is no revival: nothing
  withdraws a retirement record. The retired-TEID record is bounded and holds
  only the identifier and its retirement order — no UE identity, peer address
  or subscriber information — and is an observation aid, not an allocation
  guarantee. An identifier whose record has aged out is still unusable: it is
  not reserved, and the allocator has already spent its step.
- A G-PDU whose TEID does not resolve is dropped and classified: retired TEID
  is traffic that outlived its tunnel, unknown TEID is a packet that never had
  one. Neither may create or disturb any bearer or UE state.
- That classification is observable at runtime. `retiredTeidDrops` is a
  **process-lifetime endpoint-level** counter of the shared S1-U endpoint, not
  a per-UE forwarding counter, and it is reported on two surfaces that read the
  same field: the cumulative value is appended to the retired-drop warning as
  `retired-total=N`, and the aggregate is appended to the shared shutdown line
  as `drops(retired-teid)=N`. Unknown, malformed, evicted-tombstone and
  unexpected-peer cases must stay distinguishable from it and from each other,
  and none may borrow another's count. The warning prefix and the pre-existing
  shutdown fields are fixed compatibility surface: append to them, never
  rewrite them, because CI and historical diagnostics match on them.
  A cumulative log value alone is **not** proof that a specific packet reached
  the real S1-U receiver. Establishing that needs a separately authorized probe
  and matching capture evidence; deterministic or logged evidence is not a live
  rejection result.
- Peer identity is validated per bearer against `sgwAddress:2152` before
  anything else happens, for control messages as well as for G-PDUs. Do not
  move that check after a state change.

The detail, including the genuine wire vector the tests are anchored on and the
known limitation that an End Marker does not drain an active tunnel, is in
`docs/gtpu-end-marker-retired-tunnel-lifecycle.md`. The cases live in
`test/lte/gtpu_end_marker.cpp` and drive `handleDatagram` against loopback UDP
endpoints:

```bash
./cmake-build-release/nr-tests --no-version --test-case="lte/gtpu/*,lte/enb/retired-teid*"
```

## Dedicated bearer restoration

A dedicated EPS bearer that the network created is logical state that outlives
the access that carried it. The rules below are what a change must not weaken
when that bearer is restored on a later access.

- Bearer identities are decoded from the network's own signalling. Do not
  assume EBI 5 or EBI 6 in production acceptance logic, and do not infer
  default-versus-dedicated roles from QCI or from the order the E-RABs are
  listed in. An E-RAB list that is deliberately reordered must still produce
  the same roles.
- A dedicated bearer keeps the network-assigned EBI, its linked default EBI,
  its QoS, its EPS session identity and the **non-empty TFT** it was given
  through protected NAS signalling, across every access release and every
  later restoration. The uplink flow that reaches a dedicated bearer is
  selected by matching the packet against the retained TFT, never by QCI and
  never by bearer ordering.
- Readiness is ordered. The default bearer is established first whatever order
  the E-RABs arrive in, and a dedicated bearer's access is restored only after
  the default it is linked to is ready. `BearerRuntime::restoreAccess` is
  deliberately TUN-gated: without a real TUN the restoration is refused and
  the message is dropped. Do not relax that gate in production to make a
  control-plane test pass.
- The radio answer form comes from `MobilityContext::accessBootstrap` — that
  is, from **confirmed** bearer-role ownership — never from
  `accessGeneration`. A cell that has never confirmed the roles needs the
  bearer inventory; a cell that has does not, whatever its generation number
  is. `onAttachComplete` deliberately does not mark the roles retained, and a
  Tracking Area Update that establishes no bearer must leave the declaration
  outstanding for the next restoration.
- Local S1-U TEIDs are a fresh pair on every restoration. The previous pair
  must stop resolving, a delayed G-PDU for an old TEID must not reach the new
  tunnel, and an old End Marker must not release or modify the new bearer.
  Bearer packet counters accumulate across access restorations by design, so
  a fresh TEID must not be credited with traffic it never carried.
- Multi-round restorations after one EPS registration must not re-Attach. The
  first restoration at a cell that has not confirmed the roles declares the
  retained inventory; the later ones at that same cell use the compact Service
  Request.

### Dedicated bearer QoS identity

A bearer's QoS is part of the identity that survives a restoration, and the two
places the network states it must not disagree.

- The NAS EPS quality of service (TS 24.301 §9.9.4.3) is what the UE is sent:
  QCI and, for an extended form, bitrates. It carries **no ARP**. ARP priority
  level and the pre-emption capability and vulnerability live in the S1AP E-RAB
  Level QoS Parameters (TS 36.413 §9.2.1.15) and stay there. Do not add ARP to
  the EPS QoS sent to the UE and do not drop it from the E-RAB to make the two
  look alike.
- GBR and MBR belong to GBR QoS Information (TS 36.413 §9.2.1.18) and are
  present for a GBR bearer only. A non-GBR QCI must not be given fabricated GBR
  values, and this project does not implement full GBR bearer support; do not
  claim otherwise.
- For the same EBI, the NAS activation and the S1AP E-RAB that establishes or
  restores it name the **same QCI**. QCI remapping is not universally
  impossible — roaming and inter-RAT handover can legitimately produce a
  different value — but a remapping claim needs explicit signalling or
  configuration evidence. Absent that, for a same-PLMN scripted restoration,
  do not invent a remapping to excuse a mismatch.
- Test fixtures state the QCI explicitly, per bearer, and never through a
  hidden default. `ActivateDedicated` takes the QCI as an argument and a
  scripted activation list carries one (EBI, QCI) pair per bearer, so a case
  with two dedicated bearers plays two QCIs and they cannot blur together.
- A fixture that is backed by a capture must say exactly what was captured. A
  captured TFT value field is not a captured NAS message: the enclosing
  activation is constructed in the test, and so is the S1AP E-RAB. Record which
  is which, and never claim a packet capture or byte-for-byte capture
  equivalence that does not exist.

The detail, including the generation arithmetic, the measured per-round
transport and the QoS consistency evidence, is in
`docs/lte-dedicated-bearer-paging-restoration.md`.

## S1AP handover message handling

The S1-based connected-mode handover foundation is the codecs in
`src/lte/enb/codec.{hpp,cpp}` and the pure admission evaluation in
`src/lte/enb/handover_admission.{hpp,cpp}`. These rules are what a change must
not weaken.

- The supported family is S1-based handover only: Handover Required, Handover
  Request, Handover Request Acknowledge, Handover Command, Handover Notify, and
  the two failure representations Handover Preparation Failure and Handover
  Failure. A Path Switch Request is X2-based and must not stand in for
  Handover Notify or for the MME-controlled bearer path update. There is no
  Path Switch Request in this repository and none may be added as a shortcut.
- Procedure codes and information-element identifiers come from TS 36.413.
  Do not invent one. The S1AP PDU category, the procedure code and the
  procedure criticality are read back from the raw envelope bytes in the tests;
  a change that silently moves Handover Notification to *reject* or Handover
  Preparation to *ignore* is a wire change and must show as one.
- An opaque handover container is preserved byte for byte and is never parsed
  for RRC or security content. An opaque container is not authority to invent
  security or RRC fields. An empty container and one past
  `MaxTransparentContainerSize` are refused whole; an oversized container is
  never truncated to the bound and accepted.
- The handover security material — `nextHopChainingCount` and the
  `nextHopParameter` — is carried from signalling, never generated, defaulted,
  derived or logged. A Handover Request with no `UESecurityCapabilities` is
  refused rather than accepted with a guessed algorithm set. Never fabricate
  UE security keys.
- `HandoverType` is `intralte` and nothing else. An inter-RAT value is refused
  at decode and at encode, and a secondary transparent container is refused in
  an intra-LTE handover.
- A Handover Request carries no TargetID: the target is the recipient. The only
  message in this family that names a target is Handover Required, and the only
  named-target check is `CheckNamedTarget`. Do not add a target field to
  Handover Request and do not compare a request against a target identity it
  does not carry.
- A target eNB identity is coherent only when its Global-ENB-ID PLMN and its
  selected-TAI PLMN agree. An identity naming two networks is refused as an
  invalid context identity.
- Bearer identity is decoded from the network's own statement of the EPS
  session. Do not assign default-versus-dedicated roles from QCI, and do not
  infer them from the order the E-RABs are listed in. An E-RAB list that is
  deliberately reordered must still produce the same roles and the same
  default-first readiness order.
- Admission and commitment stay separate. `EvaluateHandoverAdmission` is a pure
  evaluation that allocates nothing: a decoded but unadmitted Handover Request
  must not allocate an S1-U tunnel, bind a TEID, open a session, forward a
  G-PDU, retire a source TEID or release an existing bearer. The only path to a
  Handover Request Acknowledge is `BuildHandoverRequestAcknowledge`, which takes
  an explicit `CommittedTransport` set and refuses to invent an address or a
  TEID.
- Admission is all-or-nothing across the bearer set. A target that cannot admit
  every E-RAB admits none and reports a Handover Failure with a standard cause.
  Do not implement a partial admission.
- Local S1-U TEIDs stay a fresh pair on every access, and any future handover
  keeps that: a previous pair must stop resolving, a delayed G-PDU for an old
  TEID must not reach a new tunnel, and an old End Marker must not release or
  modify a new bearer. Bearer packet counters accumulate across access
  restorations by design, so a fresh TEID must not be credited with traffic it
  never carried.
- A handover is not an Attach and not an idle-mode Service Request. Do not
  replace one with the other to reach a target, and do not mutate an unrelated
  UE's session.

The detail, including the normative references, the S1-based versus X2-based
distinction, the documented (not implemented) connected-mode lifecycle with
`TARGET_CONNECTED`, the ten failure and rollback behaviours and which of them
the preparation slice now implements, the transparent container and security
boundaries and the evidence categories, is in
`docs/lte-s1-connected-handover.md`. The cases live in
`test/lte/handover_s1.cpp` and drive the codecs and the admission evaluator
against offline fixtures:

```bash
./cmake-build-release/nr-tests --no-version --test-case="lte/handover/*"
```

## Handover preparation and target resource commitment

The target-side preparation slice is
`src/lte/enb/handover_preparation.{hpp,cpp}` together with the provisional
target contexts in `src/lte/enb/ue_registry.{hpp,cpp}`. It is the bridge
between `EvaluateHandoverAdmission` and `BuildHandoverRequestAcknowledge`.
These rules are what a change must not weaken.

- Admission allocates nothing. `EvaluateHandoverAdmission` still reserves no
  TEID, creates no registry entry and binds no S1AP identifier, and a plan that
  cannot be committed whole is refused before anything is allocated: the commit
  validates the complete bearer set first and only then reserves the first
  identifier.
- Commitment owns actual target resources. `CommitHandoverResources` takes its
  local S1-U TEIDs from `UeRegistry::allocateLocalTeid`, binds them with
  `bindLocalTeid`, and builds real bearer contexts through `establish` and
  `addDedicatedBearer`. A committed result is never a list of fabricated
  identifiers, and a partial multi-bearer commitment is never reported as a
  success: either every admitted E-RAB is reserved, prepared and bound, or the
  whole attempt is rolled back and the refusal names the cause.
- Target preparation is not UE arrival. A prepared context is provisional: it
  comes from `UeRegistry::allocateProvisional`, it has `radioUeId == 0` — a
  value `registerPeer` refuses — and it is absent from the radio-identity and
  peer indexes. Do not invent a radio peer, a UE session or a TUN attachment to
  make a commit look like an arrival.
- A prepared bearer cannot forward prematurely. A bearer established for a
  prepared context is not made UE-ready, so `active()` is false. A G-PDU whose
  TEID resolves to such a bearer is dropped as `bearerInactiveDrops` at that
  entry: not as an unknown TEID, not as a retired TEID, not as a malformed
  packet, and never to the UE link or the user-plane packet counters.
- Rollback never leaves a live mapping. A TEID that was actually bound is
  released through `unbindLocalTeid`, so it becomes identifiable as retired
  through the normal lifecycle. A TEID that was only reserved has its
  reservation dropped and is not retired, because no tunnel ever existed to
  retire. Nothing withdraws a retirement record, and nothing rewinds the
  allocator to simulate a rollback.
- Allocator advancement is not automatically a leak. A rollback that cannot
  complete is surfaced as `CLEANUP_FAILED` with `outstandingTeids` — the whole
  reserved set, the bound identifiers and the reserved-only one — and the
  record keeps that set so a later cancellation can try again. Those
  identifiers stay spent; a retry must never reissue one, and a retry that
  cannot see one would leak it.
- Source state remains intact during a failed preparation. Preparing at a
  target touches the target's registry alone. The source's contexts, its local
  TEIDs, its bearer identities, its access generation and its session state do
  not move, and no source TEID is retired.
- Source eNB identity cannot be inferred from the target's MME-facing SCTP
  association, from the UE's TAC, from a matching EBI or TEID, or by parsing
  the opaque RRC container. A preparation that needs a source identity it
  cannot establish from a documented contract is refused, not guessed.
- Duplicate and stale transaction handling is mandatory. A repeat of the same
  request under the same identity is one transaction and allocates nothing a
  second time, whatever state the record has reached. A repeat that disagrees
  with a live preparation is a conflicting duplicate and is refused. A request
  under a stale association epoch is refused before it can touch anything.
- A committed preparation is not a handover. `TARGET_PREPARED` means the target
  owns prepared transport for a UE that has not arrived. Nothing in this slice
  sends a Handover Notify, updates a bearer path, forwards user-plane data,
  releases a source context or drives an RRC reconfiguration. Do not report a
  prepared target as a completed handover.

The detail, including the commit algorithm, the transaction identity and the
prepared-state forwarding restriction, is in
`docs/lte-s1-connected-handover.md`. The cases live in
`test/lte/handover_preparation.cpp` and drive the commit and the preparation
owner against real registry resources:

```bash
./cmake-build-release/nr-tests --no-version --test-case="lte/handover/preparation:*"
```

## Verified target arrival and the Handover Notify gate

A prepared target is a UE that has not arrived. The rules below are what a
change must not weaken when one does.

- Verified arrival is required before promotion. A provisional context becomes
  a reached UE only through `HandoverPreparationOwner::acceptArrival`, driven by
  a handover-specific simulated radio frame that reached
  `EnbMultiplexer::handleRadioFrame`. A decoded Handover Request, a successful
  admission, a committed resource set, a built acknowledge, a datagram on the
  target's UDP socket or a numeric identity a caller supplied are each
  insufficient on their own. Do not substitute a test-only `arrived=true` flag
  for arrival evidence.
- Prepared resources alone do not prove arrival. `TARGET_PREPARED` and
  `RESOURCES_COMMITTED_PREPARED` say the target owns transport for a UE that has
  not arrived. A prepared bearer is established and not `active()`, and the
  shared S1-U endpoint drops its G-PDUs as `bearerInactiveDrops` — not as an
  unknown TEID, not as a retired one and never to the UE link.
- Provisional promotion preserves TEIDs and S1AP identities. It is a move of
  one registry entry, not a re-establishment: the same local S1-U TEIDs, the
  same eNB-UE-S1AP-ID and the same MME-UE-S1AP-ID. No TEID is allocated at
  arrival and no bearer is re-established. The move also re-binds every prepared
  bearer to the arrived radio identity, because a prepared bearer is bound to
  the MME-UE-S1AP-ID until a UE identity exists and the two are not
  interchangeable.
- Promotion transfers ownership exactly once. On success the preparation record
  sets `ownershipTransferred`, clears `entry` and `ownedTeids`, and keeps only
  immutable audit scalars. Nothing in the preparation layer holds a pointer that
  can release a reached UE's resources after that.
- Preparation cleanup must not destroy a reached UE. `releaseOwned`, `expireDue`
  and `~HandoverPreparationOwner` are no-ops on a transferred record. Cancellation,
  repeated cancellation, expiry and destroying the owner are all equally
  forbidden from touching a reached UE or retiring its current TEIDs.
- Bearer activation requires verified readiness. The whole prepared set is
  validated before the first `activateUe`, so the activation loop cannot stop
  half way; the default is activated first whatever order the E-RABs arrived
  in, and a dedicated bearer only after the default it is linked to. The
  readiness is read from the real `BearerContext` objects, not from the record's
  description of them. `BearerRuntime::restoreAccess` stays TUN-gated and is not
  involved here.
- Handover Notify requires confirmed target access. `notify()` refuses a
  transaction that is absent, stale, uncommitted, unreached, incompletely
  promoted, ambiguous, mismatched in identity or cell, or whose bearers are not
  all ready — and an already-notified transaction is a duplicate rather than a
  second notification. An unsuccessful send is reported as unsuccessful and
  leaves `notifySent` false. A caller cannot bypass the gate by calling
  `EncodeHandoverNotify` directly: that produces bytes, not an accepted runtime
  handover.
- Source eNB identity is not inferred from the MME SCTP association. The
  `SourceContext` is supplied by the caller of `EnbMultiplexer::prepareHandover`
  and is explicitly test-harness-verified provenance. It is never derived from
  the SCTP peer, from TAC or PLMN equality, from a matching EBI or TEID, or by
  parsing an opaque container. The live S1AP dispatcher does not start a
  preparation: it cannot establish that provenance, so it fails closed.
- Simulator-specific arrival control is not real RRC.
  `SIMULATED_HANDOVER_COMMAND` and `SIMULATED_HANDOVER_ACCESS` are internal
  simulator frames. The arrival binding is a correlation value and not a
  credential, it has no S1AP representation, and nothing here derives or
  fabricates a NAS or AS security key. Never place these frames in a transparent
  container, send one to an MME, or describe the exchange as 3GPP RRC.
- Source context release and the MME-controlled bearer path update remain
  deferred. Nothing here sends a UE Context Release, retires a source TEID or
  redirects real EPC downlink traffic. Do not claim end-to-end S1 handover
  completion from a Handover Notify.

The detail, including the arrival evidence contract, the promotion and rollback
algorithm, the ownership transfer and the Notify gate, is in
`docs/lte-s1-connected-handover.md`. The cases live in
`test/lte/handover_target_arrival.cpp` and drive the production radio receive
path against real registry resources:

```bash
./cmake-build-release/nr-tests --no-version --test-case="lte/handover/arrival:*"
```

## Connected-mode handover orchestration and UE-side execution

The two-eNB coordination contract is
`src/lte/enb/handover_orchestration.{hpp,cpp}`. The UE-side execution is in the
UE's own production radio receive path, `src/lte/ue/app.cpp`, driven through
`MobilityContext` in `src/lte/ue/lifecycle.{hpp,cpp}`. These rules are what a
change must not weaken.

- The isolated MME relay is a transport between two simulator-owned eNBs and
  nothing more. Every message that crosses it is a real encoded S1AP PDU
  produced and consumed by the accepted production codec, so nothing may turn a
  message into a method call to get around the codec. It holds no subscriber
  state, it is not an MME and it performs no core procedure. What it accepts is
  evidence that the target really sent a Handover Notify and that the two eNBs
  agree about the transaction. It is not evidence that a live EPC executed a
  Modify Bearer Request, redirected any real downlink traffic or updated a
  bearer path. Do not claim an MME-controlled bearer path update, a core path
  update or live EPC continuity from it, and do not add a Path Switch Request as
  a shortcut to one.
- The orchestration state machine ends at `AWAITING_CORE_PATH_UPDATE` on
  purpose. Everything after it is the MME-controlled bearer path update and the
  source release, and neither is implemented here. Do not report a transaction
  that reached that state as a completed handover.
- Source eNB identity is supplied by the caller as an explicit `SourceContext`
  and is verified against the live source registry before a transaction can
  open. It is never derived from the MME-facing SCTP association, from TAC or
  PLMN equality, from a matching EBI or TEID, or by parsing an opaque container.
  A preparation whose source identity cannot be established from a documented
  contract is refused, not guessed.
- Target selection and every target endpoint are explicit simulator
  configuration in a `HandoverTargetBinding`: the target's identity, CGI, TAI,
  radio endpoint, S1-U address, security algorithm sets, association epoch, and
  the one source it permits. Nothing about a target is discovered. A binding
  naming two networks, one that does not name this source as permitted, and one
  offered under an association epoch this side no longer holds are each refused.
- The arrival token is a correlation value the preparation issues and the UE
  repeats. It is not a credential, it proves nothing about the UE and it is not
  an authorisation to enter a cell. What the target accepts as an arrival is the
  whole frame that carries it — both cells, both S1AP identities and the PDN
  address — agreeing with the committed preparation, checked in the target's own
  production radio receive path. A replayed token, a token that disagrees with
  the record, and a frame naming another cell each confirm nothing and move
  nothing.
- The PDN address is never adopted from a frame. The UE compares the command's
  address against the one its own NAS was assigned, and the relay compares the
  arrival's address against the one the transaction already binds. Both checks
  happen before anything moves.
- A connected-mode handover command is consumed in the UE's own production
  radio receive path, and every part of it is checked before any transport
  moves. The command names a cell and never an address: the radio endpoint is
  resolved from the UE's own configuration, so a frame cannot redirect a UE to
  an endpoint nobody authorized. A command naming a cell this configuration
  never stated, or naming the serving cell as its target, is refused, and a
  refusal leaves the UE serving the cell it is already on.
- The S1AP session binding is checked against what the UE already holds and is
  never adopted from the command. That binding reaches the UE through
  `S1_CONTEXT_ESTABLISHED`, an internal simulator frame the serving cell sends
  at the moment it makes a bearer UE-ready, carrying the eNB-UE-S1AP-ID and the
  MME-UE-S1AP-ID its S1 context is bound to. It is downlink only, both halves
  are non-zero at encode and at decode, and it states a binding a later command
  is checked against. No command can establish one. This frame is a simulator
  abstraction and not 3GPP: it never leaves the simulator's radio layer.
- The radio endpoint moves only after the last check has passed, and the
  arrival frame is transmitted from the UE's own socket naming both cells from
  the UE's own configuration and never from the command, so the source identity
  in the arrival is the one the source eNB states about itself and the one the
  target's preparation was verified against.
- A connected-mode handover is not an Attach and not a Service Request. The UE
  starts neither. One EPS registration is one registration whatever accesses
  carry it, so a run that reports a second Attach or a Service Request during a
  handover has not performed one.
- `SIMULATED_HANDOVER_COMMAND` and `SIMULATED_HANDOVER_ACCESS` are internal
  simulator frames and not 3GPP RRC. The arrival binding is a correlation value
  and not a credential, it has no S1AP representation, and nothing here derives
  or fabricates a NAS or AS security key. Never place one in a transparent
  container, send one to an MME, or describe the exchange as 3GPP RRC.
- Source release and the MME-controlled bearer path update remain deferred. No
  source TEID is retired by a handover, nothing here sends a UE Context Release
  and nothing redirects real EPC downlink traffic. What the source still owns
  must still resolve and must still be unretired, and its own tunnel still
  forwards: that is the deferred boundary, not a completed handover. Do not
  simulate the deferred work by retiring anything early.
- A delayed G-PDU for a source TEID reaches no tunnel the handover created. The
  target never bound that identifier, so the packet is refused before it can
  touch the reached UE's bearers or its radio endpoint, and no counter of the
  reached UE moves on its behalf. An End Marker is still only recorded: for an
  identifier a cell never held and for its own active tunnel alike, it releases
  nothing and starts nothing.
- A handover of one UE leaves every other UE on the same cell alone: its S1
  context, its access generation, its bearers, its local transport and its data
  path.

The detail, including the sequence the acceptance case drives and the
implemented-versus-deferred boundary, is in
`docs/lte-s1-connected-handover.md`. The focused cases live in
`test/lte/handover_orchestration.cpp`:

```bash
./cmake-build-release/nr-tests --no-version --test-case="lte/handover/orchestration:*"
```

The end-to-end acceptance case is `test/lte/handover_acceptance.cpp`. It needs
a real kernel TUN, so it is a `doctest::skip()` case and has no `ctest` entry at
all; the privileged CI job runs it as its own invocation with its own log and
its own sentinels, `UNIRANSIM-PHASE18D-PRIVILEGED-EXECUTED` and
`UNIRANSIM-PHASE18D-PRIVILEGED-COMPLETE`. The privileged job therefore runs
three invocations, one per skipped case:

```bash
sudo unshare --net -- env UNIRANSIM_RUN_PRIVILEGED_TUN_TESTS=1 \
  ./cmake-build-release/nr-tests --no-skip \
  --test-case="lte/handover/acceptance: a connected-mode handover executes end to end between two real eNBs"
```

## Isolated core path migration and source handover release

The isolated core phase is `src/lte/enb/handover_core_path.{hpp,cpp}` (the SGW
forwarding map, the MME's update and its confirmation) and
`src/lte/enb/handover_source_release.{hpp,cpp}` (the source-side release). It
continues the accepted Phase 18-D transaction past
`AWAITING_CORE_PATH_UPDATE`. These rules are what a change must not weaken.

- The isolated MME owns the update decision. `BeginIsolatedCorePathUpdate`
  validates the whole precondition set — isolated-simulator mode, a transaction
  at the Phase 18-D boundary, a bound arrival token, a complete coordination
  record, a target that still holds the reached UE with an active bearer set
  exactly matching the admitted E-RABs, and an SGW that really holds this
  session's source path — and only then records the request. Nothing else may
  dispatch an update, and a Handover Notify on its own never does.
- The isolated SGW owns the installed forwarding map. `IsolatedSgw` holds one
  entry per bearer of a session, keyed by the verified EPS session identity
  (MME-UE-S1AP-ID plus the PDN address the UE's NAS assigned) and the EBI, and
  each entry carries the SGW-side tunnel identity, the downlink endpoint tuple,
  the original source endpoint, a path generation and the owning transaction.
  Nothing outside `IsolatedSgw` writes that map, and the sender
  (`sendDownlink`) names a bearer and never a destination.
- A dispatched request is not a committed update. The MME records the request,
  moves to `CORE_UPDATE_REQUESTED`, then `CORE_UPDATE_COMMITTING`, and only a
  read-back of the SGW's actual map that matches the request produces
  `CORE_PATH_UPDATED`. An answer is never taken from the component that asked
  for the update, and a commit is never inferred from sending a request.
- A request is written against the generation the MME read before dispatch. The
  SGW refuses a request whose expected generation is not the one its map holds,
  so an update can never be applied against a starting point its author did not
  see.
- Per-bearer atomicity is a publication boundary, not a promise. The whole
  replacement set is validated before the first entry is written, and it is
  published as one assignment of the session's complete state. No reader can
  observe a session whose default bearer is on the target while its dedicated
  bearer is still on the source, and a failure on the second bearer leaves the
  first one exactly where it was. A partial replacement is never reported as a
  commit.
- Target endpoint provenance is the target's own reached registry entry. The
  destination address is the address the target's S1-U socket actually bound,
  the port is the one it listens on, and the TEID is the one its own allocator
  bound and its own bearer holds. None of the three is a constant, a
  caller-supplied value, a UE report or a frame field, and each bearer's SGW
  TEID, role and linked default must agree with the transaction's own bearer
  inventory.
- An eNB-local TEID is not a globally unique identifier. Two eNBs can hold the
  same numeric local S1-U TEID, so a map entry's destination is the endpoint
  tuple and never the TEID alone. Two sessions may legitimately resolve to the
  same number on different cells, and a source retirement must never retire a
  target's identifier merely because the numbers match. Registry and S1-U
  endpoint ownership are eNB-local.
- An indeterminate update is not a success. If the SGW published a replacement
  the MME cannot correlate — a lost answer, an unreadable session, a
  generation that does not follow the request — the transaction stays
  `CORE_UPDATE_INDETERMINATE`, nothing is released and no second update is
  applied. `ReconcileIsolatedPathUpdate` reads the actual map and moves the
  transaction only when the exact transaction and the complete endpoint set can
  be proven; it never re-applies a request.
- A settled core path cannot be cancelled or expired away. `cancel` refuses a
  transaction whose update was dispatched, installed or is indeterminate, and
  `expireDue` leaves every record that entered the isolated core phase alone:
  discarding one would discard the only statement that a mapping may exist.
- The isolated MME owns the source-release authority. A release requires a real
  encoded UE Context Release Command from the MME, the source's own record of
  having commanded this UE into this handover, and a release decision the MME
  could only build after the SGW's installed mapping was confirmed. The Cause
  field is a corroborating statement (`radioNetwork`/`successful-handover`)
  and never an authorization on its own; the presence of a second UE with a
  matching identity authorizes nothing.
- Handover release is not idle release. `UeRegistry::releaseS1` is the
  ECM-IDLE transition: it retains the logical EPS bearer contexts, keeps the
  entry, marks the session retained and lets the caller tell the UE that its
  access ended. `UeRegistry::removeHandoverSource` retains nothing: it retires
  every bound local TEID through the normal ledger, drops the S1AP identity
  indexes, releases the bearer contexts and erases the entry, its radio
  identity and its peer. It is the handover path and only the handover path.
- A handover release sends no `S1_CONTEXT_RELEASED`. The UE is connected to
  the target, and a notification from the cell it left would be a statement
  about an access it is no longer on. The ordinary idle path keeps sending it;
  that behaviour is unchanged.
- Release timing is a bounded guard event, not a timer callback. The MME arms a
  deadline the caller supplies and a release before it is refused as
  `RELEASE_GUARD_NOT_SATISFIED`. Nothing in the release path deletes a UE
  context directly: it encodes a message, delivers it through the source's own
  S1AP receive path, and waits for a real encoded Complete.
- A sent release command is not a release. `SOURCE_RELEASE_COMMAND_SENT` is
  not `SOURCE_RELEASE_CONFIRMED`, and only a decoded Complete whose identity
  pair matches the transaction — or a reconciliation of the source's registry
  that proves the context is gone and every named TEID is retired — produces
  `ISOLATED_HANDOVER_COMPLETE`. A reconciliation is reported as
  `RECONCILED_REGISTRY` and is never described as a received Complete.
- A duplicate release command reaches no context. The first release erases the
  entry and spends the source record and the MME decision that authorized it,
  so a repeat is refused by the dispatcher and cannot re-run a cleanup against
  whatever holds the identifier now.
- Source cleanup preserves the target exactly. The target is a different
  registry; its context, its S1AP identifiers, its local TEIDs, its bearer
  readiness, its radio peer and its PDN address are untouched by anything the
  source does, and its counters are not credited with traffic it never carried.
- An End Marker is not a release and not a core update. The isolated SGW sends
  one on the old path after a confirmed update, the eNB records it against the
  tunnel it names, and neither the map's generation, the bearer's readiness,
  the retention of the source TEIDs nor the transaction's state moves. It is
  never a substitute for the UE Context Release Command.
- This is not S11 GTPv2-C and not a Modify Bearer Request. The MME/SGW exchange
  is an explicitly labelled simulator-internal typed contract
  (`IsolatedPathUpdateRequest` / `IsolatedPathUpdateCommit`), it has no wire
  format, no GTP-C message is encoded or decoded anywhere, and no real EPC
  procedure is claimed. A confirmed isolated mapping is evidence about this
  simulator's forwarding table and nothing about a live core.

The detail, including the sequence the acceptance case drives, the confirmation
and reconciliation rules and the retained interoperability gaps, is in
`docs/lte-s1-connected-handover.md`. The deterministic cases live in
`test/lte/handover_core_path.cpp` and `test/lte/handover_core_phase.cpp`; the
privileged acceptance case is the second one in `test/lte/handover_acceptance.cpp`:

```bash
./cmake-build-release/nr-tests --no-version --test-case="lte/handover/core-path:*,lte/handover/core-phase:*"
```

## Live S1AP handover ingress

`src/lte/enb/handover_live_ingress.{hpp,cpp}` is what a real MME's handover
messages meet on the raw S1 association. Its whole job is to recognise, check
and refuse them; it must never be loosened into executing one without the
capabilities below actually existing.

- The handover family is classified by PDU category *and* procedure code. A
  message is the procedure it claims only when both match the direction that
  procedure uses: Handover Request is an initiating message of procedure 1,
  Handover Command a successful outcome of procedure 0, Handover Preparation
  Failure an unsuccessful outcome of procedure 0, Handover Cancel an initiating
  message of procedure 4.
- A live handover message is refused, not executed. Nothing in this dispatcher
  allocates a target TEID, creates a provisional context, promotes a UE, sends a
  Handover Notify, touches the isolated SGW map or releases a source context.
  `LiveHandoverOutcome::mutatedState` is a tripwire that must stay false.
- A refusal is signalled only with a message this build can encode: a Handover
  Failure naming the MME-UE-S1AP-ID and `radioNetwork/ho-failure-in-target-EPC-eNB-or-target-system`.
  When the decode failed before an identifier was read, no response is
  invented; the refusal is recorded and nothing is sent.
- The capability model is the authority for what may run. It is computed on
  every call and nothing sets it: not a command-line option, not a
  configuration value, not an S1AP message, not a test. A capability becomes
  true when the code and the tests behind it exist, never because someone asked
  for a live experiment.
- `SOURCE_PROVENANCE_READY` is false and stays false until a real ownership
  contract exists. A target eNB receives no standards-compliant source identity,
  and the accepted contract forbids inferring one from the MME peer, the TAC, a
  PLMN match, an EBI, a TEID, a timestamp or an opaque container.
- `RRC_CONTAINER_READY` is false because there is no LTE RRC (TS 36.331) codec.
  The `SIM-HOv1` container is a simulator frame and must never be sent to a real
  MME, a real eNB or a real UE, and no opaque bytes may be translated into a
  simulator command.
- `HANDOVER_SECURITY_READY` is false because the UE has no KeNB, no NH handling
  and no AS keys. The `nextHopParameter` the MME sends is carried, never
  applied, and a handover request whose NH is zero or whose algorithms are empty
  is refused rather than accepted with fabricated material.
- `MME_PATH_UPDATE_OBSERVABLE` is false because an eNB cannot see the SGW's
  forwarding map. A sent Handover Notify is not evidence that the core moved the
  path, and the isolated SGW map is not the core's.
- The isolated path is unchanged. It still reaches its target through
  `EnbMultiplexer::prepareHandover` and still stops at
  `AWAITING_CORE_PATH_UPDATE` / `ISOLATED_HANDOVER_COMPLETE`; the live ingress
  neither calls nor bypasses it.
- No live handover is authorized by this repository's state. Running one needs
  a fresh, separately scoped authorization naming every participating resource
  and the rollback.

The source-level record of what the real EPC implements, and the reasoning
behind the live NO-GO, is `docs/lte-open5gs-s1-handover-interoperability.md`.

## LTE RRC handover codec

`src/lte/rrc/` encodes and decodes the two LTE RRC messages an S1 handover
carries, with UPER. `src/asn/lte-rrc/` is asn1c output and is never hand-edited.

- LTE RRC is UPER; S1AP is APER. Never encode one with the other's writer, and
  never decode an S1AP octet string by reinterpreting it as an S1AP PDU.
- The pinned release is TS 36.331 V15.6.0, kept as `tools/lte-rrc-15.6.0.asn1`
  with its SHA-256 in `docs/lte-rrc-handover-codec.md`. Regenerate; do not patch
  the ASN.1 or the generated sources to make a compiler or a test pass.
- Release 16 does not compile with the available asn1c (extension-addition
  groups inside a CHOICE). That is recorded, not worked around.
- The source-to-target container carries a `HandoverPreparationInformation`;
  the target-to-source container carries an RRC `HandoverCommand` whose
  `handoverCommandMessage` is an `RRCConnectionReconfiguration`. Both layers are
  encoded and checked; neither may be replaced by simulator bytes.
- The S1AP container is a 36.413 SEQUENCE
  (`SourceeNB-ToTargeteNB-TransparentContainer` /
  `TargeteNB-ToSourceeNB-TransparentContainer`) whose first field is the RRC
  octet string. This repository does not encode that wrapper yet, so what it
  produces is the `rRC-Container` payload, one layer inside a real container.
  Do not describe that as a complete transparent container.
- `SIM-HOv1` remains simulator-only and is refused by the RRC decoder. It is
  never sent to a real MME, eNB or UE.
- A valid UPER message is not an executable handover. `RRC_CODEC_VALID`,
  `RRC_CONFIGURATION_VALID`, `RRC_RUNTIME_INPUT_AVAILABLE`,
  `RRC_SECURITY_READY` and `RRC_UE_EXECUTION_READY` are separate, and only the
  first is true. The codec does not derive, log or invent security material.
- Fields this phase does not model — `sourceMeasConfig`,
  `sourceRadioResourceConfig`, the optional members of MIB/SIB1/SIB2 and of
  `radioResourceConfigCommon`, `carrierFreq`, `rach-ConfigDedicated` and the
  measurement/security IEs of the reconfiguration — are omitted or encoded as
  empty legal structures, and the design record says which.

## S1AP transparent containers

The handover transparent containers are not the RRC messages. TS 36.413 puts a
SEQUENCE around each one, and that SEQUENCE is what the S1AP IE's OCTET STRING
carries. The layers are:

```
TS 36.331 RRC message          UPER   src/lte/rrc/rrc_handover.cpp
TS 36.413 container SEQUENCE   APER   src/lte/enb/transparent_container.cpp
TS 36.413 S1AP message         APER   src/lte/enb/codec.cpp
```

- The three layers stay separate. Never encode one with another's writer, and
  never put raw RRC octets where an S1AP IE expects a container.
- The container's own fields are typed and carry provenance: a target E-UTRAN-CGI
  states whether it came from a fixture, a simulator cell or a running target,
  and a UE history entry states whether the runtime recorded it, it is fixture
  data, it is stale or the preceding cells are unknown. A decoded CGI is not
  proof that the cell exists.
- A source container must carry UE history the responsible runtime recorded.
  For offline fixtures, fixture history is acceptable and labelled. For live
  use, missing or stale history refuses the container; a timestamp difference
  is not a history.
- The target-to-source payload is the RRC HandoverCommand whose
  handoverCommandMessage is an OCTET STRING (CONTAINING DL-DCCH-Message)
  carrying the rrcConnectionReconfiguration (TS 36.331 V15.6.0). Phase
  18-F-B1's EncodeHandoverCommand stores the bare reconfiguration in that
  field; it is kept for its historical pinned vectors, and
  EncodeHandoverCommandPayload produces the conformant form the container
  carries.
- Unsupported optional fields are refused, not dropped: supplying
  e-RABInformationList or iE-Extensions fails the encoding. Omission is only
  ever used where the specification makes the field optional.
- A handover AS-Config can be syntactically valid with legal empty optional
  structures and still be an incomplete runtime configuration.
  AssessAsConfigCompleteness names the difference; do not substitute defaults
  without a normative basis, and keep fixture values labelled as fixture input.

## Handover runtime provenance

Where a handover's typed inputs come from is as important as how they are
encoded. `src/lte/enb/handover_runtime_provenance.{hpp,cpp}` owns that.

- Decoding is not verification. A value read off the wire is `WIRE_UNVERIFIED`
  until a runtime authority raises it, and a decoder is not an authority.
  Matching a PLMN, a TAC, a cell ID or a well-formed structure raises nothing.
- A cell identity is only real when an authority owns it: this eNB's own
  `EnbConfig`, or a current `TargetInventory` entry. A physical cell identity
  alone is not a globally unique E-UTRAN CGI.
- The UE's serving-cell history belongs to one EPS session and is recorded from
  real transitions on a monotonic clock. An access release is not a cell visit,
  a same-cell re-establishment is not a duplicate entry, and a fresh Attach
  starts a new session history. `Time-UE-StayedInCell` saturates at 4095 with
  the saturation named.
- A `SourceHandoverSnapshot` can only be built from live runtime components;
  a missing input is named and nothing is produced. Never substitute a fixture
  into a live-use configuration.
- `EncodeHandoverCommandPayload` is the only HandoverCommand form a live path
  may emit. The `...Legacy` pair exists for its historical pinned vectors and
  is refused by the conformant decoder.

## What must never be committed

- `config/*.local.yaml` — private laboratory configurations, including
  subscriber authentication material. They are git-ignored and mode 600.
- `reports/` and `artifacts/` — generated phase reports and packet captures.
  They are git-excluded and local only.
- Credentials, packet captures, or any generated acceptance evidence.

## Commit style on `develop`

Work goes directly on `develop` as normal forward-only commits. No feature
branches, pull requests, rebase, reset, amend, force push or history rewrite;
`master` is frozen.

The subject is one sentence, imperative and lowercase, with a `type: summary`
prefix — `fix:`, `feat:`, `test:`, `docs:`, `refactor:`. Keep it to what the
change does. Do not put phase or stage markers, or any external project name,
in the subject, and do not append an attribution trailer. A short body is
optional and should say why, not restate the diff.

## Live EPC laboratory

The LTE path can be driven against a real Open5GS EPC. When it is:

- Never run an Open5GS binary with `--version`. It prints the version and then
  starts the daemon, which collides with the live sockets.
- Never restart or reconfigure the EPC, change the MME served TAI list, or
  modify HSS authentication data, as part of development work.
- Preserve pre-existing laboratory resources. An empty-looking resource is
  still not ours to delete; removing one needs ownership established first and
  separate authorization.
- A policy change such as a PCC rule is separately authorization-gated, and the
  authorization is per change and per subscriber. A past authorization is spent
  once it has been used and is **not** standing authorization for a later phase
  or a later reproduction. Without a fresh, explicit authorization that names
  the subscriber, the APN/session, the rule scope, the backup procedure, the
  rollback and the verification, do not apply or reapply a PCC rule, modify
  PCRF policy, modify HSS or authentication data, provision another subscriber,
  or touch any other subscriber's rules. Root privileges are not authorization.
  When the authorization is absent, record the live gate as blocked and say so;
  do not substitute a deterministic or local result for it.
- A temporary PCC rule for a non-GBR QCI must carry **neither `mbr` nor
  `gbr`**. Naming one without the other makes Open5GS raise the absent one to
  `OGS_MAX_BITRATE_S1AP` (10 Gbps) while leaving the named one alone, so the
  E-RAB Level QoS Parameters advertise a guaranteed bitrate above the maximum
  bitrate and the eNB must refuse them as `invalid-qos-combination`. Both
  fields absent is the conformant shape for a non-GBR QCI: no GBR QoS
  Information and a basic QCI-only NAS EPS quality of service. This is a rule
  about the laboratory policy document; do not relax production QoS validation
  to accommodate a rule that breaks it.
- Subscriber provisioning, `maxUes`, and throughput benchmarking are outside
  the scope of ordinary development work.

## Design records

`docs/` holds one design record per LTE slice rather than a single manual. When
behaviour is verified, update the relevant record to describe what was actually
observed, and correct a record only for a demonstrated inconsistency.
