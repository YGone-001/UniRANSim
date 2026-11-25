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
- A test that asserts what a fake peer observed must wait for the peer's own
  synchronised event, not for the log line that says a message was sent. The log
  line is written after the datagram leaves, but the peer's worker may still be
  holding it when shutdown begins, and a worker stops consuming at that point.
  `test/lte/ue_mobility_context.cpp` publishes the received TAU Complete
  under a mutex and waits for it through a bounded condition variable for
  exactly this reason. A wait that times out is a failed observation and must
  fail the test; it is never a slow success.

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

## LTE AS security context

`src/lte/security/` owns the TS 33.401 Annex A key hierarchy. It is a separate
library because the UE and the target eNB both consume it and neither may depend
on the other. `docs/lte-as-security-context.md` is the design record.

- **Keys are owned, never shared.** `AsSecurityContext` is move-only and bound to
  one UE id and one NAS generation. Using it for another UE is
  `CROSS_UE_CONTEXT`; using it with an older NAS generation is
  `STALE_NAS_GENERATION`. There is no global security context and no copy in
  `SourceHandoverSnapshot`, `SourceSession`, `ServingCellHistory`,
  `TargetInventory` or a provenance manifest.
- **UL NAS COUNT provenance is explicit.** `KeNB = KDF(KASME, 0x11, count)` takes
  the COUNT of the Security Mode Complete, read at the call site *before*
  `SendProtected` advances the counter. Never use whichever `count` field is
  easiest to reach, never reconstruct it from another message, never reset it
  implicitly.
- **NCC labels a chain position; it is not an input to the NH KDF.** Keep an
  absolute chain index beside the three-bit value, so a wrap is a later position
  with a different key. A request that would land behind the current position is
  `STALE_NH`, never realised by walking backwards.
- **Handover keys are staged.** `PrepareHandover` never touches the active key;
  only `CommitHandover` installs the candidate, and `DiscardHandover` leaves the
  active key, NCC and NH chain unchanged. A failed handover must never replace
  the active KeNB.
- **No algorithm is guessed.** A runtime context is created with
  `negotiated == false` because this simulator has no RRC security mode
  procedure; `DeriveAccessKeys()` refuses rather than copying the NAS selection
  into the AS role. K_UPint is derived only for a profile that has a UP integrity
  algorithm, which the LTE UE here does not.
- **No fabricated radio parameters.** `DeriveTargetKenbStar` needs a verified
  `TargetRadioConfig`; `TargetContext` has no PCI or EARFCN-DL today, so the
  target refuses with `MISSING_TARGET_RADIO_CONFIG`. Never invent a PCI or an
  EARFCN-DL to make a derivation succeed, and never infer one from a CGI.
- **Every refusal is typed.** `AsSecurityError` names the reason, the operation
  throws, and a rejected derivation leaves no partial state. Do not add a silent
  default or an all-zero key path.
- **Secrets stay in memory and die there.** No key material in logs, metrics,
  JSON diagnostics or packet-capture notes; destruction uses a volatile store
  loop; `Describe()` is the only string a context produces and it carries no key
  bytes.
- **Derivation is not activation.** `AS_KEY_DERIVATION_READY` may be true while
  `HANDOVER_SECURITY_READY`, `UE_RADIO_EXECUTION_READY` and
  `LIVE_HANDOVER_EXECUTION_READY` stay false. Do not enable live handover
  because the KDF tests pass.

### Initial AS security mode procedure

`src/lte/security/as_algorithm_selection.{hpp,cpp}`,
`as_security_codec.{hpp,cpp}`, `pdcp_security.{hpp,cpp}` and
`as_security_procedure.{hpp,cpp}` implement the initial AS security mode of
TS 33.401 7.2.4 and TS 36.331 5.3.4. `docs/lte-as-security-activation.md` is the
design record.

- **Priority is the operator's order.** `SelectAsAlgorithms` takes the first
  allowlist entry the UE advertises and this build implements. Never sort by
  algorithm identity, never derive the choice from the UE bitmap, and never let
  the UE bitmap select on its own.
- **Fail closed, never downgrade.** Empty allowlist, empty UE bitmap, no
  intersection, unsupported identity, stale configuration generation and
  EIA0-without-null-NAS are refusals. A missing strong algorithm is never a
  quiet fallback to a null one.
- **Null security is named.** EEA0/EIA0 protect nothing and the selection says
  so; do not describe them as confidentiality or integrity.
- **Two bearer profiles, never one.** SRB: one-octet header, 5-bit SN, no
  D/C bit, 32-bit MAC-I always present, and the MAC-I is **ciphered with the
  data** (TS 36.323 6.2.2). DRB 12-bit: two-octet header with D/C = 1, no MAC-I
  (TS 36.323 6.2.3). Never give an ordinary UE DRB a MAC-I field, and never
  leave an SRB MAC-I in the clear when ciphering is active.
- **The MAC-I covers COUNT||BEARER||DIRECTION||0^26||header||data** and is
  computed before ciphering. A receiver parses the clear header, deciphers data
  and MAC-I, then verifies. B5's "the MAC-I is never ciphered" was wrong.
- **BEARER is the RB identity minus one.** SRB1 is 0, SRB2 is 1, DRB 3 is 2. Use
  `RadioBearerIdentity` and its `BearerField()`; never pass an RB identity where
  the algorithm expects the bearer field.
- **UP integrity is not claimed.** The simulator has no `UE-EUTRA-Capability`
  user-plane integrity indication, so `PDCP_UP_INTEGRITY_READY` is false and no
  DRB accepts an integrity algorithm. "Not a relay node" is not a reason.
- **Activation is a protocol event.** The SecurityModeCommand is integrity
  protected and never ciphered; the SecurityModeComplete is integrity protected
  and not ciphered; ciphering starts only after the completion is verified. A
  selected algorithm is not activation, and a sent command is not completion.
- **Failure changes nothing.** A rejected command or completion leaves the
  context, the keys and the ciphering state exactly as they were, and a failed
  transaction cannot be revived by a second message.
- **Secrets stay owned.** The PDCP entity wipes its keys on destruction; no key
  material reaches a log, a metric or a diagnostic string.
- **The procedure has no carrier.** This simulator has no RRC connection and no
  SRB1, so `AS_SMC_RUNTIME_READY` and
  `AS_INITIAL_SECURITY_ACTIVATION_READY` stay false. Do not wire a flag to make
  them true without an actual bearer to carry the messages.

## LTE simulated Uu transport and SRB0

Phase 18-F-B6-A starts the runtime carrier under the AS security work.
`src/lte/rrc-runtime/` owns it; the design records are
`docs/lte-simulated-uu-transport.md`, `docs/lte-srb0-rlc-tm.md`,
`docs/lte-rrc-initial-access.md` and `docs/lte-rrc-connection-runtime.md`.

- **RRC must travel through RLC.** A message may not go from RRC to UDP to RRC.
  The transport envelope carries an association, a direction, a logical channel
  and opaque bytes; it never names an RRC message type.
- **The transport is not reliable by accident.** No hidden ACK, retransmission,
  sequence number, reordering or deduplication. Loss stays observable so the
  state machine, not the transport, decides what a loss means.
- **RLC TM adds nothing.** No header, no SN, no STATUS, no segmentation. An SDU
  above 1024 bytes is refused, never truncated or segmented.
- **SRB0 has no PDCP.** No SN, no MAC-I, no ciphering, no integrity. Nothing in
  the SRB0 path instantiates a security entity.
- **Do not claim RRC_CONNECTED without SetupComplete.** In B6-A the UE stops at
  `RRC_SRB1_CONFIGURING` with the staged SRB1 configuration. Only a validated
  RRCConnectionSetupComplete on SRB1, in B6-B, may complete the connection.
- **The association is not a C-RNTI.** There is no PRACH, contention resolution
  or MAC scheduling; the association is a simulator routing identifier and must
  stay unique and validated per UE.
- **Never duplicate NAS.** The legacy NAS_UPLINK path is untouched in B6-A. When
  B6-C moves NAS into RRCConnectionSetupComplete, the old path must not also run.

## LTE RLC AM entity

`src/lte/rrc-runtime/lte_am.{hpp,cpp}` is the LTE AM entity; the wire codec is
`rlc_am.{hpp,cpp}`; `docs/lte-rlc-am-entity.md` is the design record.

- **Do not reuse the NR engine.** `src/lib/rlc/entity_am` is NR-typed (segment
  info enum, NR PDU objects); adapting it would fabricate NR headers from LTE
  fields. Keep the two wire formats and the two entities separate.
- **One SN arithmetic path.** Modulus 1024 and a single `Distance()` helper; never
  compare SNs with `<` and never open-code the modulo.
- **The window is a correctness boundary.** 512 outstanding PDUs; a submission
  beyond it is refused rather than sent out of window.
- **Per-SN state, not per-PDU-arrival.** A duplicate is rejected by SN, an
  out-of-order PDU is buffered, and an SDU spanning several PDUs is reassembled
  by FI before delivery - a segmented SDU must never be delivered piece by piece.
- **Timers are tick-driven.** The entity has no clock; the caller owns the tick.
  Reaching `maxRetx` fails the entity instead of retrying forever.
- **SRB1 is a bearer, not a connection.** `lte_am_bearer` now carries SRB1 on
  DCCH and B6-B2 reports `SRB1_RLC_AM_READY`, but the entity itself still knows
  nothing about PDCP, NAS or RRC state. Do not move RRC or NAS logic into it.

`lte_am_bearer.{hpp,cpp}` puts one entity on one simulated Uu endpoint; the design
records are `docs/lte-rlc-am-engine.md`, `docs/lte-rlc-am-state-machine.md`,
`docs/lte-rlc-am-retransmission.md` and `docs/lte-rlc-am-pdu-format.md`.

- **One bearer, one socket, one association.** The bearer moves a `uu::Socket`
  in and binds the entity's sender and deliverer to it. A test never calls the
  opposite endpoint's entity, and never shares a buffer between endpoints.
- **The D/C bit routes the receive path.** AMD and STATUS are told apart by the
  first octet the LTE header already carries; do not add a type field to the
  envelope and do not add an RRC shortcut.
- **Reassembly merges, it does not concatenate.** Reception keeps only the byte
  ranges it does not already hold, so a duplicate or an overlapping
  retransmission cannot double a delivered SDU. Keep that rule when touching
  `OnPdu`.
- **A reordering expiry must not acknowledge past a hole.** It makes the pending
  STATUS due and leaves VR(R) at the missing SN; moving VR(R) to VR(H) silently
  drops the SDU because the report is computed over `[VR(R), VR(H))`.
- **Impairment is test-owned and deterministic.** `test/lte/lte_am_uu.cpp` puts
  a node on the link that drops, duplicates, delays, reorders or re-segments a
  frame - and nothing else. It never repairs loss, never fabricates an ACK, and
  never enters production code. A partially delivered PDU is produced by
  re-encoding it as AMD segments at the link, not by weakening the transport.
- **Evidence comes from the frames.** A runtime test states direction, endpoint,
  PDU type, SN, SO, length, poll bit and STATUS result from the decoded frames it
  actually saw, plus the entity counters for transmission and retransmission; it
  does not infer success from the absence of a crash.

## LTE SRB1 runtime and the RRC connection (B6-B2)

`rrc_srb1_runtime.{hpp,cpp}` carries the first real SRB1 message;
`srb1_pdcp.{hpp,cpp}` and `srb1_rlc_config.{hpp,cpp}` are its two halves.
`docs/lte-srb1-pdcp-runtime.md` is the design record.

- **Pre-security means pre-security.** RRCConnectionSetupComplete is sent before
  SecurityModeCommand, so the SRB1 PDCP PDU has a one-octet header (three
  reserved bits, five-bit SN) and **no MAC-I and no ciphering**. Never call
  `PdcpSecurityEntity` on this path, and never invent a protected PDU that the
  peer has no keys to verify.
- **An enumerator is not a tick count.** Resolve every TS 36.331 RLC field through
  `MapSrb1Configuration`; a spare value, an SRB identity other than 1, a zero
  tick or an unknown field is a typed refusal, never a default. The eNB maps the
  exact message it sends, so the two sides cannot disagree.
- **maxRetxThreshold counts retransmissions.** `AmConfig.maxRetx` counts
  transmissions, so the mapper adds one. Do not compare the two directly again.
- **One direction per bearer, decided by the role.** A UE bearer transmits uplink
  and accepts only downlink; an eNB bearer the reverse. Never infer the local role
  from an incoming frame, and never let a test relay rewrite a wrong direction
  into a right one - a mislabelled frame must be refused by the receiving bearer.
- **A held frame belongs to its destination.** The socket's reorder impairment
  must never hand a delayed outgoing frame to the local receive path and must
  keep its destination. Release it on the next send, on `FlushPending()`, or
  count it when the socket closes.
- **RRC_CONNECTED needs an acknowledgement.** The UE moves to
  `RRC_CONNECTION_COMPLETE_PENDING` when it submits SetupComplete and to
  `RRC_CONNECTED` only when RLC acknowledges that PDU; the eNB moves only after
  it has decoded and validated the message.
- **One SetupComplete per context.** A second message, a duplicate PDCP SN, a
  wrong transaction identifier or a wrong PLMN must not deliver the NAS payload
  again; the callback fires exactly once.
- **No NAS interpretation.** The dedicatedInfoNAS bytes are opaque here and stop
  at the callback. Do not route them into S1AP in this phase; that is B6-C.
- **Nothing above this is claimed.** `AS_SMC_RUNTIME_READY`,
  `AS_INITIAL_SECURITY_ACTIVATION_READY`, `HANDOVER_SECURITY_READY`,
  `UE_RADIO_EXECUTION_READY` and `LIVE_HANDOVER_EXECUTION_READY` stay false:
  there is no SecurityMode procedure on this bearer, no security activation and
  no radio execution.

## LTE performance and capacity

Two goals drive the current workstream: PERF-P1 (single UE sustained 1 Gbps
user-plane goodput over a real EPC path) and PERF-P2 (512 concurrent
authenticated, EPS-registered LTE UEs). PERF-P2 is accepted by the 512-subscriber
campaign. PERF-P1 completed the four 60 s TCP profiles and a root-cause diagnostic:
TCP uplink four-stream sustained 929–941 Mbps and the best one-second interval
was 999.71 Mbps, so both targets remain below 1 Gbps. Per-thread evidence
confirms one PGW-U thread at 89.8% of one core on the uplink plateau; the
host endpoint control reaches 42.9 Gbps. Downlink is 663 Mbps with no process
saturated. The operational record is
`docs/lte-single-ue-1gbps-benchmark.md`.

The UE downlink receive path has been measured, not assumed. It sustains
245,000-287,000 frames per second on one core against the 62,000 a four-stream
downlink second actually offers, so it is excluded as the downlink limit with at
least 4.0x headroom; the remaining candidates are EPC-side and need their own
authorization. The measurement, the bounded-drain alternative and the invariants
any future batch must keep are in `docs/lte-downlink-receive-performance.md`.
The raw evidence tool is `tools/lte-downlink-receive-experiment.cpp`, built only
with `-DBUILD_EXPERIMENTS=ON`; it is a measurement tool and must never join the
CI matrix.

- An isolated registry holding 512 synthetic contexts is `ISOLATED_CONTEXT_CAPACITY`
  and never a real EPS Attach. The structured checkpoint classifications in
  `src/lte/enb/capacity_report.hpp` must be reported separately.
- A loopback or private-namespace throughput number is
  `ISOLATED_SIMULATOR_THROUGHPUT`, never `REAL_EPC_USER_PLANE_THROUGHPUT`.
  Application goodput and GTP-U wire rate are different numbers and both must
  be quoted with their measurement point.
- The eNB configuration validates `maxUes` in 1..512. That is a validation
  bound, not a measured capacity result; do not raise it and call that
  scalability support. The measured capacity evidence lives in
  `docs/lte-512-ue-capacity-foundation.md` and
  `docs/lte-ue-runtime-scalability.md`.
- The LTE UE is process-per-UE (`lte-ue -c <config>`): one process, one TUN
  interface and one UDP socket per UE. Do not assume the 5G multi-UE option
  exists for LTE.
- The performance counters in `src/lte/enb/perf_counters.hpp` are opt-in and
  hold no IMSI, key or authentication material. Keep them that way.
- Measurements that need real EPC interaction, new subscribers or sustained
  load are `NOT_MEASURED` or `BLOCKED_AUTHORIZATION`, never a fabricated zero.
- The eNB main loop must not sleep on SCTP before it drains the user plane. It
  drains radio and S1-U in bounded batches and, while traffic is present,
  checks SCTP without blocking. A 16-packet batch after a 20 ms wait is a
  800 packet/s ceiling, not a scheduler choice.
- The UE must not wait 50 ms on the radio after it read an uplink TUN packet.
  With continuous uplink and no downlink, that wait is a 320 packet/s ceiling.
  Idle turns keep the longer waits; busy turns use a non-blocking radio check.
- Throughput profiles use iperf3 with a 5 s warm-up and a 60 s measured window,
  quote decimal Mbps, and separate application goodput from S1-U GTP-U wire
  rate. The installed tool is recorded with its version.
- The EPC's online-charging quota (Gy/OCS) is a hard test limit. Never modify a
  subscriber, balance or tariff to make a test pass. A 60 s 1 Gbps run needs
  about 7.5 GB; if the available balance is lower, stop before the session is
  torn down and report `BLOCKED_EPC_CONFIGURATION`.
- UDP loss, jitter and retransmissions are results. Do not retry until a
  favorable sample appears or discard earlier samples.
- A receive-buffer experiment must state every hop effective budget. A run in
  which all sockets inherit a raised `rmem_default` is not evidence for the
  per-socket option, and a run in which one hop is larger than the others is
  not a controlled A/B. Open5GS never requests a receive buffer, so its
  sockets take `rmem_default` at creation and only a restart after the sysctl
  change moves them; record that restart rather than assuming it.
- A receive buffer is opt-in and verified. Absent means no system call and the
  historical socket; an explicit request is checked with getsockopt and a value
  the kernel capped is a configuration failure, never a success with a smaller
  number. Linux returns twice the applied request, so a readback of 2x is the
  applied value and anything lower is a cap. Never use SO_RCVBUFFORCE, never
  write a sysctl, and never enable a large per-UE buffer by default: one eNB
  S1-U socket is shared, one UE radio socket exists per process, and 512 tuned
  UEs is a deliberate memory decision rather than a default.
- A downlink TCP plateau is a loss question before it is a processing question.
  Attribute it with per-socket UDP accounting (`/proc/net/udp` drops and
  receive queue per local port) and with both ends' TCP state (`ss -tinm` in
  the sender's and the receiver's own network namespace) before proposing any
  code change. In this laboratory the first loss point moves between the eNB
  S1-U socket, the UE radio socket and the SGW-U socket as their buffers change,
  so a single-buffer fix relocates the loss instead of removing it. Quote a
  goodput number only together with its loss number, and never classify a flow
  as receive-window limited from `rcv_space` alone: check `rwnd_limited` and
  the advertised window against the measured bandwidth-delay product.
- A single simulated-radio receive per main-loop turn is the production UE
  behaviour. Do not treat it as a bottleneck without a measurement: it was
  measured at about 30% of one core at the DL4 rate, with a ceiling at least
  four times higher. A bounded
  drain is a per-turn cost saving, not a throughput fix, and it must stay
  bounded, keep arrival order, use a zero timeout after the first frame, and
  return to the TUN uplink read between turns. The contract is pinned in
  `test/lte/downlink_receive.cpp`; do not weaken it to make a batch convenient.
- The OCS ledger can differ from its own conservation equation by exactly 2^32
  bytes, in `data_used` in one snapshot and in `data_available` in another. That
  is a field-level carry artefact outside this repository, not lost credit, and
  it is never repaired here. Reconcile from the session and usage records, quote
  which observation window each number came from, and never write a balance.

## LTE 512-UE capacity

The production `maxUes` bound is now `1..512`. That is a configuration bound,
not a scalability claim: what establishes capacity is the isolated runtime
evidence in `docs/lte-512-ue-capacity-foundation.md`.

- A synthetic registry entry is `ISOLATED_CONTEXT_CAPACITY`, never a simulated
  Attach and never a real EPS registration. The nine classifications are
  reported as structured evidence states (`PASS`, `FAIL`, `NOT_MEASURED`,
  `NOT_APPLICABLE`, `BLOCKED_AUTHORIZATION`), and an unmeasured value is never
  reported as a failure.
- Each simulated radio endpoint is its own UDP socket: the registry keys a UE
  on its peer address, so one shared socket cannot present many UEs.
- This kernel drops excess UDP datagrams when a burst is queued before any
  receive (222 of 300 in a raw probe; 222 of 512 in the Phase 19-C microburst).
  Read the socket's own drop counter from `/proc/net/udp` and report
  delivered, dropped and unaccounted separately. Interleave sends with polling;
  that is also how independent radios behave.
- A full registry refuses new contexts deterministically and still accepts
  releases and cleanup. Nothing leaks a slot.

## LTE UE runtime fleet and 512 radio endpoints

Phase 19-C measures the actual `lte-ue` executable and the production radio
receive path. Its rules are what a later change must not weaken.

- A live LTE UE process is `ACTUAL_LTE_UE_PROCESS_ALIVE`, not authentication.
  A radio peer is `SIMULATED_RADIO_ENDPOINT_ACTIVE`, not an EPS bearer. An
  Attach Request is `PRE_AUTH_ATTACH_ATTEMPT`, not an Attach Accept. Context
  persistence is `ISOLATED_CONTEXT_RETAINED`; EPS registration retention is
  `STABLE_REGISTRATION_RETAINED` and stays `NOT_MEASURED` without a real EPC.
  Never set the second from the first.
- `src/lte/enb/capacity_report.hpp` owns the structured states. `PASS`,
  `FAIL`, `NOT_MEASURED`, `NOT_APPLICABLE`, `BLOCKED_AUTHORIZATION` and
  `BLOCKED_RESOURCE_LIMIT` are distinct. A checkpoint that was not attempted is
  not a failure, and a workload stopped by a declared budget is not a feature
  failure.
- Memory is three observations, never one: current RSS from `VmRSS`, peak RSS
  from `VmHWM`, and PSS/private bytes from `smaps_rollup` where available. A
  single current-RSS sample is not a peak. The page size comes from
  `sysconf(_SC_PAGESIZE)`, never a hardcoded 4096.
- The process launcher in `src/lte/enb/process_fleet.{hpp,cpp}` must run the
  real binary with generated test-only configurations. It closes every inherited
  descriptor in the child, drains the production radio socket between spawns so
  a 512-process start is not an accidental microburst, and stops at the declared
  `MemAvailable` reserve, the file-descriptor limit or a startup deadline.
  It reaps what it starts and reports orphans and residual sockets.
- The 512-process fleet is opt-in and local-only
  (`UNIRANSIM_RUN_PROCESS_FLEET=1`). It must never run as part of the ordinary
  CI matrix; the sanitizer and coverage jobs do not build `lte-ue`.
- The principal 512-endpoint acceptance uses the production default
  `EnbMultiplexer::poll(16, 16)`. A larger test-only budget may be reported as
  a comparison, never as the principal result. Paced arrival, staggered arrival
  and deliberate microburst are separate profiles and must be labelled as such.
- Kernel drops are read from the socket's own counter. `SO_RXQ_OVFL` is tried
  where available; this host did not surface it, so `/proc/net/udp` is the
  authoritative measure. Never change `rmem_max`, `wmem_max` or any persistent
  sysctl; a per-socket `SO_RCVBUF` comparison is allowed.
- Latency is reported per measurement point, with nearest-rank p50/p95/p99 and
  the sample count. Synthetic enqueue-to-processing, multiplexer handling and
  the full eNB main loop are not the same number, and the main loop is not
  claimed from a multiplexer-only fixture.
- The process-per-UE decision is `KEEP_PROCESS_PER_UE` only while the measured
  512-process fleet stays inside the budget with clean teardown. It covers the
  measured pre-authentication runtime. The later 512-subscriber campaign
  measured the post-authentication TUN and registration state with the
  authorized cohort; user-plane throughput remains a separate PERF-P1 question.
- Nothing here changes GTP-U forwarding, TUN packet handling, TEID lifecycle or
  the benchmark profiles. PERF-P1 remains a separate workstream.

## Real LTE Attach campaigns

The designated 512 subscribers ran through genuine EPS-AKA, NAS security and
Attach against the live Open5GS EPC. These rules are what a later
campaign must not weaken.

- A subscriber inventory is verified as a set, not by a count: every IMSI from
  the first to the last inclusive must be present exactly once, with a complete
  K and exactly one usable OPc or OP, an AMF, and the intended APN. A range
  count alone is not verification.
- Only the identities explicitly designated for the campaign may be used. Do
  not create, modify, clone or delete subscribers. Do not print K, OPc, OP or
  an authentication trace containing them. Generated configurations are mode
  600, outside Git, and never logged.
- The campaign builds a one-to-one manifest: index → IMSI → radio UE id →
  `enbLink.localPort` → TUN prefix. Every runtime identity is unique.
- TUN naming must be collision-safe under concurrent startup. A shared
  generated prefix races: two UEs can be offered the same name. Give each UE a
  unique prefix (or serialize allocation) before starting it.
- A live campaign is bounded and staged: 1 → 4 → 16 → 32 → 64 → 128 → 256 →
  512, with the production default radio budget, bounded outstanding Attach
  transactions, and a stop on the first material failure. Do not launch 512
  Attach Requests at once.
- Process execution, radio registration, Attach Request, Attach Accept and EPS
  registration are five different states. A report must name which one each
  number is. The MME `enb_ue` gauge and session counters are corroborated, not
  replaced, by UE state logs.
- Retention is a measured window, not the last Attach count. Sample the
  registered population, TUNs, addresses and processes for the whole window.
- When the UE TUN leaves the host namespace to avoid stealing EPC traffic, the
  move may clear its address. Restore the exact address the Attach assigned;
  never invent one.
- Cleanup goes through the supported UE Detach path. Stopping the eNB clears
  its eNB-UE contexts but leaves MME/SMF sessions; do not restart Open5GS to
  make them disappear, and do not delete unrelated sessions. Verify the EPC
  returns to its pre-campaign counts.
- The 512-subscriber live campaign is a separately authorized local operation.
  Never add it to GitHub Actions, and never make an ordinary test depend on the
  live EPC, MongoDB or subscriber secrets.

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
## LTE NAS over SRB1 and S1AP (B6-C)

`enb_rrc_bridge.{hpp,cpp}` joins the SRB1 runtime to the S1AP codec;
`docs/lte-nas-s1ap-runtime.md` is the design record.

- **NAS stays opaque to the eNB.** Encode and decode S1AP containers only. Do not
  read, decrypt or rewrite a NAS PDU, and do not move NAS security into the eNB.
- **No fabricated identities.** The eNB-UE-S1AP-ID is allocated by the eNB and
  the MME-UE-S1AP-ID is learned from the first downlink NAS. Never invent either,
  and never answer a transaction whose identity pair does not match.
- **KASME belongs to the UE and the MME.** The eNB context starts at the KeNB in
  `securityKey`. `EnbAsSecurityContext` must keep having no KASME input, and the
  AS procedure must keep taking `AsKeySource` so it cannot ask for one.
- **Read the capability string most significant bit first.** TS 36.413
  UESecurityCapabilities has EEA0/EIA0 in its first bit. Use
  `MapUeSecurityCapabilities`; a raw cast reads EEA0 as EEA15.
- **One PDCP entity per direction carries the whole procedure.** The command is
  downlink COUNT 0 and the completion uplink COUNT 0; afterwards the same
  entities continue. Never recreate them after activation.
- **A failed or unverified completion activates nothing.** Do not report an
  Initial Context Setup outcome before the radio procedure reached ACTIVE.
- **The legacy link remains for idle and mobility.** Do not send the same NAS PDU
  over both the legacy link and SRB1, and do not create a second NAS delivery
  path.
- **No live claim.** `LTE_OPEN5GS_ATTACH_ACCEPTED` and
  `LTE_EPS_ATTACH_OVER_SRB1_READY` stay false until the production UE NAS path is
  wired and a live Attach is accepted.

## LTE Uu endpoint configuration (B6-D)

`docs/lte-uu-endpoint-configuration.md` is the record. Both the UE and the eNB
accept an optional `uu` block; absence means the endpoint is not configured and
the legacy `enbLink`/`ueLink` transport stays the only radio path.

- **Opt-in, never inferred.** Do not bind a Uu socket because some other field
  looks like an address, and do not silently fall back to a different endpoint.
- **One endpoint per address and port.** The loader refuses a `uu` block that
  reuses `ueLink`, `s1u` or the UE's `enbLink` local endpoint.
- **No configuration without a consumer.** A `uu` block that nothing reads is a
  promise, not a feature: until the UE application and the multiplexer bind it,
  do not describe the production path as integrated.

## LTE eNB SRB1 multiplexer integration (B6-D1)

`EnbMultiplexer` owns the Uu socket and the `EnbRrcBridge` when `uu.port` is
configured. `docs/lte-nas-s1ap-runtime.md` is the record.

- **Transport is a per-UE property.** `EnbUeEntry::transport` names it; never
  infer it from an address or the presence of a pointer, and never send a legacy
  software-radio frame to a Uu UE or fall back to the legacy link when Uu fails.
- **One identity authority.** The bridge must allocate through
  `UeRegistry::allocateEnbUeS1apId` and emit through the identified sink, so the
  existing SCTP stream and sender binding stay authoritative. Never add a second
  allocator or a second SCTP path.
- **Register before you ask.** The setup callback creates the pending
  `CONTEXT_PENDING` entry before the Initial UE Message leaves.
- **Answer after security.** For a Uu UE the Initial Context Setup outcome is
  committed only from `commitPendingIcs()`, once AS security is ACTIVE. Do not
  send the response from the request handler and do not mark an E-RAB
  established early.
- **Cancel by association.** `unbindAssociation()` cancels pending transactions
  and releases only their reservations; no callback may commit an old one.
- **Keep the fixture honest.** A deterministic MME fixture is not Open5GS, and a
  green eNB integration is not production UE or EPS Attach acceptance.

## LTE eNB boundary closure (B6-D2 Commit A)

- **Two NAS-PDU fields, not one.** Initial Context Setup carries a message-level
  NAS-PDU (IE 26) *and* an optional per-E-RAB one. Do not conflate them. The
  message-level PDU is delivered over SRB1 only after AS security is active.
- **One transaction per UE.** A duplicate Initial Context Setup Request while a
  pending transaction exists is refused and its reservations are released; it
  must never stage a second transaction or produce a second response.
- **No capability change without evidence.** The production UE application is
  SRB1-enabled (B6-D3), so `LTE_EPS_ATTACH_OVER_SRB1_READY` is true, since
  B6-D4 `LTE_EPS_DETACH_OVER_SRB1_READY` is true as well, and since B6-D5 so are
  `LTE_EPS_SERVICE_REQUEST_OVER_SRB1_READY`, `LTE_PRODUCTION_UE_PAGING_PCCH_READY`
  and `LTE_ECM_IDLE_ACCESS_RESTORATION_READY`. There is no separate
  "production UE" switch in the registry; do not cite one.
  `LTE_DEFAULT_BEARER_OVER_SRB1_READY` and `LTE_OPEN5GS_ATTACH_ACCEPTED` stay
  false.

## LTE production UE SRB1 Attach (B6-D3)

`docs/lte-production-ue-srb1-attach.md` is the record.

- **One NAS downlink entry.** Both the legacy `NAS_DOWNLINK` path and the
  `UuNasTransport` callback deliver into `handleNasDownlink` through
  `deliverNas`. Do not add a second state machine, and do not process the same
  message from two places.
- **The application owns the transport.** When `uu` is configured, `Run` owns
  the `UuNasTransport` for its lifetime and releases it by RAII. It is never a
  global, a temporary or a test-only object.
- **RRC before the first NAS.** The Attach Request is built once and is offered
  to `SendNas` only after the connection can carry it. Never send it over the
  legacy link in Uu mode and never sleep to fake the ordering.
- **One uplink interface.** Every Attach-exchange NAS message goes through
  `sendNas`; a refusal fails the run instead of falling back to `enbLink`.
- **Security is not bypassed.** `PrepareAsSecurity` is called with the same
  KASME and uplink NAS COUNT the Security Mode Complete used. The eNB's KeNB in
  the Initial Context Setup Request must be derived from that COUNT.
- **The callback only queues.** `Pump`/Tick run on the UE thread; the callback
  appends bytes and returns. Release clears the callback before the runtime and
  socket are destroyed, so no late NAS reaches a dead handler.
- **ATTACH_ONLY, ATTACH_DETACH, SERVICE_REQUEST and PAGING are the current Uu
  scope.** Attach, the UE-initiated Detach, and the ECM-IDLE Service Request /
  Paging restoration travel on the Uu path. Recovery, TAU and the user plane
  still travel on the legacy link; a Uu configuration naming another lifecycle
  scenario is refused at startup rather than mixed.
- **Two processes, opt-in.** `UNIRANSIM_RUN_TWO_PROCESS_ATTACH=1` runs
  `tools/lte-uu-attach-peer.cpp` and the real `lte-ue`. Without it the case is
  NOT_EXERCISED. A deterministic MME is still not Open5GS.
## LTE production UE Detach and EPS lifecycle (B6-D4)

`docs/lte-production-ue-srb1-detach.md` is the record.

- **One send interface, no exceptions.** The Detach Request goes through the
  same `sendNas` as the Attach exchange. In Uu mode it is a protected
  ULInformationTransfer on SRB1; a refusal fails the run and is never retried
  over `enbLink`.
- **The Detach scenario is attach-then-detach.** `attach-detach` is an alias of
  `detach`, not a second mode: the UE attaches, registers, then detaches the
  same session after `triggerAfterMs`. Do not add a mode that skips the Attach
  or starts a new session for the Detach.
- **No security reset at Detach.** The Detach reuses the Attach's NAS security
  context. UL COUNT 2 and DL COUNT 2 follow the Security Mode Complete (0) and
  Attach Complete (1) / Attach Accept (1); never re-key, re-initialise or
  hardcode a COUNT to make a test pass.
- **Deregistration requires a verified Accept.** `EMM_DEREGISTERED` is entered
  only after the protected Detach Accept verifies. A corrupted MAC, a replayed
  COUNT or a peer that stops answering must leave the UE registered and fail the
  run, never produce a Detach success.
- **Release belongs to the layer that owns it.** Only the NAS context, bearer
  set, TUN and pending wire are released on Detach completion; the transport is
  released by RAII at process exit. Do not destroy RRC/PDCP state another layer
  still owns, and do not send a legacy `EPS_SESSION_DELETED` control frame for
  a Uu session.
- **The peer is still a deterministic MME.** It assigns a GUTI in the Attach
  Accept and verifies the Detach Request with the production decoder and the
  active EIA2 key; it must not accept a Detach by message type or length.
- **Failure modes are part of the acceptance.** Duplicate downlink, peer exit,
  corrupted MAC and an unreachable peer each have their own case. A new failure
  path that is not exercised stays reported as PARTIAL in the final report.
- **Two processes, opt-in.** `UNIRANSIM_RUN_TWO_PROCESS_ATTACH=1` runs
  `tools/lte-uu-attach-peer.cpp` and the real `lte-ue`; the GitHub Actions job
  `Production UE Attach-Detach (two processes)` sets it for the lifecycle cases.
  Without it they are NOT_EXERCISED, and a deterministic MME is still not
  Open5GS.

## LTE production UE ECM-IDLE access restoration (B6-D5)

`docs/lte-production-ue-ecm-idle.md` is the record.

- **Three layers, three states.** EMM-REGISTERED, ECM-IDLE and RRC_IDLE coexist:
  entering ECM-IDLE releases only the access. It is never a Detach, and it never
  clears the NAS security context, the GUTI or the EPS bearer identities.
- **The network owns the release.** ECM-IDLE is entered because the MME sent an
  S1AP UE Context Release Command and the eNB sent a real RRCConnectionRelease.
  Never set an ECM-IDLE flag directly.
- **Release after the stack unwinds.** The UE defers its RRC teardown to `Tick()`:
  the bearer that delivered the release is still on the stack, so destroying it
  inside `OnRrc` is a use-after-free. Keep that ordering.
- **Service Request is the first NAS of the new connection.** It travels in
  RRCConnectionSetupComplete (not ULInformationTransfer), is encoded by
  `nas::EncodeServiceRequest` and verified by `nas::VerifyServiceRequest`. Never
  bypass the short MAC, never re-use the previous COUNT, and never accept a
  COUNT that did not advance.
- **Paging is PCCH, not SRB1.** `LogicalChannel::PCCH` carries a real RRC Paging
  message. The eNB delivers it to the bounded idle endpoints; the UE matches its
  own S-TMSI. Do not deliver a page as a NAS message or as a boolean event.
- **Identity comes from the Attach.** The UE adopts the assigned S-TMSI after the
  Attach Accept; the S-TMSI in the next RRC request, the Initial UE Message and
  the page must be the same one. Never hardcode it in a test.
- **The new KeNB follows the Service Request COUNT.** `PrepareAsSecurity` and the
  MME's `DeriveKenb` both use the recovered uplink COUNT; a mismatch fails the
  scenario rather than falling back.
- **A failed restoration stays failed.** A wrong page, an absent page, a bad
  short MAC or a departed peer leaves the UE registered and exits non-zero; it
  never claims ECM-CONNECTED.
- **Two processes, opt-in.** The `lte/uu/idle` cases run under
  `UNIRANSIM_RUN_TWO_PROCESS_ATTACH=1`, and the GitHub Actions job
  `Production UE EPS lifecycle (two processes)` runs them as blocking tests.

## LTE production UE DRB user plane (B6-D6)

`docs/lte-production-ue-drb.md` is the record. `DrbRuntime`/`DrbBearer`
(`src/lte/rrc-runtime/drb_runtime.{hpp,cpp}`) compose the accepted PDCP DRB12
profile and the accepted LTE RLC AM entity on a DTCH logical channel; the RRC
configuration is `src/lte/rrc-runtime/rrc_drb_config.{hpp,cpp}`.

- **A DRB is not SRB1.** User-plane IP packets never travel on DCCH or in a NAS
  message. They travel a DRB: PDCP -> RLC AM -> DTCH. `LTE_DEFAULT_BEARER_OVER_SRB1_READY`
  is a historical, misnamed flag and stays false; the default bearer user plane
  is a DRB capability.
- **The RRC configuration is standard.** A DRB is added by an
  `RRCConnectionReconfiguration` whose `radioResourceConfigDedicated.drb-ToAddModList`
  carries `eps-BearerIdentity`, `drb-Identity`, PDCP, RLC AM and logical-channel
  configuration, and is acknowledged by `RRCConnectionReconfigurationComplete`.
  Never substitute a private simulator message for that configuration. A field
  the decoder cannot represent is refused, not ignored.
- **DRB identity is mapped, not guessed.** EPS bearer identity = E-RAB identity
  = DRB identity in this implementation; do not infer roles from QCI or list
  order, and configure the default DRB first.
- **PDCP direction is the traffic direction.** A UE DRB transmits uplink and
  receives downlink; an eNB DRB the reverse. COUNT, BEARER (identity minus one)
  and DIRECTION must agree on both ends. EEA0 is null protection and must be
  described as such; an ordinary UE DRB has no UP integrity and no MAC-I.
- **Two DTCH payload kinds.** `kind=1` is an RLC PDU. `kind=2` is READY, an
  internal simulator control that restates the generation and the NAS-assigned
  PDN address. The eNB never decrypts NAS and never invents an address; it
  refuses a restatement that contradicts what it holds.
- **S1-U is reused, not duplicated.** The eNB DRB hands uplink IP packets to
  `S1uEndpoint::forwardUplink` and receives downlink G-PDUs through its Uu
  downlink handler. A Uu downlink that no DRB can carry is an inactive-bearer
  drop; it never falls back to the legacy radio link.
- **ECM-IDLE destroys the access, not the bearer.** The S1 release retires the
  access TEID and destroys DRB/PDCP/RLC; the logical EPS bearer context and the
  TUN address stay. Restoration uses a fresh local/SGW TEID pair and fresh keys,
  carries traffic again on the same EBI, and the old TEID stays retired.
- **No production-UE user-plane claim without its acceptance.**
  `LTE_PRODUCTION_UE_DRB_READY` and
  `LTE_PRODUCTION_UE_BIDIRECTIONAL_USER_PLANE_READY` stayed false through D6
  until a multi-process case with a real TUN and a deterministic PGW endpoint
  ran. The component-level flags are true only on the evidence in
  `test/lte/drb_user_plane.cpp`; the production promotion is D7's acceptance in
  the next section.

The deterministic cases live in `test/lte/drb_user_plane.cpp`:

```bash
./cmake-build-release/nr-tests --no-version --test-case="lte/drb/*"
```

## LTE production UE TUN user plane (D7)

`docs/lte-production-ue-tun-user-plane.md` is the record. The acceptance is
`test/lte/production_uu_user_plane.cpp`: three real OS processes (production
`lte-ue`, production `EnbMultiplexer` + deterministic MME, deterministic
SGW-U/PGW-U) in two isolated network namespaces, with real TUNs and real GTP-U.

- **Three processes, no object shortcuts.** The UE reaches the eNB over the Uu
  UDP socket and the eNB reaches the SGW-U over a real GTP-U UDP socket on
  `:2152`. Never replace a socket hop with a function call, never inject a
  downlink packet directly into the UE TUN, and never claim a Core-network
  round trip from an in-process buffer.
- **The deterministic EPC is not an EPC.** The MME is a fixture; the
  SGW-U/PGW-U is test infrastructure. The bearer map file it consumes is an
  explicitly labelled simulator control written from the eNB's Initial Context
  Setup Response. It is not S11, not GTP-C and not Open5GS. Do not claim a live
  EPC path update or a real Open5GS Attach.
- **Two namespaces, two TUNs.** The UE TUN and the Core TUN are in different
  namespaces, connected only by the veth/GTP-U path. Both TUN addresses and the
  PDN address come from the same NAS assignment. A same-namespace setup would
  let the kernel route around the GTP-U path and is not acceptable evidence.
- **The production UE lifecycle must stay alive.** The `user-plane` scenario
  attaches, keeps the TUN and DRB, accepts a network release, restores the same
  EPS session with a compact Service Request and continues. It never exits on a
  successful restoration, never re-Attaches and never treats ECM-IDLE as Detach.
- **A DRB configuration that arrives before the TUN is deferred, not dropped.**
  The RRC callback can run in the same Uu batch as the Attach Accept; the
  application queues the configuration and applies it right after the NAS queue
  creates the TUN. It never acknowledges a configuration it did not apply.
- **Drain the Uu path and tick the DRB entities.** The production Uu receive
  path is drained in a bounded batch on both ends, and every DRB RLC AM entity
  is ticked each turn. Without the ticks no STATUS is generated and a lost PDU
  is never retransmitted; without the drain a TCP burst overflows the loopback
  UDP queue.
- **The DRB AM PDU bound is local and symmetric.** The RRC message carries the
  RLC enumerators, not the local AM PDU size. `DrbBearer` normalizes
  `DrbAmMaxPduBytes` on both ends; leaving the UE at the 128-octet SRB default
  fragmented every IP packet and collapsed the sustained TCP flow.
- **A Uu Service Request reuses the retained registry entry.** A reconnecting
  UE keeps its radio identity and endpoint; the multiplexer binds a fresh
  eNB-UE-S1AP-ID to the retained entry instead of registering a second UE. The
  EPS bearer contexts, the access epoch and the TEID retirement state survive.
- **TEIDs stay fresh and retired.** A restoration allocates a new local/SGW TEID
  pair; the old local TEID is retired and a late G-PDU for it is dropped as
  retired. A late old-SGW-TEID G-PDU is dropped by the SGW as retired traffic.
  Both cases are counted and neither reaches the UE.
- **Evidence is real, including its limits.** The acceptance checks ICMP, UDP
  and TCP payloads/hashes in both directions, the SGW UL/DL counters, the
  restored map generation and the retired TEID. iperf3 is attempted; the
  recorded local run stalled after a first-interval peak, so the throughput
  baseline is PARTIAL and must be reported with that observation, never as a
  fabricated sustained rate. PCAPs are written to
  `reports/evidence/phase-18-f-b6-d7/` only when `tcpdump` exists; otherwise the
  evidence says NOT_GENERATED.
- **Promotion is earned.** `LTE_PRODUCTION_UE_DRB_READY` and
  `LTE_PRODUCTION_UE_BIDIRECTIONAL_USER_PLANE_READY` are true only because this
  three-process acceptance passes. `LTE_OPEN5GS_ATTACH_ACCEPTED`,
  `LTE_512_UE_SCALE_ACCEPTED`, `LTE_SINGLE_UE_1GBPS_ACCEPTED` and
  `LTE_DEFAULT_BEARER_OVER_SRB1_READY` stay false.

Build and run:

```bash
cmake -S . -B cmake-build-d7 -DCMAKE_BUILD_TYPE=Release
cmake --build cmake-build-d7 --target nr-tests lte-ue lte-uu-user-plane-peer \
  lte-uu-sgw-peer lte-uu-traffic-probe --parallel "$(nproc)"

sudo unshare --net --mount --pid --fork --mount-proc -- bash -c '
  ip link set lo up
  export UNIRANSIM_RUN_PRIVILEGED_TUN_TESTS=1
  ./cmake-build-d7/nr-tests --no-skip \
    --test-case="lte/d7/acceptance: the production ue carries tun ip traffic over drb and gtpu end to end"'
```

The blocking CI job is `Production UE DRB TUN End-to-End User Plane
(multi-process, blocking)`; it installs `iproute2`, `tcpdump` and `iperf3`,
forces the skipped case with `--no-skip`, and requires both sentinels, the pass
line and the evidence summary.

## LTE production UE user-plane stability (D8)

`docs/lte-user-plane-stability.md` is the record. The sustained UL stall that
followed D7's first second was reproduced and attributed; these rules keep it
fixed.

- **AM timers are milliseconds and the caller must tick them that way.** The
  LTE AM entity has no clock: `t-PollRetransmit`, `t-Reordering` and
  `t-StatusProhibit` are tick counts of one millisecond. Tick the SRB/DRB
  entities on elapsed milliseconds with bounded catch-up, never once per
  main-loop iteration. The UE called `Tick()` more than a million times a
  second; a 15-tick timer expired in microseconds, repeatedly retransmitted the
  oldest PDU and failed the entity at `maxRetxThreshold` before any STATUS
  could return. That was the stall, not the socket queue.
- **Completion is "VT(A) passed the SetupComplete SN", not equality.** The UE
  may submit further SRB1 PDUs before the eNB acknowledges the SetupComplete;
  `VtA() == expectedAck_` then never holds and the UE stays pending, refusing
  its DRB reconfiguration. A reconfiguration received while
  `RRC_CONNECTION_COMPLETE_PENDING` is held and delivered on the transition;
  the application still defers it until the TUN exists.
- **The DRB RLC configuration is `t-PollRetransmit ms40`, `pollPDU p32`,
  `pollByte kBinfinity`, `maxRetxThreshold t32`, `t-Reordering ms5`,
  `t-StatusProhibit ms5`, window 512.** `PollByteCount` stores the kB
  enumerator's number and the entity uses it as bytes, so a finite pollByte
  index is effectively a poll on every PDU. Do not use a finite pollByte for
  the DRB until the table and its historical unit test are corrected together.
- **Drains are bounded and deeper than one frame.** The eNB Uu path drains 64
  frames per poll, the UE Uu pump 64 per turn, and the SGW peer 32 GTP-U
  datagrams per loop. A drain is still bounded, keeps arrival order and never
  becomes an unbounded queue. The S1-U send is non-blocking; a refused
  datagram is counted as `s1uSendDrops`/`send-drops=`, never silently lost.
- **TUN backpressure is the application's.** The UE pauses its TUN reader at
  64 unacknowledged DRB PDUs and resumes at 16, and it waits on the Uu socket
  instead of busy-spinning while paused. The RLC window stays the standard 512;
  do not enlarge it to hide a stall.
- **Measured baseline, not a first interval.** Three 30 s UL runs (67.4/69.6/
  70.1 Mbit/s; 241/249/251 MB), three 30 s DL runs (55.9/52.3/51.1 Mbit/s;
  200/187/183 MB), 60 s UL 62.2 Mbit/s and 60 s DL 52.4 Mbit/s, all with the
  DRB RLC ACTIVE, application drops 0 and 24-84 backpressure pauses per UL
  run. A simultaneous UL+DL run completed with UL 58.5 Mbit/s and DL
  6.5 Mbit/s; the DL portion is starved by the shared path and is not an
  independent DL rate. The numbers are local application goodput, not a live
  EPC or GTP-U wire rate, and 1 Gbps stays unclaimed.
- **Failure injection is evidence, not a recovery promise.** Killing the Uu
  peer fails the DRB RLC bounded and the UE still shuts down cleanly; deleting
  the TUN makes the next read fail with EBADFD and the process exits through
  its failure path; an SGW-U exit is not detectable at the UE. No RRC
  re-establishment or DRB recovery is implemented after an AM failure.
- `test/lte/production_uu_user_plane.cpp` (privileged, three processes) now
  requires the restored DRB `rlc_state == 0`, so the blocking CI job fails if
  the stall signature returns.

## Real Open5GS EPC integration (D9)

`docs/lte-open5gs-epc-integration.md` and `docs/lte-open5gs-live-acceptance.md`
are the records. The production `lte-ue` and `lte-enb` completed a live
Open5GS Attach and carried real bidirectional IP through the live SGW-U/PGW-U.

- **The live acceptance is production code, not a fixture.** S1-MME is a real
  SCTP association (`src/lte/enb/app.cpp`); S1AP, NAS, EPS AKA, NAS security,
  the default EPS bearer, Initial Context Setup, the E-RAB, the DRB12 PDCP, the
  LTE RLC AM and S1-U GTP-U all run. A deterministic MME or SGW-U must never
  stand in for the live run.
- **The PDN address comes from the Attach Accept.** The live pool assigned
  10.45.0.168/.170 etc.; never reuse the D7/D8 10.45.0.2, and never write an
  address the ESM bearer did not assign.
- **The SGW-U F-TEID comes from S1AP.** The eNB allocates its own local S1-U
  TEID and advertises it; the SGW-U F-TEID is the value the live MME delivered.
  No TEID is copied from the deterministic bearer map.
- **Test isolation and secrets.** Live tests use only identities designated for
  the laboratory and the private `config/*.local.yaml` (mode 600, git-ignored).
  Generated configs are mode 600 outside Git and deleted after the run. K, OPc,
  OP and authentication traces never enter Git, a report, a log or a PCAP
  analysis. The live EPC is never restarted, reconfigured or modified; no
  subscriber is created, changed or deleted. The test eNB/UE run in an isolated
  namespace with a new temporary veth, removed afterwards; the test endpoint is
  the host's own address, not an echo written into the UE TUN.
- **The Uu is simulated and loopback-only.** The eNB's Uu socket binds
  `127.0.0.1` and the current eNB uses the configured `uu.address` as the peer
  address, so the live eNB and UE share one isolated namespace. Separating them
  requires an eNB Uu source-address change, which is not implemented. Never
  describe this as a real RF air interface.
- **Clean lifecycle versus abnormal exit.** A clean Detach releases the eNB SRB
  and repeated Attach on the same eNB works (verified). If a UE process stops
  without Detach, the eNB's retained SRB RLC state is not reset; a later Attach
  from the same radio identity reuses it and its SetupComplete is treated as
  old. Use a fresh eNB or a clean Detach, and report the abnormal path as a
  limitation rather than a pass.
- **ECM-IDLE/Service Request on a live MME is PARTIAL.** The live environment
  has no controlled network release; the deterministic D5/D7 path remains the
  functional evidence. Do not claim a live network-initiated restoration from a
  UE-only test.
- **Live throughput is not a 1 Gbps claim.** The live Open5GS is a debug build
  and measured ~19-20 Mbit/s; the D8 deterministic path measured ~70 Mbit/s.
  `LTE_SINGLE_UE_1GBPS_ACCEPTED` and the 512-UE scale flag stay false.
- **The live EPC is not in GitHub-hosted CI.** Hosted runners have no Open5GS;
  the live acceptance is local evidence. The deterministic GitHub matrix stays
  blocking, and a live job is marked NOT_EXECUTED rather than simulated.
- `LTE_OPEN5GS_ATTACH_ACCEPTED` is now true on the live evidence (production UE,
  real MME/HSS, AKA, NAS security, default bearer, ICS, E-RAB, real IP and
  Attach Complete). The live-handover execution prerequisites remain false and
  live handover remains unauthorized.
