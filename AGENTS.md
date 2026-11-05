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
  No code path generates or transmits an End Marker.
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
