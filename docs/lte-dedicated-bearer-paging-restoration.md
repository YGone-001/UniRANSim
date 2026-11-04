# Dedicated EPS bearer restoration across repeated Paging

Design record for a network-created Dedicated EPS Bearer that is retained
across ECM-IDLE and restored on three consecutive network-triggered Paging
cycles after one EPS registration: what the bearer keeps, how each restoration
is authorised and answered, how the transport is rebuilt, and what the tests
actually proved.

This record covers the LTE UE and eNB paths in `src/lte/`. It does not describe
handover, E-RAB modification, bearer deactivation, or any NR procedure.

Three kinds of evidence appear below and are never mixed:

* **Deterministic** — the ordinary doctest suite, with a scripted network peer.
* **Privileged TUN** — the same production UE and eNB, a real kernel TUN, real
  UDP transport, and a bounded test SGW endpoint. Root and a private network
  namespace are required; the case is `doctest::skip()`ped in the ordinary
  suite and run only by the privileged CI job.
* **Real Open5GS** — a live EPC campaign. Nothing in this phase ran one; see
  §13.

A scripted or test peer is not the EPC. Where this record says "the network
sent", it means the test peer built the message the production code consumes.

## 1. EPS session and bearer lifecycle

One EPS session is one PDN connection with one default EPS bearer and zero or
more dedicated EPS bearers linked to it. The session outlives any single access.

| Stage | What exists |
|---|---|
| Attach | UE sends Attach Request; the network answers with an Attach Accept carrying the default EPS bearer identity, its QoS, and a PAA |
| Dedicated activation | the network sends `Activate dedicated EPS bearer context request` in protected NAS, carrying the dedicated EBI, the linked default EBI, the QoS and a TFT |
| ECM-IDLE | the S1 access is released; the logical bearer contexts are retained at both ends |
| Service Request | the UE answers a page; the network answers with an Initial Context Setup Request carrying the E-RABs to restore |
| Release | `UE Context Release Command` drops the access transport and returns the entry to `IDLE_RETAINED` |

Nothing in this list re-Attaches. A second Attach would be a second EPS
registration and is exactly what this record's scenario forbids.

At the eNB the split is deliberate: `DefaultBearerContext::releaseAccessTransport`
zeroes `localTeid`, `sgwTeid` and `sgwAddress` and clears the transport-ready
flags, but keeps `m_parameters.erabId` — the logical identity — so the bearer
can be restored later. Only `release()` destroys the logical context and resets
its counters.

At the UE, `MobilityContext` holds the EPS bearer state and the access
generation; `BearerRuntime` holds the per-bearer transport. An access release
takes the transport down and leaves the logical bearer in place.

## 2. Default versus dedicated bearer roles

The default EPS bearer carries the session: it is the one the PDN address
belongs to, it is established first, and a dedicated bearer is *linked* to it
by the linked EBI the network assigned.

The dedicated EPS bearer carries a filtered subset of that session's traffic.
Its role is defined by three network-assigned facts and by nothing else:

* the EPS bearer identity the network gave it,
* the default EBI it is linked to,
* the TFT the network gave it.

**Roles are never inferred.** Not from QCI — a QCI 9 bearer can be either. Not
from the order the E-RABs appear in the Initial Context Setup Request — the
MME is free to list them either way. Not from the E-RAB ID. The eNB takes the
default EBI from the UE's declared inventory when there is one, otherwise from
the retained bearer context, and only falls back to the first E-RAB when
neither exists. The three-round integration case deliberately delivers the
E-RAB list **dedicated-first** on every round and the roles still come out
correct.

Both ends must agree. The target eNB learns the roles from the UE's declaration
the first time it sees the UE; after it has confirmed them it does not need to
be told again.

## 3. NAS activation and TFT retention

A dedicated bearer is created by the network, not by the UE. The activation
arrives as `Activate dedicated EPS bearer context request` inside protected
NAS, and the UE decodes it through the production NAS path —
`src/lte/ue/nas.cpp` — so the TFT is parsed by the same code that would parse
it from a real MME.

The TFT is **retained**. It survives an S1 release, a cell reselection, a
Tracking Area Update and every later restoration. It is not re-sent in the
Initial Context Setup Request: an E-RAB to be set up carries QoS and transport
addresses, not the packet filter list. The filters the UE holds from activation
are the filters that classify traffic after restoration.

The TFT used by the tests is a real vector: the non-empty TFT the Open5GS MME
delivered during the earlier cross-TAI dedicated-bearer work, decoded and held
in `test/lte/tft.cpp`. It has two packet filters — an uplink filter for UDP
towards remote port 5000 from local port 7000, and a downlink filter for the
converse — under a `CREATE_NEW` operation code.

An unusable activation is refused in full and leaves the default bearer alone:
a duplicate EBI, a linked EBI that is not the default, or a malformed TFT each
produce a `Rejected dedicated EPS bearer activation` and no partial state.
Tests for these live in `test/lte/ue_mobility_target.cpp`.

### Matching

An uplink packet is offered to the dedicated bearers in turn and matched
against their retained TFTs (`tft::Classify`). A match selects that bearer. No
match, or no dedicated bearer at all, falls through to the default bearer. The
classification is on the packet's addresses, ports, protocol and direction —
never on the bearer's QCI and never on bearer order.

The consequence for verification is that a per-bearer user-plane test must send
a packet that actually matches the dedicated filter and a packet that does not,
and observe that they leave under different TEIDs.

## 4. Three-round Paging lifecycle

The scenario is one EPS registration and three consecutive restorations, each
one a complete ECM-IDLE → Paging → Service Request → multi-E-RAB restoration
cycle, with **no** Attach in between.

```
source cell          target cell                     target cell
Attach + dedicated   Normal TAU (no bearer)          (same cell, retained)
      |                     |                               |
   ECM-IDLE ----------> reselect                      Paging (round 1)
      |                     |                               |
      |              NAS_UPLINK_MOBILITY_CONTEXT      inventory-form SR
      |              + TAU Request                           |
      |                     |                          ICSR (both bearers)
      |                     |                          UE confirms transport
      |                     |                          release -> IDLE_RETAINED
      |                     |                               |
      |                     |                          Paging (round 2)
      |                     |                          compact SERVICE_REQUEST
      |                     |                          ICSR (both bearers)
      |                     |                          release -> IDLE_RETAINED
      |                     |                               |
      |                     |                          Paging (round 3)
      |                     |                          compact SERVICE_REQUEST
      |                     |                          ICSR (both bearers)
```

Each round restores **both** the default and the dedicated bearer, from the
same E-RAB list, to the same UE, under one security context. Each round gets a
fresh pair of local S1-U TEIDs and a fresh eNB-UE-S1AP-ID.

A retransmission of an outstanding Service Request is not another round. The
counts that matter are the Paging indications the UE matched, the Service
Requests it produced, and the restorations that completed.

## 5. Fresh-cell inventory bootstrap

A cell that has never confirmed this UE's bearer roles must be told what the UE
is holding. That is what the bearer inventory is for.

The target's Normal TAU is answered with a Tracking Area Update Accept only —
no Initial Context Setup Request. That leaves the UE in ECM-IDLE with
`AccessBootstrap::DECLARE_REQUIRED` outstanding and the eNB entry in
`IDLE_RETAINED` with its access generation still at 1 on both ends. The
`UE Context Release Command` that closes the TAU's S1 connection is silent at
the radio: the entry has no logical bearer yet, so nothing is announced and the
generation is not advanced.

On the first page the UE then sends its Service Request wrapped as
`NAS_UPLINK_MOBILITY_CONTEXT`, carrying the retained inventory — the default
EBI and the dedicated EBIs it is still holding. The target eNB resets its
access generation to 1 for this new access, records the declaration, and only
then opens the Initial UE Message. From the declaration it learns which EBI is
the default and which are dedicated.

**The form of the radio answer comes from `MobilityContext::accessBootstrap` —
confirmed bearer-role ownership — and never from `accessGeneration`.** A
generation-1 cell that has never confirmed the roles needs the declaration. A
generation-3 cell that has confirmed them does not. `onAttachComplete`
deliberately does not mark the roles retained, so an Attach is never mistaken
for a confirmed inventory.

## 6. Retained-cell compact Service Request

Once the target has confirmed the roles — a completed restoration marks them
retained, `MobilityContext::onServiceRestored` setting
`AccessBootstrap::ROLES_RETAINED` once both bearers are back and the user plane
is ready — the declaration is no longer needed. Rounds two and three at that
same cell send the ordinary compact 4-octet EPS Service Request.

The compact form is chosen because the roles are retained, not because the
generation is larger. Re-selecting away and back to a cell that has confirmed
the roles would still use the compact form, and a brand-new cell would still
need the inventory whatever generation number it assigns.

The test asserts the split explicitly: exactly one inventory-form answer across
three rounds, and exactly two compact answers.

## 7. Per-bearer transport restoration

The Initial Context Setup Request lists the E-RABs to restore. The eNB
establishes the **default first**, whatever order the list is in, and then each
dedicated bearer linked to it. The ordering is enforced in
`src/lte/enb/multiplexer.cpp`, not left to the MME's listing order.

A dedicated bearer's access is restored only when three things hold
(`BearerRuntime::restoreAccess` in `src/lte/ue/bearer_runtime.hpp`):

* the EBI being restored is this bearer's EBI,
* the linked EBI is the current default EBI,
* the access generation matches, and the default bearer can already forward.

`MobilityContext::canForwardUserPlane()` requires the default bearer to be
`USER_PLANE_READY`, which is set **only when a real TUN exists**. Without a TUN
the dedicated restoration is refused and the radio message is dropped. This is
deliberate: §5.3 of the work that established it required transport readiness
before a dedicated bearer is declared restored, and the TUN gate is how the
production code enforces it. It is not a test-only switch and must not be
relaxed to make a control-plane test pass.

Both bearers then send `BEARER_TRANSPORT_READY`, each naming its own EBI and
each bound to the access generation of the round that restored it. A
confirmation that names a stale generation is refused.

## 8. TEID freshness and retirement

Every restoration allocates a **fresh pair** of local S1-U TEIDs, one per
bearer, through the same allocator as any other establishment
(`UeRegistry::allocateLocalTeid` → `bindLocalTeid`). Nothing reuses a previous
round's identifier; the allocator is monotonic and never reissues.

The previous pair is retired when the access is released
(`UeRegistry::retireLocalTeid`), so it stops resolving immediately and is
recorded in the bounded retired-TEID ledger. The consequences that matter:

* a delayed G-PDU naming a previous round's TEID is dropped and classified as
  retired-TEID traffic; it cannot reach the new tunnel, because the new tunnel
  has a different identifier;
* an End Marker naming a previous round's TEID is recorded against a retired
  tunnel and changes nothing — in particular it does not release or modify the
  bearer that now owns the UE;
* a fresh TEID's packet counters start at zero and accumulate only what that
  tunnel actually carried.

The last point needs care, because the *bearer* counters deliberately survive
an access release: `releaseAccessTransport` does not touch `m_counters`, only
`release()` does. So the honest per-round check is a **delta** — each round
moves exactly one packet per direction per bearer, and the running totals read
1/1, 2/2, 3/3. A fresh TEID is not credited with traffic it never carried, and
the bearer's lifetime total is not reset by an access release.

### SGW-side TEIDs are not measured here

The three-round privileged case delivers a different SGW-side TEID on every
round (`0x1E`/`0x1F`/`0x20` for the default and `0x24`/`0x25`/`0x26` for the
dedicated), but those values are **authored by the test** in the E-RAB items.
That is not a measurement of a real SGW.

Phase 15's live campaign observed a **constant** SGW-TEID `0x0000AF88` across
three restorations. Whether a real SGW changes its downlink TEID when only the
access transport is restored is therefore **not determined by this phase** and
must not be read off either result as a property of the EPC.

## 9. Generation-bound readiness

Both ends count access epochs. The eNB's `UeRegistry::entry.accessGeneration`
and the UE's `MobilityContext::accessGeneration` must stay in step, because the
UE's readiness confirmations are bound to the generation they belong to.

The two counters can drift if one side advances alone. The known hazard is a
bearer-less Tracking Area Update: the MME opens and closes an S1 connection
that never carried a bearer. `UeRegistry::releaseS1` therefore advances the
generation **only** when the entry actually held a bearer
(`s1 == BEARER_ACTIVE`), and a release that never carried one is silent at the
radio. That is what keeps the TAU's close from putting the two counts out of
step and making the first page's generation-bound message look stale.

The measured sequence in the three-round case is 1, 2, 3: the TAU leaves both
ends at generation 1, the first restoration confirms at generation 1, the
release advances both to 2, and so on. Both the default and the dedicated
bearer of a round confirm at that round's generation — a dedicated bearer never
confirms at a generation its default did not.

## 10. User-plane classification and forwarding

Uplink: a packet leaving the UE's TUN is classified against the retained TFTs.
A match goes out on that dedicated bearer's local TEID; no match goes out on
the default bearer's. The eNB receives it on the UE link and forwards it as a
G-PDU to the bearer's SGW address and TEID.

Downlink: a G-PDU from the bearer's SGW naming that bearer's local TEID is
delivered to the UE's TUN. A G-PDU naming an identifier that does not resolve
is dropped and classified (retired or unknown) and never reaches any UE.

Per-bearer proof therefore means four observations per round:

| Direction | Bearer | What must be seen |
|---|---|---|
| uplink | default | a G-PDU on the default bearer's SGW TEID |
| uplink | dedicated | a G-PDU on the **dedicated** bearer's SGW TEID, not the default's |
| downlink | default | the datagram appears on the UE's TUN |
| downlink | dedicated | the datagram appears on the UE's TUN |

The three-round case opens three kernel sockets on the UE's PDN address so the
two flows are distinguishable end to end: a default flow that matches no
filter, a dedicated uplink that matches the uplink filter, and a dedicated
downlink that matches the downlink filter's shape and is received on its own
socket. The uplink proof is the TEID each G-PDU is sent under.

## 11. Failure and negative behaviour

These are the refusals a change must keep. They are split between the existing
paging and target-side suites and the two new cases in
`test/lte/ue_mobility_target.cpp`.

**Paging guards** (`EvaluatePaging` in `src/lte/ue/paging.cpp`, in order):
not registered → no security → no identity → identity mismatch → already
connected → bearer unavailable → procedure pending → area mismatch → accepted.
Each produces `Paging indication ignored: <reason>` and starts nothing. The
paging-refusal case drives all of the reachable ones through the **real S1AP
dispatcher** on stream zero:

* a page for the Attach-era M-TMSI is ignored as `IDENTITY_MISMATCH` and opens
  no context;
* a page outside the registered TAI is filtered by the eNB's TAI check and is
  never fanned out;
* a second page while a Service Request is already outstanding is not
  delivered again — the entry is not `IDLE_RETAINED`;
* a page while the UE is ECM-CONNECTED is not delivered either, for the same
  reason;
* one valid page opens exactly one Service Request.

**Bearer restoration refusals** (existing suites in `test/lte/mobility_target.cpp`
and `test/lte/ue_paging_wait.cpp`): an unknown E-RAB is not established; a
duplicated E-RAB identity fails the whole setup; invalid QoS is refused; a
declaration that contradicts the retained default is refused; source TEIDs
resolve nowhere; a stale radio frame is refused; two UEs are not mixed.

**Dedicated activation refusals** (`test/lte/ue_mobility_target.cpp`): duplicate
EBI, wrong linked EBI and malformed TFT each leave the default bearer alone.

**Lifecycle failures** (`test/lte/ue_paging_wait.cpp`): an unanswered Service
Request times out and is retried within its bound; shutdown during a paging
Service Request is clean; shutdown during a later restoration is clean; S1
access loss inside a later cycle is recovered without a re-Attach; a
retransmitted answer repeats the frozen declaration or the compact form rather
than inventing a third.

**Stale transport**: delayed G-PDUs and delayed End Markers for previous rounds'
TEIDs are dropped and classified, and touch nothing (§8).

## 12. Exact test coverage

All of the following are in `test/lte/ue_mobility_target.cpp` unless noted.

| Case | Kind | What it proves |
|---|---|---|
| a real UE reselection reaches a real target eNB and completes a TAU there | deterministic | the Normal TAU bootstrap this scenario is built on |
| a repeated mobility uplink is refused by the target without disturbing its context | deterministic | the target will not accept a second mobility uplink for the same UE |
| a network-activated dedicated bearer keeps the non-empty TFT it was given | deterministic | the real Open5GS TFT vector is decoded through the production NAS path and retained, filters=2, QCI and linked EBI as assigned |
| an unusable dedicated bearer activation is refused and leaves the default bearer alone | deterministic | duplicate EBI, wrong linked EBI and malformed TFT are each refused without partial state |
| a page that must not start a Service Request is refused at the right boundary | deterministic | the Paging guards above, driven through the real S1AP dispatcher |
| real TUN mobility restoration and user-plane round trip | privileged TUN | the pre-existing one-round TUN case; kept unchanged as a regression |
| a dedicated bearer with a non-empty TFT survives three paging restorations on a real TUN | privileged TUN | the three-round scenario end to end, with per-bearer user-plane traffic on every round |

Suites that this record relies on but does not own:

| Suite | Covers |
|---|---|
| `test/lte/ue_paging_wait.cpp` | three consecutive restorations with no re-Attach, unanswered paging, shutdown during a restoration, S1 loss, retransmitted answers |
| `test/lte/mobility_target.cpp` | target-side E-RAB negatives, multi-UE isolation, stale frames |
| `test/lte/tft.cpp` | the Open5GS TFT vector's decode |
| `test/lte/gtpu_end_marker.cpp` | End Marker semantics, TEID retirement and delayed-packet isolation |
| `test/lte/multi_ue.cpp`, `test/lte/restoration.cpp` | bearer lifecycle and TEID-index invariants |

### What the three-round privileged case asserts

For each of rounds 1, 2 and 3:

* the page was delivered by the real fan-out (`notificationsDelivered` rises);
* the UE produced exactly one Service Request for it, in the right form;
* both bearers came up, with the network-assigned EBI and linked EBI;
* the E-RAB list was delivered dedicated-first and the roles still came out
  right;
* both `BEARER_TRANSPORT_READY` confirmations named that round's generation;
* one packet per direction per bearer moved, on the right TEID;
* a fresh local TEID pair, distinct from every previous one.

And across the three:

* exactly one inventory-form answer and exactly two compact answers;
* one Attach Request and one Attach Complete in the whole run;
* all six local TEIDs pairwise distinct;
* a delayed G-PDU and an End Marker naming round 1's TEIDs after round 3 are
  dropped and classified, and round 3's bearers are untouched;
* the TUN, its route, the default route and the pre-existing network
  namespaces are exactly as they were.

The case is `doctest::skip()`ped and runs only under
`UNIRANSIM_RUN_PRIVILEGED_TUN_TESTS=1` with `--no-skip`, in a private network
namespace with a real `/dev/net/tun`, and prints `UNIRANSIM-PHASE17-PRIVILEGED-EXECUTED`
and `UNIRANSIM-PHASE17-PRIVILEGED-COMPLETE`. The CI job greps for both, so a
skipped run cannot be mistaken for a pass.

## 13. Live Open5GS evidence and its limitations

**No live Open5GS dedicated multi-round campaign was run in this phase.**

The three-round behaviour described above is proven by a privileged TUN
integration against a scripted network peer and a test SGW endpoint. That peer
builds the S1AP messages the production code consumes and terminates the GTP-U
tunnels; it is not the Open5GS MME, SGW or PCRF. Nothing here is a live EPC
result, and the deterministic and privileged evidence must not be reported as
one.

The one live result this record leans on is from an earlier phase and is
narrower than this scenario: a real Open5GS Paging-driven restoration of a
default bearer across three access epochs, which is where the constant SGW-TEID
`0x0000AF88` observation comes from (§8). It did not involve a dedicated bearer
and is not evidence for one.

Creating a live dedicated bearer requires a PCC rule on the subscriber, and
that is separately authorization-gated. The authorization used by an earlier
phase was spent and rolled back; it is not standing authorization. Without a
fresh, explicit authorization naming the subscriber, the APN/session, the rule
scope, the backup procedure, the rollback and the verification, no PCC rule is
applied or reapplied, no PCRF or HSS data is touched, and no live dedicated
bearer is created. The live gate is therefore recorded as
**`BLOCKED_AUTHORIZATION`** rather than as a pass.

### Limitations

* **The network peer is a test peer.** Message timing, retransmission policy,
  MME state machine quirks and SGW behaviour are not exercised beyond what the
  peer scripts.
* **SGW-side TEID behaviour across restorations is not measured** (§8).
* **Only one dedicated bearer per round.** A session with several dedicated
  bearers is supported by the same code paths but is not what the three-round
  case exercises.
* **The TFT is one real vector.** Other filter shapes, precedence conflicts and
  operation codes are covered by the TFT decode suite, not by the three-round
  case.
* **End Marker does not drain an active tunnel** — see
  `docs/gtpu-end-marker-retired-tunnel-lifecycle.md` §14. An End Marker naming
  a *retired* tunnel is the case §8 of this record uses, and it is inert by
  design.
* **TEID uniqueness is process-lifetime only.** Nothing is persisted across
  restarts.
* **No live campaign, no live capture, no live TEID table.** Anything of that
  kind is absent, not pending measurement.
