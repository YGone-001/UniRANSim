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

### SGW-side TEIDs are constant across access restorations

The three-round privileged case delivers a different SGW-side TEID on every
round (`0x1E`/`0x1F`/`0x20` for the default and `0x24`/`0x25`/`0x26` for the
dedicated), but those values are **authored by the test** in the E-RAB items.
They are not a measurement of a real SGW and say nothing about what one does.

Phase 15's live campaign observed a **constant** SGW-TEID `0x0000AF88` across
three restorations of a default bearer.

Phase 17-B then measured it directly against live Open5GS, with a dedicated
bearer present, across three Paging-triggered restorations after a single
registration. The SGW-side S1-U TEID was **constant** for the whole session:

| | establishment | round 1 | round 2 | round 3 |
|---|---|---|---|---|
| default bearer SGW-TEID | `0x0000DA40` | `0x0000DA40` | `0x0000DA40` | `0x0000DA40` |
| dedicated bearer SGW-TEID | `0x000037F6` | `0x000037F6` | `0x000037F6` | `0x000037F6` |
| default bearer eNB-TEID | `0x4D40293D` | `0x4D40293F` | `0x4D402941` | `0x4D402943` |
| dedicated bearer eNB-TEID | `0x4D40293E` | `0x4D402940` | `0x4D402942` | `0x4D402944` |

So the two ends do not move together. The eNB-side pair is fresh on every
restoration, exactly as the allocator contract above requires. The SGW-side
identifier is the bearer's, not the access's, and survives every access release
for the life of the bearer. That is what the S5/S8-U side shows too: its TEIDs
are stable for the same reason.

This is a property of the measured implementation, not a claim about every EPC.
A phase that needs a different behaviour has to measure it again.

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

The three-round behaviour described above was first proven by a privileged TUN
integration against a scripted network peer and a test SGW endpoint. That peer
builds the S1AP messages the production code consumes and terminates the GTP-U
tunnels; it is not the Open5GS MME, SGW or PCRF. That deterministic and
privileged evidence is what the code is written against and is still the
regression bar. It was never a live EPC result.

A live Open5GS dedicated multi-round campaign has since been run under
separate, explicit PCC authorization, and produced the following. Each line is
what the live trace showed, not what the test suite asserts:

* One EPS registration and **three** genuine S1AP UE Context Release
  procedures (`user-inactivity` Request, Command, Complete), each opening an
  ECM-IDLE epoch. No round re-Attached and there was no reauthentication.
* One real network-created dedicated EPS bearer: EBI 6, linked to EBI 5, QCI 7
  on **both** the NAS and the S1AP side, with the two-filter UDP TFT, activated
  once and retained across all three releases.
* Three MME-initiated Pagings addressed to this UE's own S-TMSI, each answered
  by exactly one protected EPS Service Request bearing the security context
  from the original Attach (same KSI, distinct short MACs).
* Three restorations, each restoring **both** E-RABs, and each carrying
  independent bidirectional user-plane traffic on both bearers.
* The SGW-side TEID measurement in §8.

Two things the live campaign did **not** establish, and which must not be
filled in from the deterministic results:

* **The answer form was the compact Service Request in all three rounds**, not
  the bearer-inventory form in round 1. That is the correct form here: the cell
  had already confirmed the bearer roles during the initial Attach, so
  `MobilityContext::accessBootstrap` was `ROLES_RETAINED` before the first
  page. A cell that has never confirmed the roles still needs the inventory.
  The form is a property of confirmed role ownership, never of a round number.
* **Retired-tunnel isolation was not probed live.** No G-PDU was injected, so
  no rejection of a retired identifier is claimed from this campaign.

### The three rounds at frame level

A later read-only reconciliation decoded the campaign's own captures and
established each round against specific frames. The methodology matters more
than the numbers, because it is what makes the numbers checkable.

**Separate the establishment from the restorations.** The establishment is one
Attach, one Initial Context Setup carrying the **default** bearer, and then a
**separate E-RAB Setup** carrying the dedicated bearer. Each restoration is
different: it re-establishes **both** E-RABs inside a **single** Initial Context
Setup, and never re-Attaches. So an E-RAB Setup for EBI 6 appears exactly once
in the session, at establishment, and the three restorations carry EBI 5 and
EBI 6 together.

**Establish the association first.** The capture was taken at the MME, so it
contains every eNB's association. Ours is `10.10.0.139:34533 ↔ 10.10.0.139:36412`;
the pre-existing cell at `10.10.0.138:36412` shares the TAI and contributes its
own attaches and restorations on a disjoint TEID series and with different
QCIs. Every claim must be scoped to one association before any frame number
means anything. Paging makes this sharp: **each Paging is transmitted twice**,
one copy per eNB serving the TAI, so a paging event appears as an adjacent frame
pair and only the copy addressed to our association is ours.

**Two bridges join the S1AP and GTP-U captures, and they must agree.** Relative
times cannot be joined — the captures do not share a zero point. First, both
record `frame.time_epoch` on one host clock, so every frame can be placed on an
absolute axis. Second, each user-plane probe log records its own send wallclock
and its source UDP port, and those two values select exactly one GTP-U frame.
The two bridges agreed to within ±30 ms on every frame, a constant
print-before-capture offset.

**Distinguish probes from triggers.** A downlink datagram is sent to the PDN
interface to make the SGW buffer traffic for an idle UE and the MME page it.
That *trigger* is later delivered on the new default eNB TEID, immediately after
the restoration, which is genuine evidence that a buffered downlink arrived on
the restored tunnel — but it is the same datagram as the stimulus and is **not**
an independent restoration probe. Counting it as one inflates the per-round
evidence. Per round the independent probes are four: default uplink, default
downlink, dedicated uplink, dedicated downlink, and the dedicated pair must
travel the dedicated bearer's own TEIDs.

The measured frame map for the campaign of record is:

| Event | s1ap.pcap frames | eNB-UE-S1AP-ID | MME-UE-S1AP-ID |
|---|---|---|---|
| UE A Attach, default E-RAB 5 | 5, 17, 19 | 2 | 466 |
| dedicated E-RAB 6 setup | 23, 25 | 2 | 466 |
| round 1: release / Paging / Service Request / ICSR | 98-100 / 102 / 103 / 104-105 | 2→3 | 466→471 |
| round 2: release / Paging / Service Request / ICSR | 203-205 / 208 / 209 / 210-211 | 3→4 | 471→478 |
| round 3: release / Paging / Service Request / ICSR | 271-273 / 276 / 277 / 278-279 | 4→5 | 478→481 |

Each round releases the context the **previous** round created, so the identity
chain is unbroken across the session.

### Residual limitations of the live evidence

* **A constructed G-PDU is not a genuine SGW-generated G-PDU.** Nothing in the
  campaign originated from the authenticated SGW path for the purpose of testing
  the receive path. Any future probe sent from a test-owned socket must be
  labelled `LIVE_ENB_RECEIVE_PATH_WITH_TEST_OWNED_INJECTOR` and must not be
  described as proof of SGW peer authenticity.
* **`S1uEndpointCounters::retiredTeidDrops` has no runtime reporting surface**
  — **this finding is historical and is now resolved.** At the time of the
  Phase 17-C campaign the counter was declared in `s1u_endpoint.hpp`, incremented
  on the retired branch of `handleGPdu`, and asserted in-process by the
  deterministic tests — but the shared S1-U statistics line printed `malformed`
  and `unknown-teid` only. The drop was logged with its own distinct message, so
  the classification was observable live; the numeric counter delta required to
  prove the counter moved was not. That was an observability gap in the
  reporting surface, not a functional defect, and it did not affect the
  acceptance of Phase 16 or 17. **Retired-TEID runtime observability
  prerequisite resolved; live active rejection remains
  `BLOCKED_AUTHORIZATION`.** The counter now has two surfaces reading one field —
  `retired-total=N` appended to the retired-drop warning and
  `drops(retired-teid)=N` appended to the shared shutdown line — as recorded in
  `docs/gtpu-end-marker-retired-tunnel-lifecycle.md` §11. Resolving the
  observability prerequisite does not itself close B-G17, which remains
  `PARTIAL`, and it is not a live rejection result (§ "Limitations" below).
* **Capture windows are not identical.** One control probe fell outside the
  GTP-U capture's window and is evidenced only at the UE TUN. Silence is not
  evidence: the absent frame is a capture-scope fact and proves nothing about
  the network.

Creating a live dedicated bearer requires a PCC rule on the subscriber, and
that is separately authorization-gated. An authorization is spent once used and
is not standing authorization. Without a fresh, explicit authorization naming
the subscriber, the APN/session, the rule scope, the backup procedure, the
rollback and the verification, no PCC rule is applied or reapplied, no PCRF or
HSS data is touched, and no live dedicated bearer is created. Any campaign that
finds itself in that position records the live gate as **`BLOCKED_AUTHORIZATION`**
rather than substituting a deterministic result for it.

### Limitations

* **The network peer is a test peer.** Message timing, retransmission policy,
  MME state machine quirks and SGW behaviour are not exercised beyond what the
  peer scripts, and the live campaign covers one EPC build, not all of them.
* **Only one dedicated bearer per round.** A session with several dedicated
  bearers is supported by the same code paths but is not what either the
  three-round case or the live campaign exercises.
* **The TFT is one real vector.** Other filter shapes, precedence conflicts and
  operation codes are covered by the TFT decode suite, not by the three-round
  case.
* **End Marker does not drain an active tunnel** — see
  `docs/gtpu-end-marker-retired-tunnel-lifecycle.md` §14. An End Marker naming
  a *retired* tunnel is the case §8 of this record uses, and it is inert by
  design.
* **TEID uniqueness is process-lifetime only.** Nothing is persisted across
  restarts.
* **Retired-tunnel isolation has no live positive probe.** The deterministic
  suite proves the drop-and-classify path; no live G-PDU has been sent against a
  retired identifier, so no live rejection is claimed. The runtime
  observability of `retiredTeidDrops` is now in place, so a later authorized
  probe can measure the counter delta across a bounded window without shutting
  the endpoint down — but the counter surface is a measurement instrument, not
  the probe, and it is not evidence of a live rejection on its own.

## 14. Dedicated Bearer QoS Consistency and Evidence Provenance

A dedicated bearer keeps its QoS across a restoration, so the network must state
one QoS for one bearer identity wherever it states one at all. This section
records what was found, what the rule is, and what the evidence behind the
fixtures actually is.

1. **What was wrong.** The capture-backed dedicated bearer — EBI 6, linked to
   default EBI 5 — was played with **QCI 9** in the NAS Activate Dedicated EPS
   Bearer Context Request and **QCI 7** in the S1AP E-RAB that established and
   restored it. Same EBI, two QCI values, in the same test file. The source of
   the capture records QCI 7 on both sides, so the NAS side of the fixture had
   drifted away from the evidence it was named after.

2. **What the two sides carry.** The NAS EPS quality of service (TS 24.301
   §9.9.4.3) is what the UE is sent: QCI, and bitrate octets in the extended
   form. The S1AP E-RAB Level QoS Parameters (TS 36.413 §9.2.1.15) carry the
   QCI and the AllocationAndRetentionPriority. They are different messages with
   different scopes, and the QCI is the field they share.

3. **Per-bearer QoS identity.** The QoS is part of the identity that survives an
   access release, along with the EBI, the linked default EBI and the TFT. The
   fixture states it per bearer: `ActivateDedicated` takes the QCI as an
   argument with no default, and a scripted activation list is a list of
   (EBI, QCI) pairs rather than a list of EBIs. A case with two dedicated
   bearers therefore plays two QCIs — EBI 6 on QCI 7 and EBI 9 on QCI 8 in the
   reselection case — and they cannot blur together.

4. **Explicit NAS QCI in the test fixtures.** No fixture may reach a dedicated
   activation through a hidden QCI 9. The capture-backed bearer is played at
   `kCapturedDedicatedQci`, the default bearer at `kDefaultQci`, and the second
   dedicated bearer at `kSecondDedicatedQci`, all named constants beside the
   capture they belong to.

5. **Corresponding S1AP E-RAB QCI.** The E-RAB that establishes or restores a
   dedicated bearer names the same QCI the NAS activation named. In the
   three-round case the target's own bearer registry is read back after each
   restoration: default EBI 5 at QCI 9 and dedicated EBI 6, linked EBI 5, at
   QCI 7, on every round.

6. **ARP is S1AP-side only.** AllocationAndRetentionPriority — priority level
   15, pre-emption capability false, pre-emption vulnerability false in these
   fixtures — is encoded and decoded in the S1AP E-RAB Level QoS Parameters and
   is never part of the EPS QoS Profile sent to the UE. The NAS activation has
   no field that could carry it. The values are left at the E-RAB helper
   defaults and are not adjusted to look more realistic.

7. **GBR and MBR follow the bearer type.** GBR QoS Information (TS 36.413
   §9.2.1.18) is present for a GBR bearer only. QCI 7 ("voice, video,
   interactive gaming") and QCI 9 ("TCP based") are both non-GBR in TS 23.203
   table 6.1.7-1, so these E-RABs carry no GBR QoS Information and none is
   invented. Full GBR bearer support is not implemented and is not claimed.

8. **Legitimate QCI remapping needs evidence.** A different QCI on the two sides
   is not universally impossible — roaming and inter-RAT handover can produce
   one — but a remapping claim must be backed by explicit signalling or
   configuration. For the same-PLMN scripted restoration these cases play, with
   no such evidence, the network-authored NAS activation and the corresponding
   S1AP E-RAB use the same dedicated-bearer QCI. No remapping is invented to
   excuse a mismatch.

9. **A captured TFT is not a captured NAS message.** The captured artefact is
   the TFT value field and the bearer identity metadata beside it: EBI 6,
   linked default EBI 5, QCI 7, and the same QCI in the S1AP E-RAB Setup
   Request. The enclosing NAS Activate Dedicated EPS Bearer Context Request is
   **constructed** by the test's `ActivateDedicated`, and the S1AP E-RAB items
   are constructed too. The production UE then decodes that envelope with its
   own NAS decoder. No packet capture is claimed for the envelope and no
   byte-for-byte equivalence with one is claimed.

10. **What the tests observe.** The consistency is read out of the production
    decoders rather than out of the fixture's own expectations. A deterministic
    case encodes the activation and the E-RAB, decodes them with
    `nas::DecodeDownlink` and `s1ap::DecodeErabSetupRequest`, and requires the
    two decoded QCIs to be equal. The live cases then observe the UE's own
    report of the QoS it decoded, and the three-round case reads the target's
    registry back after each restoration. Measured on the privileged run:
    `Dedicated EPS bearer 6 activated (QCI=7, linked-EBI=5, filters=2)`, and
    per round `default ebi=5 qci=9 … | dedicated ebi=6 linked=5 qci=7 …`.

No production code was changed for this. The production NAS decoder already
reads the QCI out of the EPS quality of service, the production S1AP codec
already round-trips QCI and ARP and the presence or absence of GBR QoS
Information, and the UE runtime already stores the decoded QCI on the bearer.
The defect was in the test fixture's inputs and nowhere else.

11. **What live Open5GS does to a non-GBR rule that names a rate.** A real PCC
    rule for a non-GBR QCI must carry **no `mbr` and no `gbr` at all**. Naming
    one without the other makes the real MME advertise a QoS combination this
    eNB has to refuse.

    The mechanism, in Open5GS's own code: `mme-s11-handler.c` runs its bitrate
    clamp whenever **any** of the four bitrate components is non-zero, and
    raises every zero component to `OGS_MAX_BITRATE_S1AP` (10 Gbps).
    `s1ap-build.c` then emits `gbrQosInformation` whenever **all four** are
    non-zero. A rule carrying `mbr` 200 kbps and no `gbr` therefore leaves the
    MME advertising `e-RAB-GuaranteedBitrateDL/UL` = 10 Gbps against
    `e-RAB-MaximumBitrateDL/UL` = 200 kbps.

    Measured on the live EPC, and this is the whole failure, in two messages:

    ```
    E-RABSetupRequest  (e-RAB-ID 6)
        e-RABlevelQoSParameters
            qCI: 7
            allocationRetentionPriority  priorityLevel 8, shall-not-trigger-
                pre-emption, not-pre-emptable
            gbrQosInformation
                e-RAB-MaximumBitrateDL/UL     200000 bits/s
                e-RAB-GuaranteedBitrateDL/UL  10000000000 bits/s
    E-RABSetupResponse
        Cause: radioNetwork/invalid-qos-combination
    ```

    The NAS EPS quality of service in the same request disagreed with that
    anyway — an extended-2 form giving 200 kbps MBR against 8 640 kbps /
    256 Mbps / 10 000 Mbps GBR — so the two places the network states one
    bearer's QoS were not even the same fabrication.

    The refusal is correct and was kept. `ErabQos::valid()` requires
    `guaranteedDl <= maximumDl` and `guaranteedUl <= maximumUl`, and
    AGENTS.md requires that a non-GBR QCI be given no fabricated GBR values.
    Nothing was relaxed to make the bearer come up.

    With **both** bitrate fields absent the clamp is skipped, the
    `gbrQosInformation` IE is not emitted at all, and the NAS EPS quality of
    service takes its basic one-octet QCI-only form. That is the shape this
    record already calls correct for QCI 7, and it is what a live campaign must
    request of its policy rule. This is a rule of the *laboratory policy*, not
    a change to production code; the production QoS validation is what caught
    it.
