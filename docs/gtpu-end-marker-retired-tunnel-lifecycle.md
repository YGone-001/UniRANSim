# GTP-U End Marker handling and retired tunnel lifecycle

Design record for the eNB GTP-U receive path: which message types are
recognised, what an End Marker does and does not do, how a tunnel becomes
active and retired, and why a packet that outlived its tunnel can never reach
the wrong UE.

This record covers receive-side handling only. It does not describe handover,
Path Switch, Indirect Data Forwarding or any other procedure, and nothing in
the implementation generates or transmits an End Marker.

## 1. Message types

TS 29.281 table 6.1-1 assigns the GTP-U message types. The decoder in
`src/lte/enb/gtpu.cpp` accepts exactly four:

| Type | Name | Meaning here |
|---|---|---|
| 1 | Echo Request | answered by the endpoint |
| 2 | Echo Response | ignored |
| 254 (0xFE) | End Marker | control message about one tunnel |
| 255 (0xFF) | G-PDU | the only user-plane payload |

Anything else is rejected at decode. Values 32–253 are reserved in the
specification and are not guessed at.

## 2. End Marker semantics

TS 29.281 §7.3.2: *"The End Marker message indicates the end of the payload
stream on a given tunnel, i.e. a G-PDU that arrives after an End Marker message
on this tunnel may be silently discarded."* Table 7.3.2-1 lists Private
Extension as the message's only optional information element; there are no
mandatory information elements and no Recovery IE.

The wire form is the mandatory eight-octet header and nothing else when the E,
S and PN flags are clear. The TEID field carries **the identifier of the tunnel
being retired** — it is not zero. The reference vector used throughout the
tests is a genuine Open5GS SGW-U End Marker captured during the Phase 15
campaign (`artifacts/p15-campaign/run-p15-20261103-131408/gtpu.pcap`, frame 8):

```
30 fe 00 00 c6 b5 5b 7a
```

Flags `0x30` (version 1, PT 1), message type `0xfe`, length `0`, TEID
`0xc6b55b7a`. The eight-octet size is a consequence of the optional-header
rules of §5.1, never a hardcoded length.

**What an End Marker does not do here.** It is not a release, not a bearer
transition and not a handover authorisation. §7.1 forbids treating it as one,
and this implementation does not: an End Marker on a tunnel that is still up
leaves that tunnel exactly as it was. Tunnel retirement is the explicit S1
release path described in §6 below.

## 3. Header and information-element validation

`gtpu::Decode` validates, for every message type:

* version `0x20` under mask `0xE0`, protocol-type bit `0x10` set, reserved flag
  `0x08` clear;
* the declared length equals the number of octets after the mandatory header;
* the four-octet optional block is present if and only if one of E, S or PN is
  set, and the Next Extension Header value is consistent with the E flag;
* an extension-header chain is well formed, is at most 16 entries long, and
  uses only the supported types `0x40`, `0x85`, `0xC0`, `0xC1`, `0xC2`.

**End Marker S flag.** TS 29.281 V14.0.0 §5.1 states: *"In an End marker
message the S flag shall be set to '0'."* This implementation adopts that as
a strict LTE receive profile: an End Marker whose S flag is set is refused at
decode, and there is no runtime compatibility switch that relaxes it. The rule
is deliberately a later release's requirement rather than a back-dated one.
V9.3.0 (Release 9) §5.1 lists the messages whose S flag shall be '1' — Echo
Request, Echo Response, Error Indication and Supported Extension Headers
Notification — and the messages for which it should be '0', and it is simply
silent about the End Marker, which that release did not yet carry. The change
history records CR 0033 *"End Marker message"* (CT#50, December 2010) taking
9.3.0 to 10.0.0; the V10.0.0 text itself was not available to this record, so
no claim is made about the exact wording of that release. The E and PN flags
and the extension-header rules are unchanged by this policy, because no End
Marker-specific rule in the specification restricts them.

Per type it then applies the TEID rule:

* **G-PDU** — non-zero TEID and a non-empty payload. TS 29.281 §7.1: *"A G-PDU
  shall not include any information element."*
* **End Marker** — non-zero TEID, and the remainder must be empty or a
  sequence of well-formed Private Extension information elements. The
  information-element area is validated and then withheld from the caller, so
  `Packet::payload` is empty for an End Marker and can never be mistaken for
  user-plane data.
* **Echo Request / Echo Response** — zero TEID (TS 29.281 §7.2 addresses them
  to the endpoint itself).

### Private Extension wire form

TS 29.281 figure 8.6-1 gives the Private Extension this shape (identical in
V9.3.0 and V14.0.0):

| Octets | Field |
|---|---|
| 1 | Type = 255 (decimal, `0xFF`) |
| 2–3 | **Length**, 16-bit, network byte order |
| 4–5 | **Extension Identifier**, 16-bit, network byte order |
| 6–m | **Extension Value**, variable, opaque |

§8.1: *"The Length field contains the length of the information element
excluding the Type and Length field."* Length therefore counts the Extension
Identifier **and** the whole Extension Value, so a valid element has
`Length >= 2` and occupies `3 + Length` octets in total. §8.6: the Extension
Identifier *"is a value defined in the Private Enterprise number list in the
most recent 'Assigned Numbers' RFC"* — an IANA Private Enterprise Number, not
a TEID, a bearer identifier or a UE identifier. It is validated structurally
and never interpreted. *"A signalling message may include more than one
information element of the Private Extension type."*

Two worked shapes: the minimal element `FF 00 02 12 34` (Length 2, Extension
Identifier `0x1234`, empty Extension Value), and `FF 00 04 12 34 AA BB`
(Length 4, the same identifier, a two-octet Extension Value).

The decoder walks the area on that basis: fewer than three octets left is a
truncated element; a Length below 2 is shorter than its own Extension
Identifier; `3 + Length` running past the end of the area is an overrun; and a
type other than `0xFF` is unsupported. The older one-octet-length reading of
this element is wrong and is not what the code accepts: it would read
`FF 02 AA BB` as a complete element of Length 2, whereas the specification
reads it as Length `0x02AA` and rejects it as truncated.

## 4. Dispatch: G-PDU and control messages are separate

`S1uEndpoint::handleDatagram` is the single GTP-U entry point. After decoding
it switches on the message type:

* Echo Request is answered inline on the shared socket.
* Echo Response is dropped.
* **End Marker** goes to `handleEndMarker`, which only ever reads state and
  moves observation counters.
* **G-PDU** goes to `handleGPdu`, the only path that forwards to a UE.
* anything else is counted as an unsupported message and dropped.

The separation is structural rather than a flag: there is no code path by which
a control message reaches `m_ueLink.TrySend`, the frame encoding, or the
user-plane packet counters. `Packet::payload` for an End Marker is empty as
well (§3), so even a hypothetical future mistake has nothing to forward.

## 5. Tunnel states

A local S1-U TEID is in exactly one of three states:

* **active** — present in `UeRegistry::m_byLocalTeid` and owned by one bearer
  of one UE. The bearer may be *signalling established* (the TEID resolves but
  `active()` is false, so datagrams are dropped as inactive) or *forwardable*
  (the UE has confirmed transport readiness and `active()` is true).
* **retired** — absent from `m_byLocalTeid` and present in the
  `RetiredTeidLedger`. The tunnel's access transport has been released.
* **unknown** — neither. Either never issued, or issued and since aged out of
  the bounded ledger.

A bearer becomes active in two stages. `DefaultBearerContext::establish` binds
the transport and sets `signalingEstablished`; `activateUe`, which runs on the
UE's own `BEARER_TRANSPORT_READY` / `BEARER_READY` / `BEARER_ACTIVATED`
confirmation, is what makes it forwardable. Until then downlink datagrams are
dropped and counted as `bearerInactiveDrops`.

## 6. Retirement

Every path that stops a tunnel from resolving goes through
`UeRegistry::retireLocalTeid`, which erases the live index entry and records
the identifier as retired:

* `releaseS1` — S1 Context Release and any other access release. The S1AP
  identifiers, `sgwPeer` and every local TEID of the default and dedicated
  bearers are retired; the **logical EPS bearer contexts are retained** (this
  is the ECM-IDLE semantics the idle-restoration work established) and the UE
  entry stays in `IDLE_RETAINED` for a later Service Request.
* `releaseBearer` — an E-RAB Release Command deletes one bearer or, for the
  default EBI, the whole PDN connection.
* `deleteBearerContexts` — the UE's NAS deletes the session.
* `unbindLocalTeid` — releases this entry's local TEID. For a live mapping it
  retires the identifier through `retireLocalTeid`. For a value that is not a
  live mapping of this entry — the rollback of an Initial Context Setup whose
  response could not be transmitted — it drops the reservation instead, and
  retires nothing, because no tunnel of this registry ever existed to retire.
  Either way the identifier is never offered again (§7).

`DefaultBearerContext::releaseAccessTransport` then zeroes `localTeid`,
`sgwTeid` and `sgwAddress` on the bearer itself.

## 7. TEID allocation and reuse protection

A wire TEID is 32 bits and zero is reserved, so at most `2^32 - 1` distinct
identifiers exist. `TeidSequence` (`src/lte/enb/user_plane.cpp`) hands them
out over a bounded issuance window and cannot hand one out twice.

* The sequence is seeded at random and advances a 64-bit **step** counter. The
  value for step *n* is `seed + n + 1` in explicitly 32-bit modular
  arithmetic, so consecutive steps name consecutive 32-bit patterns and all of
  them are distinct.
* Zero is reserved and is never returned. The step that would have produced it
  is spent rather than retried, so it cannot be reserved twice and cannot
  cause a repeat. This costs at most one step.
* A step is reserved with a compare-exchange, so two callers never take the
  same step, and the counter is never advanced past the end of the window.
* **Exhaustion fails closed.** Once the window is spent, `next()` throws
  `TeidExhausted` and returns nothing. It never returns zero, never returns a
  previously issued value, never overwrites a live mapping and never clears a
  retirement record. Because the counter stops at the window, exhaustion is
  sticky: the sequence cannot wrap open again.

`AllocateLocalTeid()` is the one production sequence, with the whole non-zero
32-bit space as its window. **The no-reissue guarantee is process-lifetime
only.** Nothing is persisted, so a later run may issue an identifier an
earlier run used, and no cross-restart uniqueness is claimed.

### The reservation contract

Uniqueness comes from the allocator alone. `UeRegistry` does not keep a
history of what has been issued; it keeps only the values currently in flight.

* `allocateLocalTeid()` draws a candidate and **reserves** it. It refuses a
  candidate that is zero, already live in `m_byLocalTeid`, or still recorded
  as retired in the `RetiredTeidLedger`, and it is bounded so that a
  pathological injected allocator fails deterministically rather than looping.
* `bindLocalTeid()` accepts **only** a value this registry reserved. It
  refuses a zero identifier, a value that is not reserved, a value already
  owned by another bearer, and — absolutely — a value still recorded as
  retired.
* A reservation is consumed by a bind, dropped by an `unbindLocalTeid`
  rollback, and dropped defensively by `retireLocalTeid`. A failed
  establishment therefore leaks nothing and leaves no half-built bearer.

Without the reservation check, `bindLocalTeid` would be an open setter and any
caller could attach an identifier of its own choosing, bypassing the
allocator's no-reissue guarantee. There is deliberately **no revival API**:
nothing withdraws a retirement record, and a retired identifier is never
rebound to a live tunnel, so a delayed packet of an old tunnel can never
resolve against a new one.

### The ledger is an observation aid

`RetiredTeidLedger` (`DefaultCapacity`, 4096) records only the identifier and
the order in which it was retired. It holds no UE identity, no peer address
and no subscriber information. When it is full the longest-retired record is
dropped first.

**It is not an allocation guarantee and the code does not rely on `contains()`
to decide eligibility.** After a record ages out the identifier is still
unusable: it is not reserved, so it cannot be bound, and the allocator is
monotonic and has already spent its step, so it is never offered again. What
eviction does change is only the *classification* of a very late packet, which
moves from "traffic that outlived its tunnel" back to "a packet that never had
one". Neither is delivered.

## 8. Delayed and stale packets

A G-PDU whose TEID does not resolve is classified before it is dropped:

* retired TEID → `retiredTeidDrops`: traffic that outlived its tunnel. Nothing
  is written anywhere except the drop counter — no UE entry, no bearer, no
  counter of any UE is touched.
* unknown TEID → `unknownTeidDrops`: a packet that never had a tunnel.

Neither is forwarded, and neither can reach the tunnel a later access opened,
because that tunnel has a different identifier (§7).

## 9. End Marker handling

`handleEndMarker` classifies the named identifier and moves only observation
counters:

* **active tunnel** — the peer must be the bearer's SGW (`sgwAddress:2152`) or
  the message is dropped as an unexpected peer. Otherwise
  `endMarkerActiveTunnels` and the bearer's `counters().endMarkers` rise, and
  the tunnel is left up. A repeat raises `duplicateEndMarkers` as well and
  changes nothing else.
* **retired tunnel** — the natural case, and the one an S1 release produces.
  `endMarkerRetiredTunnels` rises. A repeat lands here too and changes nothing
  at all, which is what makes reordered or duplicated announcements idempotent.
* **unknown TEID** — `endMarkerUnknownTunnels` rises and no state is created:
  no bearer, no tunnel, no UE entry, and nothing added to the ledger.

An End Marker never reaches the UE link, is never counted as user-plane payload
in either direction, and never creates, releases or rebinds a bearer.

## 10. Peer validation and multi-UE isolation

Every datagram that resolves to a bearer is checked against that bearer's
expected peer, `InetAddress(sgwAddress, 2152)`, before anything else happens.
A mismatch is dropped and counted on the owning UE as `unexpectedPeerDrops`.
The check is per bearer, so a datagram naming one UE's TEID can never be
handled in the context of another UE. The lookup itself is by local TEID, which
is unique across concurrently active bearers and is never shared.

An End Marker naming an unknown or retired TEID is dropped before any peer
comparison, because there is no bearer whose peer could be compared against —
and no state is created on any UE either way.

## 11. Rejection accounting

| Counter | Meaning |
|---|---|
| `S1uEndpointCounters::malformedDrops` | decode failed, or Echo Request without a sequence number |
| `S1uEndpointCounters::echoRequests` | Echo Requests answered |
| `S1uEndpointCounters::unknownTeidDrops` | G-PDU naming a TEID that never existed |
| `S1uEndpointCounters::retiredTeidDrops` | G-PDU naming a retired TEID |
| `S1uEndpointCounters::unsupportedMessageDrops` | recognised-but-unhandled message type |
| `S1uEndpointCounters::endMarkers` | End Markers recognised, all cases |
| `S1uEndpointCounters::endMarkerActiveTunnels` | End Markers naming a live tunnel |
| `S1uEndpointCounters::endMarkerRetiredTunnels` | End Markers naming a retired tunnel |
| `S1uEndpointCounters::endMarkerUnknownTunnels` | End Markers naming a TEID that never existed |
| `EnbUeEntry::counters.unexpectedPeerDrops` | datagram from a peer that is not the bearer's SGW |
| `EnbUeEntry::counters.bearerInactiveDrops` | G-PDU for a bearer that is not yet forwardable |
| `BearerPacketCounters::endMarkers` | End Markers recognised on this tunnel |
| `BearerPacketCounters::duplicateEndMarkers` | repeats of one already recognised on this tunnel |

## 12. Source files

| File | Role |
|---|---|
| `src/lte/enb/gtpu.hpp`, `gtpu.cpp` | GTP-U codec, message types, header and IE validation |
| `src/lte/enb/s1u_endpoint.hpp`, `s1u_endpoint.cpp` | shared endpoint, dispatch, forwarding |
| `src/lte/enb/user_plane.hpp`, `user_plane.cpp` | `AllocateLocalTeid`, `RetiredTeidLedger`, bearer contexts |
| `src/lte/enb/ue_registry.hpp`, `ue_registry.cpp` | TEID index, allocation, binding, retirement |

## 13. Where this is verified

`test/lte/gtpu_end_marker.cpp` holds the End Marker and retired-tunnel cases:
the genuine capture vector; header, optional-field and information-element
validation including the S-flag policy and the Private Extension wire form; the
per-type TEID and payload rules; the ledger's own behaviour; retirement through
S1 release and through an E-RAB release; the reservation contract and its
refusals; the issuance window, its exhaustion and concurrent draws; delayed
G-PDU and delayed End Marker isolation both before and after a retirement
record has aged out; duplicate and unexpected-peer End Markers; bearer
readiness; the endpoint's own guards; and multi-UE isolation. The tests drive
`S1uEndpoint::handleDatagram` directly against loopback UDP endpoints, so a
datagram either reaches a UE endpoint or it does not — that is what makes "the
End Marker never reaches the TUN" an observation rather than an assertion about
counters.

The tests reach the window boundary and the eviction path through the same
code a bearer runs: `TeidSequence` is the sequence `AllocateLocalTeid()`
itself instantiates, and the ledger capacity is a constructor parameter that
only a test lowers.

Line coverage of these four source files is 93.7% (612 of 653 lines). What is
left uncovered is either pre-existing error handling outside this record, the
`default:` dispatch branch that the message-type whitelist makes unreachable,
or defensive early returns that no public call can reach.

Existing suites (`test/lte/multi_ue.cpp`, `test/lte/restoration.cpp`,
`test/lte/modify.cpp`, `test/lte/user_plane.cpp`) cover the bearer lifecycle
and the TEID-index invariants this record relies on.

## 14. Known limitations

* **An End Marker does not drain an active tunnel.** TS 29.281 §7.3.2 permits a
  receiver to discard a G-PDU that arrives after an End Marker on that tunnel.
  This implementation does not, because discarding implies retiring the tunnel
  and retiring an active tunnel on an End Marker alone is out of scope here. A
  G-PDU that arrives after an End Marker on a live tunnel is still forwarded,
  and the End Marker is recorded. The consequence is that a peer which sends an
  End Marker and then continues to send on the same tunnel will have that
  traffic delivered; a peer that sends an End Marker and then stops is
  unaffected either way.
* **No End Marker is generated.** Nothing in the implementation encodes or
  transmits one. The tests build the wire form directly, anchored on the
  captured vector.
* **The retired-TEID ledger is bounded.** An identifier whose record has aged
  out is classified as an unknown TEID rather than a retired one. It is still
  never delivered, and it is still never re-issued (§7).
* **TEID uniqueness is process-lifetime only.** Nothing is persisted, so a
  later run may issue an identifier an earlier run used. No cross-restart
  uniqueness is claimed or provided.
* **No live-lab End Marker claim.** Whether a genuine Open5GS End Marker is
  observed in a given live capture is recorded per capture and is not implied
  by this record.
