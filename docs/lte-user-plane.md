# LTE IPv4 user plane

UniRANSim's LTE path supports multiple concurrently attached UEs, each with one
IPv4 PDN connection and one default EPS bearer. NAS remains on S1-MME/SCTP.
User IPv4 packets use a separate LTE radio-link frame and GTPv1-U over S1-U/UDP.

```text
application <-> uniransim-lte0 <-> lte-ue(A) <-> DATA_* UDP <-> lte-enb
            <-> GTP-U T-PDU/UDP 2152 <-> Open5GS SGW-U
application <-> uniransim-lte0 <-> lte-ue(B) <-> DATA_* UDP <-> lte-enb (same)
```

## Multi-UE architecture

One `lte-enb` process multiplexes every concurrent UE over three shared
transports: the single S1AP SCTP association to the MME, one simulated
radio-link UDP listener, and one shared S1-U GTP-U endpoint. Each UE is a
separate `lte-ue` process with its own subscriber identity, NAS security
context, TUN device, and lifecycle. The eNB never stores subscriber
credentials; it forwards NAS transparently.

Per-UE state lives in a bounded registry (`maxUes`, default 8) indexed by
radio UE ID, verified UDP peer, eNB-UE-S1AP-ID, MME-UE-S1AP-ID, and local
GTP-U TEID. The eNB UE S1AP ID is allocated monotonically per S1 connection,
skips zero, and wraps without colliding with a live context. A UE Context
Release clears that UE's S1AP IDs and TEID mapping while the registry entry
is retained (`IDLE_RETAINED`) for a later Service Request or re-Attach; the
other UEs and both shared sockets are untouched. Every inbound UE-associated
S1AP message must resolve through these indexes — including the MME-ID-only
variant of UE Context Release Command — and inconsistent identity pairs are
rejected without falling back to "the only registered UE".

UE-associated S1AP signalling is spread across the negotiated non-zero
outbound SCTP streams by eNB-UE-S1AP-ID; stream zero stays reserved for
non-UE procedures such as S1 Setup, and UEs share streams when the
negotiated count is smaller than the UE count. Per-UE ordering is preserved
because each UE's messages always use the same stream.

The simulated radio identity (`ueId` in the UE YAML, default 1) is carried in
every radio-link frame and must be unique among concurrently running `lte-ue`
processes. The eNB rejects a duplicate radio identity, a UDP endpoint that
claims another UE's identity, and an existing identity arriving from a new
endpoint. Distinct radio UE IDs alone do not make two processes distinct
subscribers; each must use its own authorized IMSI and credentials.

## S1-U addressing and TEIDs

`s1u.address` in the eNB YAML is both the local bind address and the address
advertised in Initial Context Setup Response. It must be a concrete IPv4 address
owned by the eNB host and reachable from SGW-U. `0.0.0.0` is rejected. Loopback
is appropriate only when eNB and SGW-U share the same network namespace, and
requires the explicit `s1u.allowLoopback: true` acknowledgement.

The SGW-U address and uplink TEID come from Initial Context Setup Request; they
are not copied from the MME address. Uplink T-PDUs use the SGW receiving TEID.
Downlink T-PDUs must use the monotonically allocated eNB receiving TEID that was
advertised in Initial Context Setup Response. The SGW-U UDP port is the standard
2152. Packets from another endpoint or with an old/unknown TEID are dropped.

All concurrent default bearers share the single eNB S1-U socket: downlink
T-PDUs are demultiplexed by the locally allocated receiving TEID to exactly one
UE bearer — never by EBI or by the most recently established bearer — and each
release removes only that UE's TEID mapping. Two UEs may both use EBI 5; their
bearers remain independently mapped by TEID.

The decoder accepts the ordinary eight-byte T-PDU header and bounded, valid
optional sequence, N-PDU, and supported extension-header chains. It rejects
wrong versions, protocol type, reserved flags, length mismatches, truncated or
unknown extensions, and unsupported message types. Echo Requests with a sequence
number receive an Echo Response; control messages never enter the UE TUN.

## LTE data-link framing

The version-1 frame header contains message type, UE identity, and exact payload
length. `NAS_UPLINK`/`NAS_DOWNLINK` retain Phase 2 signaling. `DATA_UPLINK` and
`DATA_DOWNLINK` carry one unchanged IPv4 packet. `BEARER_READY` conveys the
accepted EBI and assigned IPv4 address after TUN setup, allowing the eNB to bind
the encrypted NAS result to the E-RAB. `S1_CONTEXT_RELEASE_REQUEST`,
`S1_CONTEXT_RELEASED`, and `S1_CONTEXT_RESTORED` distinguish an ordinary ECM
release from bearer deletion. The legacy `BEARER_RELEASED` alone closes UE TUN
resources. `PAGING_INDICATION` is the downlink-only simulated paging occasion
described below. Direction, UE identity, peer endpoint, type, and length are
checked before use.

## EPS lifecycle

The LTE UE tracks mobility registration, S1 connectivity, and bearer readiness
independently. `EMM_REGISTERED` may coexist with `ECM_IDLE`; in that state the
GUTI, NAS keys and COUNTs, assigned IPv4 address, logical default bearer, and
TUN are retained, but no user packet is forwarded. A UE Context Release removes
the current S1AP IDs and GTP-U TEIDs. A subsequent Service Request uses security
header type 12, the native KSI, five-bit sequence number, and EIA2 short MAC in
an Initial UE Message. Initial Context Setup allocates a fresh eNB S1AP ID and
eNB TEID before forwarding resumes.

Normal Detach sends a protected GUTI-based Detach Request and waits for a
verified Detach Accept. Only then are registration, security, bearer, routes,
and TUN cleared. Switch-off Detach is available explicitly and does not wait for
an acknowledgement. Requests use a bounded timeout and retransmit the identical
protected PDU, so a retry does not consume a second NAS COUNT.

Normal and periodic TAU retain the Attach-assigned GUTI, TAI list, T3412 value,
KSI, security context, EBI, and PDN address. TAU Request includes EPS bearer
context status. Context changes are applied only after an integrity-verified TAU
Accept; a new GUTI causes a protected TAU Complete. TAU Reject fails the scenario
without inventing success. `tau-periodic` is an explicitly accelerated lab
trigger, not a claim that the encoded T3412 interval elapsed. `tau-normal` must
only be used with a real authorized TAI-change arrangement.

The optional deterministic scenario block is:

```yaml
lifecycle:
  scenario: attach-only     # detach | service-request | paging | tau-normal | tau-periodic
  triggerAfterMs: 2000
  procedureTimeoutMs: 5000
  maxRetries: 3
  pagingWaitMs: 60000       # paging only; bounded wait for a network page
  switchOff: false          # detach only; normal acknowledged Detach is preferred
```

For `service-request`, the trigger first sends a standards-valid S1AP UE Context
Release Request with `radioNetwork/user-inactivity`; the UE waits for the MME's
Release Command and eNB Release Complete before sending Service Request. Logs
separately report ECM-IDLE and restoration. Keep one UE/eNB pair per run.

`paging` shares that release sequence but deliberately stops there: after
ECM-IDLE the UE sends **no** Service Request on its own and only responds to a
verified network paging indication. This is the scenario for network-triggered
service restoration; see the Phase 6 section below.

## Network-triggered paging (Phase 6)

Phase 6 adds network-initiated service restoration: a real downlink IPv4 packet
addressed to an ECM-IDLE UE makes the EPC page that UE, and only the matching UE
answers with an authenticated Service Request.

```text
downlink IPv4 to the idle UE address
        -> PGW-U / SGW-U  (Downlink Data Notification)
        -> MME            (S1AP Paging, procedure 10, stream 0)
        -> lte-enb        (decode, TAI filter, bounded fanout)
        -> lte-ue         (S-TMSI match, ECM-IDLE preconditions)
        -> compact EPS Service Request -> Initial UE Message
        -> Initial Context Setup -> fresh eNB TEID -> IPv4 forwarding
```

### S1AP Paging decoding

`DecodePaging` in `src/lte/enb/codec.cpp` parses the Paging initiating message
with the existing APER primitives and validates it fail-closed. It rejects a
wrong procedure code, a non-initiating PDU kind, a wrong PDU criticality, every
truncation of a valid PDU, missing or duplicate mandatory IEs, an unexpected IE
criticality, non-canonical ten-bit alignment, a zero M-TMSI, an extended CHOICE,
a non-decimal IMSI, a TAI item with the wrong identifier, an oversized TAI
collection and unknown reject-critical IEs.

The information elements and their wire identifiers are:

| IE | id | Criticality | Handling |
|---|---|---|---|
| UE Identity Index value | 80 | ignore | `INTEGER (0..1023)`, ten bits in the two most significant bits of two octets |
| UE Paging Identity | 43 | ignore | `CHOICE { s-TMSI, iMSI }`; s-TMSI is `MMEC` (8 bits) then an octet-aligned 32-bit M-TMSI |
| CN Domain | 109 | ignore | `ps-domain` is the only value acted upon |
| TAI list | 46 | ignore | `SEQUENCE OF ProtocolIE-SingleContainer`; each item is `id-TAIItem` (47) wrapping a PLMN + TAC |
| Paging DRX | 137 | ignore | optional; recorded but not used for radio timing |

That layout was not guessed: a live Open5GS 2.8 MME page captured on the lab S1
interface was decoded with the reference ASN.1 dissector, which reported
`UEIdentityIndexValue=1`, s-TMSI `MMEC=1` / `M-TMSI=0xC00007C4`, `ps-domain`,
one TAI `460/02/TAC=1`. The captured 43-octet PDU is an automated fixture
(`test/lte/paging.cpp`), and `EncodePaging` reproduces it byte for byte.

The UE Identity Index value is a paging-frame input derived from the subscriber
identity, never a paging identity. It is decoded and range-checked but never
used to decide whether a page belongs to a UE.

### Tracking area and identity filtering

The eNB forwards a page only when the received TAI list contains an exact
`(PLMN, TAC)` match for its configured serving cell. A page for another PLMN or
another TAC is counted and dropped. The eNB never invents an MME-UE-S1AP-ID and
never inspects NAS: it has no NAS identity for any UE.

CS-domain pages and IMSI-addressed pages are counted and dropped explicitly.
IMSI paging is **not** supported in this phase; it is never reinterpreted as an
S-TMSI.

### Simulated radio paging

Because the software radio link has no broadcast medium, the eNB sends one
`PAGING_INDICATION` frame to every retained idle UE radio endpoint, bounded by
`maxUes`. The frame payload is fixed at seven octets:

```text
MMEC(1) || M-TMSI(4, big endian) || served TAC(2, big endian)
```

Each UE re-derives its own S-TMSI from its assigned GUTI (type octet must be a
GUTI, MMEC and M-TMSI are both compared) and answers only on a full match. A UE
that is `EMM-DEREGISTERED`, `ECM-CONNECTED`, missing its security context or
GUTI, missing its logical default bearer, or holding any pending mobility
procedure ignores the indication without changing state. This is a laboratory
abstraction: it is not an RRC Paging message, has no paging frames, no DRX
timing and no air-interface authentication, and must never be described as one.

### NAS reuse and pending state

An accepted page enters `SERVICE_REQUEST` and sends the existing compact EPS
Service Request (security header type 12, native KSI, five-bit sequence, EIA2
short MAC). One accepted page advances the uplink NAS COUNT exactly once; a
duplicate page during the pending procedure is ignored, so it neither sends a
second request nor consumes a second COUNT. A page never makes the bearer
active by itself, and ECM-IDLE never resets the NAS COUNT.

### Downlink trigger procedure

```bash
sudo ./cmake-build-phase6/lte-enb -c config/open5gs-lte-enb.yaml
sudo ./cmake-build-phase6/lte-ue  -c config/open5gs-lte-ue-paging.local.yaml
# wait for State=ECM_IDLE, then send real traffic to the assigned address
ping -c 2 10.45.0.118
```

Run the probe from a host or namespace whose route to the UE address actually
enters the EPC user plane. On an all-in-one Open5GS host the PGW-U `ogstun`
address is on-link, so a probe to the assigned UE address traverses
PGW-U -> SGW-U -> eNB.

**The UE TUN must not live in the same namespace as the probe.** If it does, the
assigned UE address becomes a *local* address of that host and the kernel answers
the probe itself: the ping succeeds in ~0.04 ms and no downlink packet, no
Downlink Data Notification and no Paging ever exist. That is a false positive and
must never be reported as paging evidence. Move each UE TUN into its own
namespace before probing:

```bash
# after lte-ue created <tun> with <ue-ipv4>
ip netns add p6ns7
ip netns exec p6ns7 ip link set lo up
ip link set <tun> netns p6ns7          # moving a link flushes its IPv4 address
ip netns exec p6ns7 ip addr add <ue-ipv4>/32 dev <tun>
ip netns exec p6ns7 ip link set <tun> up
ip netns exec p6ns7 sysctl -qw net.ipv6.conf.<tun>.disable_ipv6=1
ip netns exec p6ns7 ip route add 10.45.0.0/16 dev <tun>
ip route get <ue-ipv4>                 # must report dev ogstun
```

Then `ping <ue-ipv4>` from the host produces real EPC round trips (tens of
milliseconds, not microseconds), and `ip netns exec p6ns7 ping -I <tun>
10.45.0.1` exercises the uplink direction. Disabling IPv6 on the TUN avoids
harmless router-solicitation frames that the IPv4-only uplink validator rejects.

Verify the path rather than assuming it: if the EPC never emits Paging, the fault
is on the EPC side and no S1AP decoder change can fix it.

The first trigger packet may be discarded while the S1-U downlink TEID is gone;
the MME then pages from the Downlink Data Notification. Acceptance therefore
requires that real traffic triggers the page, that the page restores service,
and that subsequent mobile-terminated packets reach the UE TUN. Whether the
original trigger packet is buffered and delivered depends on the deployed EPC
buffering policy and is recorded per run, never assumed.

### Diagnostics

The eNB reports, at shutdown and per page:

```text
S1AP Paging statistics: received=1 valid=1 invalid=0 cs-domain=0 imsi-unsupported=0
                        tac-filtered=0 notified=1 notify-failures=0
```

The UE reports:

```text
Paging statistics: indications=1 matched=1 ignored=0 service-requests=1
                   restorations=1 restoration-failures=0
```

A notification-delivery counter is not evidence of restoration. The decisive
evidence is the Service Request, the Initial Context Setup with a fresh
eNB-UE-S1AP-ID and TEID, and IPv4 bytes arriving on the UE TUN.

### Known paging limitations

- No RRC paging channel, paging frames, DRX scheduling or paging-area broadcast.
- IMSI paging is rejected explicitly; only S-TMSI paging is supported.
- The eNB pushes a notification to idle radio endpoints instead of broadcasting
  over a cell, and the simulated link provides no radio authentication.
- The paging wait timeout is a laboratory bound; MME paging retries are owned by
  the EPC and are only observed, never configured.

## TUN and route policy

The UE takes its IPv4 address from Activate Default EPS Bearer Context Request,
creates `/dev/net/tun` with `IFF_TUN|IFF_NO_PI`, assigns the address as `/32`,
sets the configured MTU, and keeps the descriptor open until release or shutdown.
The default prefix creates `uniransim-lte0`; concurrent UEs receive distinct
kernel suffixes (`uniransim-lte0`, `uniransim-lte1`, ...) because allocation
scans the interfaces that already exist. `CAP_NET_ADMIN` (normally `sudo`) is
required. IPv6 and IPv4v6 data-plane operation are rejected because they do not
provide a supported non-zero IPv4 address.

No route is installed by default and the host default route is never replaced.
Optional `tun.routes` entries are explicit IPv4 CIDRs only; `0.0.0.0/0` is
rejected. The UE records routes it successfully added and removes only those
routes at cleanup — closing UE A's TUN never touches UE B's interface, address,
or routes. A safe controlled test configuration is:

```yaml
tun:
  required: true
  namePrefix: uniransim-lte
  mtu: 1400
  routes:
    - 10.45.0.1/32       # replace with the authorized EPC test endpoint
```

`tun.required` defaults to `true`. Setting it to `false` permits control-plane
diagnostics on a host without `CAP_NET_ADMIN`; the UE then deliberately remains
at `BEARER_SIGNALING_ESTABLISHED`, never emits `BEARER_READY`, and never forwards
IP packets. Such a run is not user-plane or Phase 4 continuity evidence.

## Build and run

```bash
cmake -S . -B cmake-build-phase6 -DCMAKE_BUILD_TYPE=Release
cmake --build cmake-build-phase6 --parallel 2
ctest --test-dir cmake-build-phase6 --output-on-failure --no-tests=error

sudo ./cmake-build-phase6/lte-enb -c config/open5gs-lte-enb.yaml
sudo ./cmake-build-phase6/lte-ue -c config/open5gs-lte-ue.local.yaml
sudo ./cmake-build-phase6/lte-ue -c config/open5gs-lte-ue-b.local.yaml
```

One eNB serves every UE. Each `lte-ue` process needs its own ignored local
YAML with a distinct authorized subscriber, a distinct `ueId` (1, 2, ...), and
a distinct `enbLink.localPort` (4999, 5000, ...). The committed
`config/open5gs-lte-ue.yaml` and `config/open5gs-lte-ue-b.yaml` show the
synthetic pattern; never commit real credentials.

```yaml
# UE A (open5gs-lte-ue.local.yaml)      # UE B (open5gs-lte-ue-b.local.yaml)
imsi: '<authorized subscriber A>'        imsi: '<authorized subscriber B>'
ueId: 1                                  ueId: 2
enbLink:                                 enbLink:
  localAddress: 127.0.0.1                  localAddress: 127.0.0.1
  localPort: 4999                          localPort: 5000
  address: 127.0.0.1                       address: 127.0.0.1
  port: 4998                               port: 4998
```

Before running, verify the live topology rather than assuming all EPC functions
share one address:

```bash
ip -br address
ip route
ip -4 route get <sgw-u-address>
ss -lunp | grep ':2152'
grep -R -n -E 'gtpu|sgwu|pgwu|upf' /etc/open5gs
```

Use the SGW-U transport address logged from the current Initial Context Setup
Request. A bind failure usually means another process already owns the selected
eNB address/port. A peer-drop counter indicates an address or source-port
mismatch; a TEID-drop counter indicates stale or incorrectly directed GTP-U;
malformed drops identify GTP/IPv4 framing problems; inactive drops mean bearer
signaling and UE TUN readiness have not both completed.

For a controlled destination listed in `tun.routes`, verify the actual return
path with:

```bash
ping -I uniransim-lte0 <controlled-epc-ip>
sudo tcpdump -i any -nn -s 0 -w /tmp/uniransim-phase3-s1u.pcap 'udp port 2152'
sudo tcpdump -i uniransim-lte0 -nn -s 0 -w /tmp/uniransim-phase3-tun.pcap
```

Successful Attach, a bound UDP socket, or uplink counters alone are not proof of
interoperability. Acceptance requires the Echo Request to appear on the UE TUN,
uplink GTP-U with the SGW TEID, downlink GTP-U with the eNB TEID, the Echo Reply
on the UE TUN, and successful `ping` output.

### Same-host EPC acceptance

When the UE TUN and Open5GS `ogstun` are in the same network namespace, Linux
also owns the UE's negotiated `/32` locally. An apparent successful ping can
therefore bypass PGW-U and the downlink GTP-U path. Enabling `accept_local` alone
does not remove this local return-path shortcut and is not sufficient evidence
of bidirectional S1-U interoperability.

For same-host acceptance, place the live UE TUN in a temporary network
namespace (or run the UE on another host/namespace) before testing. If moving
the live TUN clears its address, restore the same `/32` address negotiated in
the current Attach; do not invent or retain an address from an older session.
After the test, stop the UE before deleting the temporary namespace and restore
any diagnostic sysctl to its original value.

## Concurrent multi-UE acceptance

With both UEs registered, move each TUN into its own isolated namespace and
ping concurrently — not sequentially — so an overlapping active period is
proven:

```bash
sudo ip netns add ueA && sudo ip link set uniransim-lte0 netns ueA
sudo ip netns add ueB && sudo ip link set uniransim-lte1 netns ueB
sudo -n ip netns exec ueA ping -I uniransim-lte0 -c 5 -W 3 10.45.0.1 &
sudo -n ip netns exec ueB ping -I uniransim-lte1 -c 5 -W 3 10.45.0.1 &
wait
```

Both UEs must independently receive all replies. Correlate the evidence per UE
from the S1-U capture (`tshark -d udp.port==2152,gtp`): UE A's uplink T-PDUs
carry SGW TEID A, UE B's carry SGW TEID B, and each downlink T-PDU uses the
eNB TEID advertised for that UE only. The eNB logs one identity and counter
block per UE on shutdown:

```text
User-plane statistics for LTE UE 1: radio-ul=… s1u-ul=… s1u-dl=… drops(…)=…
User-plane statistics for LTE UE 2: radio-ul=… s1u-ul=… s1u-dl=… drops(…)=…
Shared S1-U endpoint statistics: echo=… drops(malformed/unknown-teid)=…
```

Lifecycle isolation is verified the same way: detaching UE A (its Detach
Request accepted, bearer released, TUN closed, TEID invalidated) must leave
UE B registered and pinging; a Service Request from UE A must restore only
UE A with a fresh eNB receiving TEID; and a restarted UE A must re-Attach with
new identifiers while UE B continues. Per-UE cleanup removes only the exiting
UE's TUN, address, and routes; the shared eNB sockets and the other UE's
bearer remain until their own shutdown.

## Phase 3-A runtime acceptance record

The 2026-10-24 acceptance run used Ubuntu 24.04.5 LTS, CMake 3.28.3, GCC 13.3.0,
Clang 18.1.3, Open5GS on `192.168.64.128`, and an eNB S1-U endpoint at
`127.0.0.5:2152` in the same host namespace as SGW-U
`192.168.64.128:2152`. Loopback S1-U was explicitly enabled after confirming
the shared namespace and a GTP-U Echo Request/Response exchange with SGW-U.

The live EPC assigned `10.45.0.5/32` to `uniransim-lte0` with MTU 1400. The
decisive test moved that TUN into an isolated UE network namespace and ran:

```text
ping -I uniransim-lte0 -c 5 -W 2 10.45.0.1
5 packets transmitted, 5 received, 0% packet loss
rtt min/avg/max/mdev = 56.146/56.819/58.478/0.855 ms
```

Graceful shutdown reported matching end-to-end counters:

```text
UE:  tun-ul=17/1428 tun-dl=7/588
eNB: radio-ul=17/1428 radio-dl=7/588 s1u-ul=17/1428 s1u-dl=7/588
eNB drops(malformed/teid/peer/inactive)=0/0/0/0
```

The reproduced runtime defect was an unintended infinite wait in
`UdpServer::Receive(..., timeoutMs=0)`. The eNB blocked while polling an idle
S1-U socket, so `BEARER_READY` and `DATA_UPLINK` frames accumulated on the UE
radio-link socket. Zero-timeout UDP receive is now a genuine non-blocking poll,
covered by a focused regression test. The complete local suite contains 146
tests after that addition.

## Phase 6 runtime acceptance record

The 2026-10-26 acceptance run used Ubuntu 24.04 (kernel 6.17.0-35-generic) with
Open5GS 2.8 running natively on the same host, serving PLMN 460/02, TAC 1, MME
S1AP 10.10.0.139:36412 and SGW-U 10.10.0.139:2152. The eNB advertised the
S1-U endpoint 127.0.0.5:2152. Subscribers 460020000000007 and
460020000000008 were used; no subscriber data is recorded here.

**Single UE (IMSI ...007).** Attach established EBI 5 with eNB-UE-S1AP-ID 1,
MME-UE-S1AP-ID 487, eNB TEID `0x4E666705` and SGW TEID `0x000018B4`, and the EPC
assigned `10.45.0.169/32`. After the S1 release the UE was ECM-IDLE with no
active TEID. A host `ping` to `10.45.0.169` (route `dev ogstun`) produced a real
MME page:

```text
S1AP Paging: MMEC=0x01 M-TMSI=0xC00000E1 TAI=460/02/TAC=1 CN=ps-domain
             UE-identity-index=7; notified 1 of 1 retained idle UE(s)
```

The UE matched its S-TMSI and sent the compact Service Request; the MME created a
fresh context and the eNB allocated a fresh receiving TEID:

```text
Initial UE Message sent for LTE UE 1 with fresh eNB-UE-S1AP-ID=2
Established default bearer ... eNB-UE-S1AP-ID=2, MME-UE-S1AP-ID=490
    eNB-TEID=0x4E666706 SGW-TEID=0x000018B4
```

End-to-end delivery and counters:

```text
host ping           3/3, rtt 29.9/43.9/61.8 ms
namespace ping      5/5, rtt 39.2/54.8/70.5 ms
tcpdump <tun>       10.45.0.1 > 10.45.0.169: ICMP echo request
                    10.45.0.169 > 10.45.0.1: ICMP echo reply
UE                  tun-ul=8/672 tun-dl=8/672
eNB                 radio-ul=8/672 radio-dl=8/672 s1u-ul=8/672 s1u-dl=8/672
                    drops(malformed/teid/peer/inactive)=0/0/0/0
UE paging counters  indications=1 matched=1 ignored=0 service-requests=1
                    restorations=1 restoration-failures=0
```

**Two UEs, A idle and B connected.** A (`10.45.0.171`) was released and B
(`10.45.0.172`) stayed ECM-CONNECTED. A page for A restored only A
(eNB-UE-S1AP-ID 1 -> 3, eNB TEID `0x1897C607` -> `0x1897C609`, SGW TEID
`0x00008EBC` unchanged) and B reported `indications=0 service-requests=0` while
continuing to pass traffic. Both probes completed 3/3 with 25-62 ms round trips.

**Two UEs both idle.** A page addressed to A was fanned out to both retained idle
endpoints (`notified 2 of 2`); A matched and restored, B logged
`Paging indication ignored: IDENTITY_MISMATCH` and stayed idle. A later page for
B restored B independently, and B's final counters were
`indications=3 matched=1 ignored=2` - it observed the other UE's pages and
correctly declined them. Stale pages for retired sessions were never delivered:
the eNB reported `notified 0 of 0` for identities that no live context owned.

IPv6 router solicitations emitted on a fresh TUN before the namespace move were
rejected as non-IPv4 uplink frames (5 drops in that run); disabling IPv6 on the
isolated TUN removed the noise. The IPv4-only uplink validator fails closed.

## Dedicated bearer user-plane acceptance

A network-initiated dedicated bearer must be proved on the wire, not by the
simulator's own log. Three things have to hold at once: the uplink packet reaches
the TUN, the TFT selects the dedicated bearer, and the two bearers use different
GTP-U tunnels in both directions.

### The TUN must live in its own namespace

Testing from the host namespace cannot work when the EPC shares that host. The
EPC management address is a local address there, so `ip route get` resolves it
through the `local` table (rule 0, highest priority) and the packet is delivered
to loopback. Adding `ip route replace <epc-ip>/32 dev <tun>` writes to the `main`
table and is therefore never consulted:

```text
$ ip route get 192.168.64.128 from 10.45.0.11
local 192.168.64.128 from 10.45.0.11 dev lo uid 1001
```

A zero uplink counter in that setup says nothing about the implementation. Move
the TUN into a throwaway namespace instead, where the same address resolves
through the TUN:

```bash
sudo ip netns add p7ue
sudo ip link set uniransim-lte0 netns p7ue
sudo ip netns exec p7ue ip link set uniransim-lte0 up
sudo ip netns exec p7ue ip addr add <assigned-ipv4>/32 dev uniransim-lte0
sudo ip netns exec p7ue ip route add default dev uniransim-lte0
sudo ip netns exec p7ue ip route get <epc-ip> from <assigned-ipv4>
```

The UE process keeps working because it already holds the TUN descriptor; only
the interface moves. Confirm the route names the TUN before sending anything, and
capture on the interface inside the namespace so a silent delivery problem cannot
be mistaken for a missing packet.

### Policy wording that the EPC rejects

The flow description is an IPFilterRule. `assigned` is not accepted by this
deployment's parser, and the rejection is quiet at the policy layer:

```text
[core] ERROR: hostname ``assigned'' unknown (lib/ipfw/ipfw2.c:2858)
[upf]  ERROR: Send Error Indication [TEID:...]
```

The dedicated bearer is still created, the UE still accepts it, and the eNB still
reports it ready — but the UPF has no PDR to match, so every uplink T-PDU comes
back as an Error Indication. Use literal addresses or `any` in the filter:

```text
permit out udp from any 5000 to any 7000
permit out udp from any 7000 to any 5000
```

### Observed result

Two flows from one EPS session, distinguished only by source port:

```text
uplink   sport 7000 (TFT match)    -> SGW TEID 0x0000fe0a   (dedicated)
uplink   sport 3000 (no match)     -> SGW TEID 0x0000f461   (default)
downlink dport 7000 and 3000       -> eNB TEID 0x8b7962ef   (default)
```

The uplink proof is unambiguous: the dedicated filter and the default bearer use
different SGW receiving TEIDs on the same shared S1-U socket. The return packets
were classified by the EPC onto the default bearer, because the downlink filter
names source port 7000 while the replies originate from port 5000. That is the
network's decision, not a simulator fallback, and it is recorded as observed.

Application delivery was confirmed end to end: the UE sent, the EPC forwarded, a
UDP responder on the EPC side echoed, and the reply arrived back on the UE TUN.

### Driving a dedicated bearer from the policy interface

The policy function exposes an Rx interface, and a request can create and remove a
dedicated bearer on a live session. Two properties of this deployment shape the
procedure.

First, an Rx request does not invent a bearer. The policy function maps the media
type to a QoS class (audio to QCI 1, video to QCI 2, control to QCI 5) and then
looks for a provisioned PCC rule with that class in the subscriber record. Without
one it answers `DIAMETER_REQUESTED_SERVICE_NOT_AUTHORIZED`. A provisioned rule
with an empty flow list is not installed at attach (`if (pcc_rule->num_of_flow)`),
so the session starts with only the default bearer and the Rx request is what
brings the dedicated bearer up.

Second, the flow description is an IPFilterRule whose endpoints are read from the
network side, not from the UE. Writing the UE address after `from` produces a
downlink filter that can never match an uplink packet. The mapping this deployment
applies is:

```text
permit in  <proto>  from <ue-ip> <ue-port>  to <peer-ip> <peer-port>
        |                    |                          |
        uplink               local side                 remote side
```

Using `out` instead of `in` yields a downlink filter, and swapping the endpoints
puts the peer's port on the UE side. Both mistakes leave the bearer established
and the counters flat, which looks like a forwarding defect rather than a policy
description one.

A full lifecycle then reads as follows. The request establishes the bearer, the UE
accepts it through NAS, traffic classified by the filter takes the dedicated
tunnel, and a session termination request removes it again while the default
bearer keeps carrying everything else:

```text
E-RABSetupRequest            Activate dedicated EPS bearer context request
E-RABSetupResponse
UplinkNASTransport           Activate dedicated EPS bearer context accept
...
E-RABReleaseCommand          Deactivate EPS bearer context request
E-RABReleaseResponse
UplinkNASTransport           Deactivate EPS bearer context accept
```

The release command carries that deactivation as a NAS-PDU information element.
Two details matter when decoding it. The E-RAB list and its items are declared with
`ignore` criticality, and a decoder that insists on `reject` discards a legitimate
release. The NAS-PDU element is an OCTET STRING, so its open type still begins with
a length octet; forwarding the raw value hands the UE a buffer whose first octet is
a length instead of a security header. The item type is `id-E-RABItem`, not the
separate release item used by other procedures.

### Measured result

One EPS session, two flows distinguished only by source port, then the release:

```text
uplink  sport 7000 (TFT match)   -> SGW TEID 0x00004761   dedicated
uplink  sport 3000 (no match)    -> SGW TEID 0x0000aad7   default
downlink both flows              -> eNB TEID 0x15ae614b   dedicated
after release: sport 7000        -> SGW TEID 0x0000aad7   default
```

Both flows completed a round trip to a responder on the EPC side while the
dedicated bearer existed, and the former matching flow continued to work over the
default bearer after the release. The downlink direction used the dedicated tunnel
for both flows because the provisioned rule carried only an uplink filter; that is
the network's classification, not a simulator fallback.

### Runtime bearer removal requires a provisioned rule and an Rx client

Deleting the PCC rule from the subscriber record does not release an active
dedicated bearer: the policy function reads the database when a session is
established, so no update reaches a live session.

Removal works through the Rx interface instead. The policy function accepts a
configured Diameter peer and answers a session termination request with a charging
rule removal, which the serving gateway turns into a bearer deletion. The peer must
be declared in the policy configuration, and this build rejects the usual
`AcceptUnknownPeers` setting, so an additional client has to be listed explicitly.

## Live bearer modification

E-RAB Modify (S1AP procedure 6) changes an existing per-UE bearer. It never
allocates an EBI, receiving TEID, PDN address, TUN, or second S1-U listener.
`EnbMultiplexer` validates the active eNB/MME identity pair before looking up
each EBI in that UE's registry. A candidate bearer is validated before assignment;
each item has an independent success or failure in E-RAB Modify Response. An
unknown/released EBI reports `unknown-E-RAB-ID`, invalid QoS reports
`invalid-qos-combination`, and an unusable transport reports
`transport-resource-unavailable`. No successful item implies UE NAS acceptance.

The Modify item has an extension bit, an IE-extension presence bit, E-RAB-ID,
QoS parameters, mandatory NAS OCTET STRING, and optional IE-extension container.
It has neither the Setup item's root address/TEID nor Context Setup's optional
NAS presence bit. The NAS length is consumed exactly once. Request identities,
list and item use reject criticality; response identities, lists and items use
ignore criticality. The procedure uses reject criticality. Failure Cause uses
its actual extensible choice/enumeration encoding, including category-specific
root widths. Truncation, duplicate IEs/EBIs, invalid criticalities and unsupported
reject/notify extensions fail before state mutation.

The wire layouts and transport rules follow
[TS 36.413, clauses 8.2.2 and 9.1.3.3/4](https://www.etsi.org/deliver/etsi_ts/136400_136499/136413/16.04.00_60/ts_136413v160400p.pdf).
Independent APER fixtures in `test/lte/modify.cpp` are reproducible with
`tools/lte-modify-fixtures.py` and pycrate 0.8.1. They cover QoS, GBR, UE-AMBR,
IPv4/IPv6 Transport Information and a mixed response. They contain only synthetic
identities, addresses and NAS. Comparing these bytes is additional to C++
round-trip tests; pycrate is not a build/runtime dependency.

### QoS and transport branches

An ordinary modification stores QCI, ARP priority/pre-emption fields, and optional
GBR/MBR values (bits/second). UE-AMBR is stored per UE when applicable and at
least one E-RAB succeeds. EBI, linked EBI, PDN address, bearer kind, readiness,
local/SGW TEIDs, other bearers and counters survive a QoS-only update. QCI zero,
reserved ARP priority, missing GBR for QCI 1-4, contradictory GBR/MBR or rates
beyond the supported root range fail without replacing the old metadata.
These values describe negotiated configuration; there is no radio scheduler or
GBR throughput enforcement.

When item extension 185 (`TransportInformation`) is present, only its endpoint
is considered: accompanying QoS and NAS are ignored for that E-RAB as specified
by TS 36.413. A valid IPv4 unicast address and nonzero uplink TEID atomically
replace the selected bearer destination; its eNB receiving TEID is unchanged.
Both uplink destination selection and downlink peer checking consult that
bearer's endpoint. Other bearers keep their endpoints and the shared UDP socket.
Non-IPv4 root addresses receive a per-item transport failure. Malformed or
unsupported extended ASN.1 structures are rejected by the decoder before any
item is committed. No live transport relocation was generated in this acceptance;
independent fixtures and actual UDP socket tests validate this branch separately.

### Protected NAS and atomic TFT updates

`Modify EPS Bearer Context Request` (C9) accepts optional New EPS QoS (5B) and
TFT (36), independently or together. `Accept` is EBI/PD, PTI, CA; `Reject` adds a
mandatory **value octet** ESM cause after CB. Requests use the existing EBI;
they cannot create a bearer. Network-initiated PTI zero is supported, reserved
255 is rejected with cause 81, and an assigned PTI without a matching local
procedure is rejected with cause 47. See
[TS 24.301, clauses 6.4.3, 7.3 and 8.3.16-18](https://www.etsi.org/deliver/etsi_ts/124300_124399/124301/17.12.00_60/ts_124301v171200p.pdf).

The existing EIA2 and EEA0/EEA2 security context protects the response. Active
downlink reception verifies integrity and COUNT and rejects duplicate/new-context
headers before committing COUNT. Malformed or unauthenticated signaling cannot
change bearer state, and bad protected traffic cannot terminate a registered UE.
An authenticated malformed C9 with a complete header receives a protected Reject.
An authenticated rejected request still consumes its received downlink COUNT;
the protected Reject consumes the next uplink COUNT after sending. KSI/keys and
EPS registration are preserved.

The UE copies the complete existing configuration, validates all requested QoS
and TFT changes, prepares its protected response, and commits at one event-loop
boundary. Failed TFT updates retain the complete old filters and classification,
including when failure happens after a valid first ADD/REPLACE/DELETE item.
The classifier retains no filter pointer across events. A packet observes one
consistent TFT version, and the TUN remains open.

TFT supports CREATE_NEW, ADD_FILTERS, REPLACE_FILTERS, DELETE_FILTERS,
DELETE_EXISTING and NO_TFT_OPERATION. DELETE_FILTERS contains identifier octets,
not full filters. DELETE_EXISTING and NO_TFT_OPERATION have zero filters.
Evaluation precedence uses all eight bits; local/remote range components are
41/51. Duplicate identifiers/components, unknown targets, conflicting precedence,
invalid direction/ranges, empty wire filters, unsupported components/parameters,
trailing bytes and capacity overflow fail before commit. ESM causes distinguish
resource exhaustion (26), QoS (37), TFT semantics/syntax (41/42), invalid bearer
(43), filter semantics/syntax (44/45), malformed message (95), unsupported IE
(99), duplicate IE (100), and conflicting lifecycle state (101). The component
layouts follow
[TS 24.008, clause 10.5.6.12](https://www.etsi.org/deliver/etsi_ts/124000_124099/124008/17.09.00_60/ts_124008v170900p.pdf).

Only EPS QoS and dedicated-bearer IPv4 TFT changes are currently applied by NAS
Modify. EPS QoS values of length 1/5/9/13 retain the full bitrate-extension
octets. APN-AMBR, PCO, mapped legacy QoS and other optional Modify IEs are
explicitly rejected with cause 99; default-bearer TFT changes are rejected with
cause 41. Additional UE-initiated ESM resource procedures are not implemented.
ECM-IDLE invalidates access transport; modification requires a live S1 context.
UE TFT/QoS persists over idle, but this phase does not establish multi-E-RAB
restoration or persistence through simulator restarts. Detach clears the UE
configuration and eNB release invalidates TEID indexes.

### Real EPC acceptance, 2026-10-27 (Asia/Shanghai)

Baseline `develop` was `5cb3fe1f43ca736abb0f0486be65ea0929c831cf`, clean and
equal to `origin/develop`; the complete Release suite passed 274/274 before edits.
The extended suite has 306 cases, including independent wire fixtures, rollback,
security/replay, mixed outcomes, cross-UE isolation and actual bidirectional UDP
after bearer endpoint replacement. Full NR/LTE targets remain in the build.
The unchanged CI workflow validates GCC, Clang, ASan/UBSan and coverage on the
resulting commit; exact run/SHA evidence belongs to the final acceptance report.

Read-only inspection of the deployed 2.8-based xCloud EPC found that a repeated
AAR **in the same Rx session** updates the existing named PCC rule. PCRF compares
media flows and regenerates Charging-Rule-Install; the gateway compares bearer
QoS/filters and initiates Update Bearer rather than creating a new bearer. Merely
editing MongoDB remains insufficient to update a live session.

The user authorized one temporary, empty-flow QCI 1 rule on the existing test
subscriber's internet APN, preserving its QCI 7 rule. The original policy was
privately backed up before adding the rule; no PCRF configuration or service was
changed. AAR created EBI 7, then repeated AARs changed bandwidth and added a port
filter. The AF, captures, subscriber configuration and endpoint scripts remain
outside Git.

During the main acceptance window, UE A retained IPv4 `10.45.0.22`, eNB/MME
identities `1/42`, default EBI 5, existing QCI 7 EBI 6 and Rx QCI 1 EBI 7.
UE B retained `10.45.0.23`, identities `2/43` and its default bearer.

| Bearer | SGW receiving TEID | eNB receiving TEID |
|---|---|---|
| UE A default EBI 5 | 00003231 | 4f80dff7 |
| UE A existing EBI 6 | 00002ff5 | 4f80dff8 |
| UE A modified EBI 7 | 000075c8 | 4f80dffa |
| UE B default EBI 5 | 0000d121 | 4f80dff9 |

Timestamp-correlated capture observations (seconds shown to six decimals):

| Local time | Observation |
|---|---|
| 01:10:05.467442 | E-RAB Modify Request, UE 1/42, EBI 7; QoS-only update to 768000 bit/s |
| 01:10:05.468130 | E-RAB Modify Response succeeds for EBI 7 |
| 01:10:05.670924 | Protected NAS Modify Accept, PTI 0; DL COUNT 6, UL COUNT 5 |
| 01:10:31.375888 | E-RAB Modify Request, same UE/EBI; QoS 1024000 bit/s plus ADD_FILTERS |
| 01:10:31.376707 | E-RAB Modify Response succeeds for EBI 7 |
| 01:10:31.583101 | Protected NAS Modify Accept; DL COUNT 7, UL COUNT 6 |
| 01:14:09.655075 | Further QoS-only Modify, 1280000 bit/s, same two-filter TFT |
| 01:14:09.862872 | Protected NAS Modify Accept; DL COUNT 8, UL COUNT 7 |
| 01:14:09.863082 | MME Update Bearer Response, message type 98, overall/per-bearer cause 16 |
| 01:14:25 | STR accepted; E-RAB Release and NAS Deactivate for EBI 7 |

The S1AP response preceded the NAS Accept; there is no extra invented
acknowledgment. The real TFT operation was **ADD_FILTERS**, not replacement:
the new uplink filter was identifier 1 (wire nibble), precedence 3, UDP,
local address UE A/32, remote test endpoint/32, local port 7101, remote port 5000.
Its existing port-7100 filter was retained. No transport extension was sent.

| UDP source port | Before TFT addition | After TFT addition | Remote replies per probe |
|---|---|---|---|
| 7100 | EBI 7 / SGW 000075c8 | EBI 7 / SGW 000075c8 | 3/3 before and after |
| 7101 | EBI 5 / SGW 00003231 | EBI 7 / SGW 000075c8 | 3/3 before and after |
| 3000 | EBI 5 / SGW 00003231 | EBI 5 / SGW 00003231 | 3/3 before and after |

After STR, both former dedicated flows used the default SGW TEID and still
received 3/3 replies. On the downlink the EPC selected EBI 7's eNB TEID for UDP
replies while that Rx bearer existed; this was the network's classification.
TUN capture, bearer-aware radio frames, GTP-U and echoed payloads corroborate
the result. There was no new Attach or EBI recreation during these modifications.

UE B had 967 consecutive Ping replies (sequence 109 through 1075, no internal
gaps) across UE A's modifications and release. Its S1AP IDs/TEIDs remained
unchanged, and no Modify/NAS exchange was addressed to it. The first 108 probes
occurred before restoring the IPv4 address after moving its TUN to the namespace
and were unsuccessful; they are excluded from the measured interval, not counted
as successful delivery. UE A's measured UDP probes totalled 54/54 round trips;
eNB A/B forwarding reported no malformed/TEID/peer/inactive drops.

A separate cleanup run with a fresh registration repeated live Modify and then
normal protected Detach; the MME accepted it and the eNB released its S1 context
and receiving TEID. A second cleanup registration detached UE B as well. These
deliberate cleanup registrations occurred after the main acceptance window.

The temporary rule was removed and compared equal to the original complete
policy. STR returned success. All test generators, AF, captures and simulator
processes stopped; test-created namespaces/TUNs were removed. Host routes and
rules matched the preflight snapshots. MME, HSS, SGW-C/U, PGW-C and PCRF kept
their original PIDs; ogstun stayed UP and the pre-existing Rx peer configuration
was retained. Private captures/backups were preserved outside the repository.

Live replacement/deletion of individual TFT filters and real SGW transport
relocation were NOT EXECUTED; deterministic rollback, replacement, deletion and
socket tests cover those paths. The inherited G46 multiple-E-RAB paging restore
and multi-tracking-area normal TAU limitations remain unverified.

## Supported scope

Supported: multiple concurrent LTE UEs (bounded by `maxUes`) through one eNB
with independent S1AP contexts, default bearers and TEID mappings, one default
bearer per UE, IPv4, EEA0/EEA2 NAS security, S1-U GTP-U, persistent TUN
forwarding, per-UE lifecycle isolation (Detach, ECM-IDLE, Service Request,
periodic TAU), per-UE context cleanup, per-UE packet/drop counters, real
S1AP Paging decoding with tracking-area filtering, simulated radio paging with
S-TMSI matching, network-triggered compact Service Request, restoration of
the existing default bearer, network-initiated dedicated bearers with TFT-based
uplink classification, and per-bearer GTP-U tunnels.

Not supported: RRC paging channels, paging frames and DRX radio timing, IMSI
paging, additional PDN connections, inter-MME mobility,
handover, IPv6/IPv4v6 forwarding, RF/SDR, IMS/VoLTE, QoS scheduling, GTP-U
kernel offload, or session persistence across eNB process restarts.
