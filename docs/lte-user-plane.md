# LTE IPv4 user plane

UniRANSim's LTE path supports one UE, one IPv4 PDN connection, and one default
EPS bearer. NAS remains on S1-MME/SCTP. User IPv4 packets use a separate LTE
radio-link frame and GTPv1-U over S1-U/UDP.

```text
application <-> uniransim-lte0 <-> lte-ue <-> DATA_* UDP <-> lte-enb
            <-> GTP-U T-PDU/UDP 2152 <-> Open5GS SGW-U
```

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
resources. Direction, UE identity, peer endpoint, type, and length are checked
before use.

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
  scenario: attach-only     # detach | service-request | tau-normal | tau-periodic
  triggerAfterMs: 2000
  procedureTimeoutMs: 5000
  maxRetries: 3
  switchOff: false          # detach only; normal acknowledged Detach is preferred
```

For `service-request`, the trigger first sends a standards-valid S1AP UE Context
Release Request with `radioNetwork/user-inactivity`; the UE waits for the MME's
Release Command and eNB Release Complete before sending Service Request. Logs
separately report ECM-IDLE and restoration. Keep one UE/eNB pair per run.

## TUN and route policy

The UE takes its IPv4 address from Activate Default EPS Bearer Context Request,
creates `/dev/net/tun` with `IFF_TUN|IFF_NO_PI`, assigns the address as `/32`,
sets the configured MTU, and keeps the descriptor open until release or shutdown.
The default prefix creates `uniransim-lte0`. `CAP_NET_ADMIN` (normally `sudo`) is
required. IPv6 and IPv4v6 data-plane operation are rejected because they do not
provide a supported non-zero IPv4 address.

No route is installed by default and the host default route is never replaced.
Optional `tun.routes` entries are explicit IPv4 CIDRs only; `0.0.0.0/0` is
rejected. The UE records routes it successfully added and removes only those
routes at cleanup. A safe controlled test configuration is:

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
cmake -S . -B cmake-build-phase4 -DCMAKE_BUILD_TYPE=Release
cmake --build cmake-build-phase4 --parallel 2
ctest --test-dir cmake-build-phase4 --output-on-failure --no-tests=error

sudo ./cmake-build-phase4/lte-enb -c config/open5gs-lte-enb.yaml
sudo ./cmake-build-phase4/lte-ue -c config/open5gs-lte-ue.local.yaml
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

## Supported scope

Supported: one LTE UE, one default bearer, IPv4, EEA0/EEA2 NAS security, S1-U
GTP-U, persistent TUN forwarding, context cleanup, and packet/drop counters.

Not supported: multiple UEs or PDNs, dedicated bearers, paging-driven
mobile-terminated service, inter-MME mobility, handover, IPv6/IPv4v6 forwarding,
RF/SDR, IMS/VoLTE, QoS scheduling, or GTP-U kernel offload.
