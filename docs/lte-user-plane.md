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
the encrypted NAS result to the E-RAB. `BEARER_RELEASED` closes UE TUN resources.
Direction, UE identity, peer endpoint, type, and length are checked before use.

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
  namePrefix: uniransim-lte
  mtu: 1400
  routes:
    - 10.45.0.1/32       # replace with the authorized EPC test endpoint
```

## Build and run

```bash
cmake -S . -B cmake-build-phase3 -DCMAKE_BUILD_TYPE=Release
cmake --build cmake-build-phase3 --parallel 2
ctest --test-dir cmake-build-phase3 --output-on-failure

sudo ./cmake-build-phase3/lte-enb -c config/open5gs-lte-enb.yaml
sudo ./cmake-build-phase3/lte-ue -c config/open5gs-lte-ue.local.yaml
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

## Supported scope

Supported: one LTE UE, one default bearer, IPv4, EEA0/EEA2 NAS security, S1-U
GTP-U, persistent TUN forwarding, context cleanup, and packet/drop counters.

Not supported: multiple UEs or PDNs, dedicated bearers, IPv6/IPv4v6 forwarding,
TAU, paging, Service Request, handover, RF/SDR, IMS/VoLTE, QoS scheduling, or
GTP-U kernel offload.
