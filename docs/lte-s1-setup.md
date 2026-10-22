# LTE eNB S1 Setup

`lte-enb` implements the Phase 0 LTE control-plane vertical slice: an SCTP association to an MME followed by a
non-UE-associated S1AP S1 Setup Request on stream 0. It accepts the connection only after decoding and validating an
S1 Setup Response, and reports S1 Setup Failure causes and TimeToWait.

## Build and run

```bash
cmake -S . -B cmake-build-lte-s1 -DCMAKE_BUILD_TYPE=Release
cmake --build cmake-build-lte-s1 --parallel 2
./cmake-build-lte-s1/lte-enb -c config/open5gs-lte-enb.yaml
```

Set `mcc`, `mnc`, `enbId`, `tac`, `s1apIp`, and the MME endpoint in the YAML file to values served by the EPC. MNC is
kept as a string so that a two-digit MNC such as `02` is not confused with the three-digit MNC `002`. `enbId` is the
20-bit macro eNB ID. `pagingDrx` accepts 32, 64, 128, or 256. Retry counts and finite connect/response timeouts are under
`sctp`.

The transport uses Linux SCTP, destination port 36412 by default, PPID 18 in network byte order, and SCTP stream 0.
Terminate with SIGINT or SIGTERM for a clean socket shutdown.

## Open5GS verification

Start packet capture before the simulator (only when authorized to use the interface):

```bash
sudo tcpdump -i any -nn -s 0 -w /tmp/lte-s1-setup.pcap 'sctp port 36412'
./cmake-build-lte-s1/lte-enb -c config/open5gs-lte-enb.yaml
tshark -r /tmp/lte-s1-setup.pcap -Y s1ap -V
```

Confirm an S1SetupRequest containing Global-ENB-ID, SupportedTAs, and DefaultPagingDRX, followed by an S1SetupResponse.
The simulator must log `S1_SETUP_ESTABLISHED`; an SCTP association alone is not success.

## Scope and provenance

The implementation reuses UERANSIM's Linux SCTP client, YAML utilities, build infrastructure, and test runner. The
focused APER codec was implemented from the S1 Setup ASN.1 constraints in 3GPP TS 36.413; no source or generated codec
was copied from an external project. Encoding behavior was compared with Magma S1APTester commit
`0d739923068c0c6cffdb042ddba56b70c5aaf76c` and srsRAN 4G commit
`bef8680d5f9714f3e040e6f9cbc88d7888439b6d`. The response test fixture is attributed inline to srsRAN 4G (AGPL-3.0-or-later)
and is protocol data rather than incorporated implementation source. Project code remains under UERANSIM's existing
GPL-3.0 license.

LTE UE, EPS NAS, authentication, attach, bearer setup, S1-U, RRC, and radio layers are deliberately unsupported. The
next development stage is LTE UE initial NAS signalling and EPS AKA preparation; none of that functionality is included
here.
