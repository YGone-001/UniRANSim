# LTE production UE DRB user plane (Phase 18-F-B6-D6)

This record describes the user-plane layer added on top of the accepted
control-plane lifecycle (Attach, Detach, ECM-IDLE, Service Request, Paging). It
states what is implemented, what is exercised, and what is deliberately not
claimed.

## Layers

```
EPS bearer (NAS ESM)         src/lte/ue/nas.cpp, src/lte/ue/bearer_runtime.hpp
E-RAB (S1AP)                 src/lte/enb/codec.cpp, src/lte/enb/multiplexer.cpp
DRB identity                 drb-Identity configured by RRC
PDCP DRB12                   src/lte/security/pdcp_security.cpp
RLC AM                       src/lte/rrc-runtime/lte_am.{hpp,cpp}
Uu DTCH                      src/lte/rrc-runtime/uu_transport.{hpp,cpp}
S1-U GTP-U                   src/lte/enb/{gtpu,s1u_endpoint}.{hpp,cpp}
UE TUN                       src/lte/ue/tun.{hpp,cpp}
DRB composition              src/lte/rrc-runtime/drb_runtime.{hpp,cpp}
RRC DRB configuration        src/lte/rrc-runtime/rrc_drb_config.{hpp,cpp}
```

The mapping is:

```
EPS bearer identity (5..15)
      = E-RAB identity (the S1AP E-RAB ID)
      = DRB identity
      -> PDCP entity (DRB12, one per direction)
      -> RLC AM entity (one bearer, DTCH)
      -> Uu DTCH frame: kind(1) || drbIdentity(1) || body
```

The identities are decoded from the network's own signalling; nothing here
infers a default-versus-dedicated role from QCI or from list order. The default
DRB is configured first whatever order the E-RABs arrive in.

## RRC configuration

`EncodeDrbReconfiguration` builds a DL-DCCH `RRCConnectionReconfiguration`
whose `radioResourceConfigDedicated.drb-ToAddModList` carries, for every DRB,
`eps-BearerIdentity`, `drb-Identity`, a PDCP configuration (RLC-AM, no status
report, no header compression), an RLC AM configuration and a logical-channel
configuration. The UE answers with UL-DCCH
`RRCConnectionReconfigurationComplete`. Both messages are encoded with the
asn1c TS 36.331 V15.6.0 UPER codec already in the tree; there is no private
field standing in for a standard one.

The decoder refuses the message whole when it carries anything this layer
cannot represent: a UM RLC configuration, a missing PDCP or logical-channel
configuration, a duplicated EBI/DRB/logical-channel identity, a field outside
its enumeration, or a non-DRB body. It does not silently ignore a field.

Implementation limitation: a dedicated bearer released by S1AP releases its
DRB locally. A standard `drb-ToReleaseList` RRC message is **not** emitted yet;
the remaining DRB set continues to work and the whole set is destroyed with the
access. That gap is recorded, not hidden.

## DRB data path

One `DrbBearer` is one EPS bearer:

- uplink: IP SDU -> PDCP `Protect` (12-bit SN, EEA2 from K_UPenc) -> RLC AM
  `SubmitSdu` -> DTCH frame;
- downlink: DTCH frame -> RLC AM reassembly -> PDCP `Unprotect` -> IP SDU.

The PDCP direction follows the traffic direction, not the local role: the UE
transmits uplink and receives downlink, the eNB the reverse, so COUNT,
BEARER (DRB identity minus one) and DIRECTION agree on both ends. EEA0 is a
real selection that protects nothing; the PDU header is still emitted and the
data field is left in clear, and nothing describes that as confidentiality.
Integrity is not claimed for an ordinary UE DRB (no UP integrity profile).

The DTCH payload begins with a two-octet routing header: `kind` and the DRB
identity. `kind=1` is an RLC PDU. `kind=2` is READY, an internal simulator
control message (never 3GPP) sent by the UE once its DRBs exist; it restates the
access generation and the PDN IPv4 address its own NAS assigned. The eNB cannot
decrypt NAS, so it never invents that address; it compares the restatement with
what it already holds and refuses a contradiction.

## RLC mode and limits

The DRB uses the existing LTE **RLC AM** entity (1024 SN, 512 PDU window,
STATUS, retransmission, reassembly). RLC UM does not exist in this tree and is
not claimed. AM is reliable inside the configured retransmission threshold; a
peer that stops acknowledging eventually fails the entity rather than retrying
forever.

## S1-U integration

The eNB's DRB uplink calls the production `S1uEndpoint::forwardUplink`, which
validates the UE identity and source address, encapsulates a G-PDU with the
bearer's SGW TEID and sends it from the shared S1-U socket. A downlink G-PDU is
decapsulated, peer-validated, resolved through `UeRegistry::findBearerByLocalTeid`,
and, for a Uu UE, handed to the addressed bearer's DRB; a Uu downlink that no
DRB can carry is dropped as an inactive bearer and never falls back to the
legacy link. There is one GTP-U codec and one S1-U socket, not a second set.

## ECM-IDLE and restoration

An S1 release retires the access TEID, destroys the DRB/PDCP/RLC entities and
retains the logical EPS bearer context and the TUN address. A later Service
Request establishes a fresh local/SGW TEID pair, a fresh KeNB and K_UPenc, and a
fresh RRCConnectionReconfiguration; the UE rebuilds its DRBs from the new keys.
The same EPS bearer identity carries traffic again, and the old TEID stays
retired: a delayed G-PDU for it is classified as retired traffic and reaches no
UE.

## Evidence

- `test/lte/drb_user_plane.cpp`
  - RRC DRB configuration round trip and refusals.
  - Two production `DrbRuntime` endpoints on two real Uu UDP sockets carrying
    uplink and downlink IP packets on two EBIs, with exact payload equality,
    wrong-bearer, wrong-direction, oversized and duplicate-setup refusals.
  - The production `S1uEndpoint` carrying a DRB uplink SDU as a real GTP-U
    G-PDU to a peer on port 2152, and delivering a downlink G-PDU back through
    the DRB.
  - ECM-IDLE release, retired-TEID classification, fresh TEIDs and fresh keys
    on restoration, and resumed bidirectional traffic.
- `test/lte/handover_live_ingress.cpp` states the capability flags.
- `test/lte/enb_uu_integration.cpp` drives an S1AP UE Context Release through
  the production multiplexer: the RRCConnectionRelease is sent, exactly one
  Release Complete is emitted, the DRB runtime is destroyed and the UE reaches
  RRC_IDLE.

## Not claimed

- No authorized live Open5GS Attach or live EPC user plane.
- No multi-process production-UE acceptance with a real TUN and a deterministic
  PGW endpoint. That flag (`LTE_PRODUCTION_UE_BIDIRECTIONAL_USER_PLANE_READY`)
  stays false.
- No IPv6/dual-stack PDN, no RLC UM, no PDCP status report, no DRB release RRC
  message, no 512-UE or 1 Gbps acceptance.
