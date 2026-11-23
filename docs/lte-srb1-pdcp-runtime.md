# LTE SRB1 PDCP runtime

Phase 18-F-B6-B2. `src/lte/rrc-runtime/srb1_pdcp.{hpp,cpp}`,
`srb1_rlc_config.{hpp,cpp}` and `rrc_srb1_runtime.{hpp,cpp}`.

This is the first carrier for an RRC message that is neither SRB0 nor a test
vector: RRCConnectionSetupComplete leaves the UE through PDCP and RLC AM, crosses
the simulated Uu, and is decoded by the eNB.

## The PDU

Before the AS Security Mode procedure, SRB1 has no integrity protection and no
ciphering, so the PDCP Data PDU is the TS 36.323 6.2.2 SRB shape with the MAC-I
absent:

```text
octet 1   R | R | R | SN(5)
octet 2.. Data
```

The three reserved bits must be zero on reception and are always zero on
transmission. There is no D/C bit: SRBs have no PDCP control PDU in this
release. A five-bit SN means modulus 32.

COUNT is `HFN << 5 | SN`. The transmitter keeps one 64-bit counter, derives the
SN from its low five bits and the HFN from the rest, and refuses to transmit past
`2^32`. The receiver accepts exactly the SN it expects, advances COUNT, and
increments the HFN when the SN wraps. Anything else is typed:

| Refusal | Meaning |
|---|---|
| `MALFORMED_PDU` | shorter than the one-octet header |
| `RESERVED_BITS_SET` | one of the three reserved bits is not zero |
| `DUPLICATE` | the SN is behind the expected one |
| `OUT_OF_SEQUENCE` | the SN is ahead of the expected one |
| `COUNT_EXHAUSTED` | the 32-bit COUNT is used up |
| `RELEASED` | the entity has been released |

RLC AM delivers in order and exactly once, so a duplicate that reaches PDCP can
only come from a lower layer that misbehaved or from a synthetic test; both are
refused rather than delivered twice.

## Why the security entity is not used here

`lte::security::PdcpSecurityEntity` (B5/B5-R1) composes COUNT, bearer,
direction, MAC-I and ciphering for a *configured* security context. Its inputs are
algorithm identifiers and keys, and calling it before SecurityModeCommand would
invent a protected PDU that the peer cannot verify. The runtime therefore uses
the pre-security entity above and leaves the security component untouched; B6-C
is where an activated entity replaces it on this bearer. No key material is
present in this path at all.

## RLC configuration

`RrcConnectionSetupMessage` carries six RLC fields as TS 36.331 enumerators, not
as numbers. `MapSrb1Configuration` resolves each enumerator to its duration or
count, then converts the duration to runtime ticks:

| Field | Resolved to |
|---|---|
| t-PollRetransmit | milliseconds -> `AmConfig.pollTicks` |
| t-Reordering | milliseconds -> `AmConfig.reorderingTicks` (ms0 = 0 = not started) |
| t-StatusProhibit | milliseconds -> `AmConfig.prohibitTicks` |
| pollPDU | `AmConfig.pollPdu` (pInfinity = 0 = disabled) |
| pollByte | `AmConfig.pollByte` in bytes (kBinfinity = 0 = disabled) |
| maxRetxThreshold | retransmissions; `AmConfig.maxRetx` counts transmissions, so + 1 |

One tick is one millisecond of simulated time (`Srb1DefaultTickMilliseconds`),
and the ratio is a parameter, so the conversion is `ceil(ms / tick)` and not a
cast. A spare enumerator, an SRB identity other than 1, a zero tick or any value
the table does not define is refused with the name of the field. No received
value is replaced by a default.

The eNB maps exactly the message it offers (`EnbInitialAccess::SetSetup`) and
throws at construction if it cannot, so the two sides cannot silently disagree.

## Data path

```text
UE                                        eNB
RRC SDU                                   Uu
  -> SrbPdcpEntity::Protect                 -> LteAmBearer::OnFrame (DCCH, UL)
  -> LteAmBearer::SubmitSdu                 -> LteAmEntity::OnPdu
  -> LteAmEntity::OnPdu (AM)                -> deliverer
  -> uu::Frame{UE, UL, DCCH} -> socket      -> SrbPdcpEntity::Unprotect
                                            -> DecodeRrcConnectionSetupComplete
                                            -> validate, deliver dedicatedInfoNAS
```

Both endpoints borrow one socket each and dispatch on the logical channel: CCCH
is SRB0 and goes to `UeInitialAccess` / `EnbInitialAccess`, DCCH is SRB1 and goes
to the bearer. A bearer validates association, direction, channel and RLC format
before an entity sees the frame, so a mislabelled or malformed frame changes no
RLC state. The relay used by the tests forwards the label an endpoint emitted; it
never rewrites a wrong direction into a right one.

## State machines

UE: `RRC_IDLE` -> request -> `RRC_CONNECTION_REQUEST_PENDING` -> setup decoded ->
`RRC_SRB1_CONFIGURING` (SRB1 AM and PDCP now exist) -> SetupComplete submitted ->
`RRC_CONNECTION_COMPLETE_PENDING` -> RLC acknowledgement for that PDU ->
`RRC_CONNECTED`.

eNB: per association, `RRC_SETUP_PENDING` after the setup is sent -> a decoded
SetupComplete with the right transaction identifier and PLMN -> `RRC_CONNECTED`.
One SetupComplete per context: a second one is an unexpected message, and a
duplicate PDCP SN is refused, so the NAS callback fires exactly once.

## Evidence

`test/lte/srb1_runtime.cpp` pins, over the socket transport:

- the enumerator-to-tick mapping at both ends of every table, and the refusals;
- the PDCP header, SN 0..39 with the HFN wrap after 32, and every typed refusal;
- the UPER round trip of the message, including exact NAS bytes;
- the complete establishment, with the UE's PDCP PDU byte-identical to the PDU
  the eNB's RLC delivered, and both endpoints' `AmConfig` equal;
- a lost SetupComplete recovered by RLC AM retransmission (one PDCP PDU, one RLC
  retransmission, one NAS delivery), a duplicate, and a delayed PDU;
- a wrong transaction identifier, a malformed PDCP PDU, a malformed RRC PDU, a
  wrong direction, a wrong channel and a wrong association, each refused before
  delivery;
- two UE contexts on one eNB with loss in one and no effect on the other;
- context release and re-creation, and a separate UE process completing the
  whole procedure with exact payload reconciliation in the supervisor.

## Limitations

- Downlink SRB1 messages are not implemented: the eNB sends only RLC STATUS on
  SRB1, so `RRCConnectionReconfiguration` and the rest of DL-DCCH are absent.
- Exactly one uplink SRB1 message exists (SetupComplete); there is no second RRC
  message to drive the PDCP SN past 0 on the wire. The wraparound is pinned on
  the PDCP entity directly.
- No security: no MAC-I, no ciphering, no SecurityModeCommand, no activation.
- No SRB2, no DRB PDCP, no re-establishment, no PDCP status report.
- The NAS bytes stop at a callback; nothing routes them into S1AP yet.
