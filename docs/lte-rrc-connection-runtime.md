# LTE RRC connection runtime

The runtime carrier for the AS work: SRB0 initial access, then the first SRB1
control-plane exchange.

| Slice | Scope | State |
|---|---|---|
| B6-A | simulated Uu transport, RLC TM, SRB0, RRCConnectionRequest/Setup/Reject | **implemented** |
| B6-B1 | LTE RLC AM: codec, entity, partial NACK, LI, Uu acceptance | **implemented** |
| B6-B2 | SRB1 AM/PDCP runtime, RRCConnectionSetupComplete, NAS boundary | **implemented** |
| B6-C | SecurityMode over SRB1, NAS/S1AP migration | not started |

Design records:

* [lte-simulated-uu-transport.md](lte-simulated-uu-transport.md)
* [lte-srb0-rlc-tm.md](lte-srb0-rlc-tm.md)
* [lte-rrc-initial-access.md](lte-rrc-initial-access.md)
* [lte-rlc-am-engine.md](lte-rlc-am-engine.md)
* [lte-srb1-pdcp-runtime.md](lte-srb1-pdcp-runtime.md)

## The procedure

```text
UE                                                   eNB
RRCConnectionRequest      -- SRB0 / RLC TM / CCCH -->
                          <-- RRCConnectionSetup (SRB1 AM config)
map the AM configuration, build SRB1 RLC AM + PDCP
RRCConnectionSetupComplete -- PDCP --> RLC AM / DCCH -->
                                                      RLC AM --> PDCP --> RRC
                                                      validate tid and PLMN
                                                      deliver dedicatedInfoNAS
                          <-- RLC STATUS / DCCH --
RRC_CONNECTED (only after that acknowledgement)
```

One socket per endpoint carries both logical channels; the endpoint dispatches on
the channel, and the SRB1 bearer validates association, direction and channel
before an entity sees a frame.

## What exists

- Real UPER encoding and decoding of all four messages, plus the reject.
- The SRB1 AM configuration mapped from the six TS 36.331 fields, with typed
  refusals for anything the tables do not define.
- A pre-security SRB PDCP entity: five-bit SN, one-octet header, no MAC-I.
- An eNB context per association with one SetupComplete, a NAS callback, and a
  refusal path for a wrong transaction identifier, PLMN, direction, channel,
  association, PDCP PDU or RRC PDU.
- Deterministic impairment over the shared link node: loss, duplication, delay,
  reordering and re-segmentation.

## What does not exist

Downlink SRB1 messages, SRB2, DRB PDCP, AS security activation, NAS/S1AP
migration, re-establishment, and any real radio: no PRACH, no MAC scheduling, no
C-RNTI. `RRC_CONNECTED` here means the simulated procedure above completed, not
a commercial stack.

## Capabilities

`SIMULATED_UU_TRANSPORT_READY`, `SRB0_INITIAL_ACCESS_READY`,
`SRB1_RLC_AM_READY`, `SRB1_PDCP_RUNTIME_READY` and
`RRC_CONNECTION_RUNTIME_READY` are true. `AS_SMC_RUNTIME_READY`,
`AS_INITIAL_SECURITY_ACTIVATION_READY`, `HANDOVER_SECURITY_READY`,
`UE_RADIO_EXECUTION_READY` and `LIVE_HANDOVER_EXECUTION_READY` remain false.

## B6-C: the NAS carrier

SRB1 now also carries connected-mode NAS: `ULInformationTransfer` /
`DLInformationTransfer` above PDCP, and the RRC AS Security Mode procedure
between them. The eNB side is composed into `EnbRrcBridge`, which turns the
SetupComplete NAS into an S1AP Initial UE Message and drives the AS security
procedure from the KeNB the MME sends. See
[lte-nas-s1ap-runtime.md](lte-nas-s1ap-runtime.md).
