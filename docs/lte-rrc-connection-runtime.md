# LTE RRC connection runtime

Phase 18-F-B6-A is the first slice of the runtime carrier that the AS security
work (B4, B5, B5-R1) needs.

| Slice | Scope | State |
|---|---|---|
| B6-A | simulated Uu transport, RLC TM, SRB0, RRCConnectionRequest/Setup/Reject | **implemented** |
| B6-B | RLC AM, SRB1 PDCP runtime, RRCConnectionSetupComplete | not started |
| B6-C | NAS/S1AP migration and runtime AS security activation | not started |

Design records:

* [lte-simulated-uu-transport.md](lte-simulated-uu-transport.md)
* [lte-srb0-rlc-tm.md](lte-srb0-rlc-tm.md)
* [lte-rrc-initial-access.md](lte-rrc-initial-access.md)

## What exists after B6-A

```text
UE RRC  ->  UE RLC TM  ->  simulated Uu transport  ->  eNB RLC TM  ->  eNB RRC
```

A UE process and an eNB process exchange real TS 36.331 messages through that
path. The UE stops at `RRC_SRB1_CONFIGURING`: SRB1, PDCP and
RRCConnectionSetupComplete are B6-B.

## What does not exist

RLC AM, SRB1, PDCP on a bearer, NAS through RRCConnectionSetupComplete, S1AP
re-integration, and any security activation on the runtime path. No C-RNTI, no
PRACH, no MAC scheduling: the transport association is a simulator identifier.

## Capabilities

`SIMULATED_UU_TRANSPORT_READY` and `SRB0_INITIAL_ACCESS_READY` are true.
`AS_SMC_RUNTIME_READY`, `AS_INITIAL_SECURITY_ACTIVATION_READY`,
`HANDOVER_SECURITY_READY`, `UE_RADIO_EXECUTION_READY` and
`LIVE_HANDOVER_EXECUTION_READY` remain false.
