# LTE RRC initial access (SRB0)

Phase 18-F-B6-A. `src/lte/rrc-runtime/rrc_initial_access.{hpp,cpp}`.

## Messages

| Message | Direction | Channel | Carrier |
|---|---|---|---|
| RRCConnectionRequest | UE -> eNB | UL-CCCH | SRB0 / RLC TM |
| RRCConnectionSetup | eNB -> UE | DL-CCCH | SRB0 / RLC TM |
| RRCConnectionReject | eNB -> UE | DL-CCCH | SRB0 / RLC TM |
| RRCConnectionSetupComplete | UE -> eNB | UL-DCCH | **B6-B, not implemented** |

All three are real TS 36.331 messages encoded with the accepted asn1c LTE RRC
UPER codec. The request carries an S-TMSI (`mmec`, `m-TMSI`) and an
establishment cause; the setup carries transaction 0 and an SRB1 entry with an
explicit AM RLC configuration; the reject carries a wait time.

## State machines

UE: `RRC_IDLE` -> (request sent) `RRC_CONNECTION_REQUEST_PENDING` -> (setup
decoded and validated) `RRC_SRB1_CONFIGURING`, or `RRC_CONNECTION_REJECTED`, or
`RRC_CONNECTION_FAILED` on timeout or an undecodable answer.

eNB: per association, `RRC_SETUP_PENDING` after a valid request, or
`RRC_CONNECTION_REJECTED`. A repeated request for a pending association returns
the same answer and does **not** create a second context.

**The UE never reaches `RRC_CONNECTED` in this phase.** SRB1 needs RLC AM, which
is B6-B; until then the UE holds the staged configuration and stops.

## Why not connected

`RRC_CONNECTED` requires a received and validated RRCConnectionSetupComplete on
SRB1, which requires RLC AM and a PDCP SRB1 entity. Neither exists yet. The
capability table therefore reports `SRB0_INITIAL_ACCESS_READY = true` and keeps
`AS_SMC_RUNTIME_READY`, `AS_INITIAL_SECURITY_ACTIVATION_READY` and
`HANDOVER_SECURITY_READY` false.

## NAS

The legacy `NAS_UPLINK` path is untouched. No NAS is carried in this phase's
messages, so there is exactly one NAS Attach path, as before.
