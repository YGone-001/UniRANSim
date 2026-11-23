# LTE RRC initial access (SRB0)

Phase 18-F-B6-A. `src/lte/rrc-runtime/rrc_initial_access.{hpp,cpp}`.

## Messages

| Message | Direction | Channel | Carrier |
|---|---|---|---|
| RRCConnectionRequest | UE -> eNB | UL-CCCH | SRB0 / RLC TM |
| RRCConnectionSetup | eNB -> UE | DL-CCCH | SRB0 / RLC TM |
| RRCConnectionReject | eNB -> UE | DL-CCCH | SRB0 / RLC TM |
| RRCConnectionSetupComplete | UE -> eNB | UL-DCCH | SRB1 / RLC AM, protocol above PDCP (B6-B2) |

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

In B6-A the UE stopped at `RRC_SRB1_CONFIGURING` because SRB1 did not exist.
B6-B2 continues from there: `UeSrb1Runtime` maps the staged configuration, builds
the SRB1 AM and PDCP entities and sends RRCConnectionSetupComplete, reaching
`RRC_CONNECTED` only after RLC acknowledges that PDU. The state machine here is
unchanged; the connection runtime above it owns the rest.

## Why the steps stop where they do

`RRC_CONNECTED` still requires a validated RRCConnectionSetupComplete on SRB1,
which is exactly what B6-B2 implements. AS security is still absent, so
`AS_SMC_RUNTIME_READY`, `AS_INITIAL_SECURITY_ACTIVATION_READY` and
`HANDOVER_SECURITY_READY` remain false.

## NAS

The legacy `NAS_UPLINK` path is untouched. No NAS is carried in this phase's
messages, so there is exactly one NAS Attach path, as before.
