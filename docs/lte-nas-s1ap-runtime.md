# LTE NAS over SRB1 and S1AP

Phase 18-F-B6-C. `src/lte/enb/enb_rrc_bridge.{hpp,cpp}`,
`src/lte/security/enb_as_security_context.{hpp,cpp}`,
`src/lte/rrc-runtime/rrc_information_transfer.{hpp,cpp}`,
`src/lte/enb/s1ap_security_capabilities.{hpp,cpp}`.

This is the first path on which an EPS Attach crosses real S1AP bytes, real RRC
messages and the socket-backed SRB1 in one procedure.

## Data path

```text
UE                                     eNB bridge                    MME
RRCConnectionSetupComplete(NAS)  -->  EncodeInitialUeMessage     -->  (S1AP)
                                 <--  DecodeDownlinkNasTransport <--  Downlink NAS
DLInformationTransfer            <--  SendDownlinkNas
ULInformationTransfer            -->  EncodeUplinkNasTransport -->  (S1AP)
                                 <--  DecodeInitialContextSetup <--  KeNB + caps
RRC SecurityModeCommand          <--  EnbAsSecurityProcedure
RRC SecurityModeComplete         -->  (MAC-I verified, ciphering on)
protected DLInformationTransfer  <--  (Attach Accept)
protected ULInformationTransfer  -->  EncodeUplinkNasTransport -->  Attach Complete
                                     EncodeInitialContextSetupResponse
```

`EnbRrcBridge` owns the SRB1 runtime and no SCTP association: S1AP PDUs leave
through a sink and arrive through `OnDownlinkNasTransport` /
`OnInitialContextSetupRequest`. That keeps the existing S1 association epoch,
sender binding and E-RAB allocation in `EnbMultiplexer`, which is where they
already are. The bridge binds each radio association to one eNB-UE-S1AP-ID and
learns the MME-UE-S1AP-ID from the first downlink NAS; neither is fabricated.

## NAS is opaque at the eNB

The eNB encodes and decodes S1AP containers and never reads a NAS message. The
same bytes that the UE put in `RRCConnectionSetupComplete.dedicatedInfoNAS`
arrive in the Initial UE Message, and the same bytes the MME put in a Downlink
NAS Transport arrive in a `DLInformationTransfer`. The first NAS of the slice
is the real `lte::ue::nas::EncodeAttachRequest` output; the UE side decodes the
NAS Security Mode Command and the Attach Accept with the production NAS
decoders.

## Security architecture

| Material | UE | eNB | MME |
|---|---|---|---|
| KASME | owns | never receives | owns |
| KeNB | derives from KASME and the UL NAS COUNT | receives in `securityKey` | derives |
| K_RRCint / K_RRCenc | derives | derives from its KeNB | not held |
| NAS keys | owns | never receives | owns |
| PDCP COUNT | per direction | per direction | not applicable |

`EnbAsSecurityContext` accepts only the KeNB and has no KASME member and no NAS
COUNT. Both contexts implement `AsKeySource`, which is the subset an AS security
procedure needs, so `EnbAsSecurityProcedure` cannot ask for a KASME. A test
proves the UE context (KASME -> KeNB) and the eNB context (MME-provided KeNB)
derive identical RRC keys.

## PDCP transition

| Message | PDCP profile | Integrity | Ciphering |
|---|---|---|---|
| SetupComplete, pre-SMC InformationTransfer | pre-security SRB (1-octet header, 5-bit SN) | none | none |
| SecurityModeCommand (DL COUNT 0) | secure SRB | yes | no |
| SecurityModeComplete (UL COUNT 0) | secure SRB | yes | no |
| subsequent InformationTransfer | secure SRB | yes | yes |

The entities that carry the command and the completion are moved into the
steady-state bearer (`TakeTx/TakeRx`), not recreated, so COUNT continues from 1
in both directions after activation.

## UESecurityCapabilities

TS 36.413 9.2.1.88 numbers the bits of a 16-bit string from the first, leftmost
one with EEA0/EIA0 in bit 0; `UeAlgorithmCapabilities` stores identity n in bit n
of a uint16. The mapper bit-reverses the raw word. A test pins 0xE0 0x00 ->
identities 0,1,2; 0xA0 0x00 -> 0 and 2; and proves a UE that does not advertise
EEA3 never gets it even when it heads the operator allowlist.

## Evidence

`test/lte/lte_cp_runtime.cpp` runs the slice over a real socket pair and asserts:
one Initial UE Message, three Uplink NAS Transports, three Downlink NAS
Transports, one Initial Context Setup Response, exact NAS equality at both ends,
both sides ACTIVE with the same KeNB, a lost SecurityModeCommand recovered by RLC
AM without a second NAS message, S1 association loss invalidating the access
context, and two independent UE contexts on two eNBs.

## Limitations

- The MME is a deterministic fixture inside the test. No live Open5GS Attach was
  run: `REAL_OPEN5GS_ATTACH_ACCEPTANCE = NOT_EXECUTED`.
- The production UE application and `EnbMultiplexer` are not wired to this path
  yet: the bridge is the composition point, but the `lte-ue` event loop still
  sends every NAS over the legacy link, and the multiplexer's E-RAB setup is not
  connected to `CompleteInitialContextSetup`. The UE's NAS state machine is not
  driving the messages; the fixture supplies the downlink NAS.
- The E-RAB setup items in the response come from the caller; the bridge does not
  allocate GTP-U endpoints.
- No SRB2, no DRB PDCP, no re-establishment, no handover security change.
