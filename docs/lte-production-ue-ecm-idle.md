# ECM-IDLE access restoration on the production UE (B6-D5)

This is the record of how the production `lte-ue` enters ECM-IDLE with its EPS
registration and NAS security context intact, and how a UE-initiated Service
Request or a network page returns it to ECM-CONNECTED over a new RRC connection.

## The three state layers

| Layer | ECM-CONNECTED | ECM-IDLE | EMM-DEREGISTERED |
|---|---|---|---|
| EMM | REGISTERED | REGISTERED | DEREGISTERED |
| ECM | CONNECTED | IDLE | IDLE |
| RRC | RRC_CONNECTED | RRC_IDLE | RRC_IDLE |
| NAS security context | active | active, preserved | destroyed |
| EPS bearer / GUTI | active | preserved | released |
| S1 UE context (MME) | present | present | released |
| RRC/S1 radio resources | present | released | released |

ECM-IDLE is not a Detach. Only the radio access is gone; `MobilityContext::
onS1ContextReleased()` clears the S1AP identities and TEIDs of the connection and
nothing above them.

## Entering ECM-IDLE

The network decides it. The deterministic MME sends an S1AP UE Context Release
Command; `EnbRrcBridge::OnUeContextReleaseCommand` sends a real
`RRCConnectionRelease` on SRB1 (protected with the active AS profile), emits the
UE Context Release Complete and drops the radio context while retaining the UE's
radio endpoint for paging. The UE decodes the release, defers its own teardown to
`Tick()` (the bearer that delivered the PDU is still on the stack), and reports
`onRelease` to the application. The application calls
`MobilityContext::onS1ContextReleased()`, keeps `security`, `mobility.guti` and
the bearer identities, and states `EMM-REGISTERED + ECM-IDLE + RRC_IDLE`.

## UE-initiated Service Request

```text
ECM-IDLE
  -> nav::EncodeServiceRequest(security)      (C7 | KSI:5-bit seq | short MAC)
  -> UuNasTransport::ResumeAccess()           (new RRCConnectionRequest)
  -> RRCConnectionSetup
  -> SendNas(Service Request) in RRCConnectionSetupComplete
  -> eNB Initial UE Message (with the S-TMSI from the RRC request)
  -> MME verifies the short MAC against the retained context and COUNT
  -> Initial Context Setup with KeNB = KDF(KASME, SR uplink COUNT)
  -> RRC Security Mode Command / Complete
  -> ECM-CONNECTED
```

The Service Request is the first NAS of the new connection, so it travels in
SetupComplete, not in ULInformationTransfer. The compact message is TS 24.301's
Service Request security form as this project implements it: type `0xC7`, KSI in
the top three bits of the second octet, a five-bit sequence in the low bits, and
a two-octet short MAC over those two octets. `nas::VerifyServiceRequest` checks
the KSI, rebuilds the COUNT from the previous one and rejects a short MAC that
does not match; the MME also refuses a COUNT that did not advance.

## Network Paging

```text
MME -> S1AP Paging (S-TMSI, TAI list, CN domain PS)
    -> eNB maps it to one cell-wide RRC Paging on PCCH
    -> PCCH frame over the simulated Uu (LogicalChannel::PCCH)
    -> idle UE decodes RRC Paging and matches its own S-TMSI
    -> the same Service Request path as above
```

The paging identity is the S-TMSI the MME assigned in the Attach Accept; after the
Attach the UE sets its RRC identity from the GUTI, so the request it sends on the
next access, the S-TMSI in the Initial UE Message, and the page all name the same
UE. A page for another identity is decoded, counted and ignored: it cannot start
an access. There is no broadcast medium in this software link, so the eNB
delivers the page to the bounded set of retained idle endpoints and the UE does
the identity matching, exactly as a real UE would over a real cell.

## Counts

| Message | Direction | COUNT |
|---|---|---|
| Security Mode Complete | UL | 0 |
| Attach Complete | UL | 1 |
| Detach Request (if used) | UL | 2 |
| Service Request | UL | 2 |
| New Initial Context Setup KeNB | - | derived at UL COUNT 2 |

The Service Request reuses the Attach's context. The MME's `ulNasCount` is the
last accepted value (1); the short sequence recovers 2, and the new KeNB is
derived from KASME at 2 on both sides.

## Failure handling

| Situation | Observable outcome |
|---|---|
| Page for another S-TMSI | decoded, ignored, UE waits until its bounded deadline, exit 1 |
| No page arrives | `Timed out waiting for a network Paging indication`, exit 1 |
| Corrupted Service Request short MAC | MME refuses, no Initial Context Setup, UE exits 1 |
| Peer exits after paging | UE starts RRC, then fails its restoration deadline, exit 1 |
| Network never releases | `Timed out waiting for the network to release the RRC connection`, exit 1 |

A failed restoration never sets ECM-CONNECTED and never clears the EPS
registration.

## Test commands

```bash
UNIRANSIM_RUN_TWO_PROCESS_ATTACH=1 ./cmake-build-release/nr-tests --no-skip \
  --test-case="lte/uu/idle: the production ue restores access with a service request from ecm-idle"

UNIRANSIM_RUN_TWO_PROCESS_ATTACH=1 ./cmake-build-release/nr-tests --no-skip \
  --test-case="lte/uu/idle: a network page wakes the production ue into a service request"
```

The GitHub Actions job `Production UE EPS lifecycle (two processes)` runs all
`lte/uu/lifecycle` and `lte/uu/idle` cases plus the D3/D4 acceptance cases and
asserts the peer result files.

## What this does not do

No DRX or paging-occasion calculation: this is a deterministic cell-wide
delivery. No CS-domain paging, no IMSI paging, no network-initiated Service
Request, no TAU or Recovery over Uu, no user plane. The MME is deterministic,
not Open5GS.
