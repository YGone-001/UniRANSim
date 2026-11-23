# LTE RLC AM PDU format

Phase 18-F-B6-B1-R2-C3. The exact octets `rlc_am.{hpp,cpp}` produces and
consumes, and the fields the test evidence records.

## AMD PDU

```text
octet 1   D/C=1 | RF | P | FI(2) | E | SN[9:8](2)
octet 2   SN[7:0]
octet 3*  LSF | SO[14:8](7)          * only when RF = 1
octet 4*  SO[7:0]
...       E | LI(11) repeated, 4 bits of zero padding when the LI count is odd
...       Data field
```

- `D/C = 1` marks a data PDU. That single bit is what the bearer uses to route a
  received frame; the transport envelope carries no type.
- `RF = 1` with `FI = 00` is rejected: a segment may not claim both boundaries.
- `E = 1` says an E/LI element follows. Each LI is 11 bits; the last element's
  `E = 0` ends the chain and the Data field follows. LI 0 is reserved and
  rejected.
- The decoder checks the sum of the LIs against the Data length: the last element
  carries no LI, so the sum may be smaller but never larger.
- SN is 10 bits, SO is 15 bits, and a segment with `SO > 0x7FFF` is refused.

## STATUS PDU

```text
octet 1   D/C=0 | CPT(3)=000 | ACK_SN[9:8](2)
octet 2   ACK_SN[7:0]
then, per NACK:  SN(10) | E1 | E2 | [ SOstart(15) | SOend(15) ]
```

`E1 = 1` means another NACK follows. `E2 = 1` means the two SO fields are
present; without them the NACK covers the whole PDU. An SO range of
`[x, 0x7FFF]` means "from x to the end of the SDU". The PDU is padded to an
octet boundary; no padding bits are interpreted as fields.

## Simulated Uu envelope

```text
'U' 'U' | version 1 | reserved 0 | association (u32 BE)
        | direction (0 uplink, 1 downlink) | channel (0 CCCH, 1 DCCH)
        | payload length (u16 BE) | payload
```

The payload is the RLC PDU byte for byte, up to 2048 bytes. A prefix of the
envelope never names the RLC or RRC message type. The association is a simulator
identifier, not a C-RNTI.

## Evidence

`test/lte/lte_am_uu.cpp` decodes every frame that crosses its link node into one
record: round, direction, PDU type, SN, segment flag, SO, LSF, poll bit, LI
count, length, the direction label the endpoint emitted and, for a STATUS, ACK_SN
and the first NACK range. A dropped frame keeps its decoded identity and is
marked as lost, so the log states what the endpoints emitted as well as what
arrived. Only DCCH payloads are decoded as RLC PDUs; a CCCH payload is an RRC
message in transparent mode and is reported by length only.

Examples from the passing run:

```text
r1 ue->enb sent AMD sn=0 len=5
r2 enb->ue sent STATUS ack=1 nacks=0 len=2

r1 ue->enb sent AMD sn=0 so=0 len=10
r1 ue->enb lost AMD sn=0 so=6 lsf len=10
r2 enb->ue sent STATUS ack=0 nacks=1 so=6..32767 len=8
r3 ue->enb sent AMD sn=0 so=6 lsf len=10
r7 enb->ue sent STATUS ack=1 nacks=0 len=2
```

The second block is a partial loss: the head of the PDU arrives, the tail does
not, the receiver names the missing range to the end of the SDU, and the
transmitter's replacement segment closes it under the same SN.