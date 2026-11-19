# SRB0 over RLC Transparent Mode

Phase 18-F-B6-A. `src/lte/rrc-runtime/rlc_tm.{hpp,cpp}`.

SRB0 carries the initial RRC connection messages on CCCH.

## What RLC TM is

Transparent Mode adds **nothing**: no header, no sequence number, no STATUS PDU,
no retransmission, no segmentation. The RLC TM PDU is the SDU. That is the whole
implementation, and it is deliberate.

## Rules enforced here

* The maximum SDU is 1024 bytes. A larger SDU is refused with
  `OVERSIZED_SDU`; it is never truncated and never segmented.
* An empty SDU is refused (`EMPTY_SDU`).
* A released entity refuses further work (`ENTITY_RELEASED`) and must not deliver
  into a replacement UE context.
* No deduplication. A duplicated transport delivery is delivered twice; the RRC
  state machine is what rejects a duplicate request, and it does so from its own
  state, not from an invented RLC sequence number.

## What SRB0 is not

SRB0 has **no PDCP**: no PDCP SN, no MAC-I, no ciphering, no integrity
protection. Nothing in this path instantiates a security entity. Security starts
on SRB1 (Phase 18-F-B6-B), not here.
