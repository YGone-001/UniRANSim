# LTE Uu endpoint configuration (B6-D)

Phase 18-F-B6-D adds the explicit simulated Uu endpoint both applications need
before they can own the SRB1 runtime. It is opt-in and distinct from every other
local UDP endpoint a process binds.

## eNB

```yaml
uu:
  address: 127.0.0.1
  port: 21500
```

Absent: `EnbConfig::uuAddress` is empty, `uuPort` is zero, and no Uu socket is
bound. The legacy `ueLink` transport stays the only radio path.
Present: the address must be a concrete IPv4 address and the port 1..65535; the
loader refuses `0.0.0.0`, a port that would reuse `ueLink`, and a pair that
would reuse `s1u`.

## UE

```yaml
uu:
  localAddress: 127.0.0.2
  localPort: 21600
  address: 127.0.0.1
  port: 21500
```

Absent: `Config::uu.enabled` is false and every NAS message keeps travelling over
`enbLink`. Present: the loader refuses a local endpoint that would reuse
`enbLink.localAddress:localPort` and a peer that equals the local endpoint.

## What the configuration now drives

The eNB multiplexer binds the block when it is present, and since B6-D3 the
production UE application owns a `UuNasTransport` bound to the same block. With
`uu` present the UE sends its Attach exchange and, since B6-D4, the
UE-initiated Detach that closes the same session over SRB1, never over
`enbLink`; without it nothing changes. See
`docs/lte-production-ue-srb1-attach.md` and
`docs/lte-production-ue-srb1-detach.md`.

## B6-D2 Commit B: the UE NAS transport

`lte::ue::UuNasTransport` (`src/lte/ue/uu_transport.{hpp,cpp}`) is the seam the
production UE application will use. It owns one `UeSrb1Runtime` and one socket
bound to the configured local endpoint (`uu::Socket::Bind`, not a loopback
fallback), carries the first NAS message in RRCConnectionSetupComplete and every
later one in ULInformationTransfer, and hands downlink NAS to one callback. A
send that the transport cannot make returns false; it is never retried on the
legacy link.

`test/lte/enb-uu/the production ue nas transport carries the attach request in
setupcomplete` drives it against the real `EnbMultiplexer`: the actual Attach
Request arrives in the Initial UE Message, a Downlink NAS Transport reaches the
callback, the reply travels as an Uplink NAS Transport, and a released transport
refuses further sends.

**B6-D3 wires it into `src/lte/ue/app.cpp`**: the application owns the transport,
both transports deliver into one downlink entry, and every uplink NAS of the
Attach exchange goes through it. The two-process acceptance is recorded in
`docs/lte-production-ue-srb1-attach.md`.
