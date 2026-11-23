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

## What this configuration does not do yet

The endpoint is parsed, validated and stored, but no consumer exists: the UE
application still sends NAS over `enbLink` and the eNB multiplexer does not bind
it. Wiring those two is the remaining work of B6-D and is listed as
NOT_EXECUTED in the final report.

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

**`src/lte/ue/app.cpp` does not use it yet**; wiring the loop and the shared
downlink handler is the remaining work.
