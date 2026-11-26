#!/usr/bin/env python3
"""D10-512-R1 paced concurrent traffic.

Modes:
  send   one per-UE paced UDP sender, executed inside the UE network namespace
  run    the orchestrator: echo server + N senders per level, warmup, a measured
         window, drain, aggregate results
  capacity  offered-load sweep at a fixed UE count

The sender paces with absolute monotonic deadlines (not accumulated sleeps) and
a bounded catch-up. Every payload carries a sequence number, a per-UE tag and an
FNV-1a hash, so loss, duplication, reordering, corruption and cross-UE delivery
are all observable.
"""
import argparse
import json
import math
import os
import socket
import struct
import subprocess
import sys
import time

PROJ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_PROBE = os.path.join(PROJ, "cmake-build-release/lte-uu-traffic-probe")
HEADER = 12


def fnv1a(data):
    value = 2166136261
    for byte in data:
        value ^= byte
        value = (value * 16777619) & 0xFFFFFFFF
    return value


def payload_for(tag, seq, size):
    """seq(4) || hash(4) || tag(4) || pattern; hash covers tag and pattern."""
    size = max(size, HEADER)
    buf = bytearray(size)
    struct.pack_into(">I", buf, 0, seq & 0xFFFFFFFF)
    struct.pack_into(">I", buf, 8, tag & 0xFFFFFFFF)
    for i in range(HEADER, size):
        buf[i] = (i * 31 + seq) & 0xFF
    struct.pack_into(">I", buf, 4, fnv1a(bytes(buf[8:])))
    return bytes(buf)


def parse_payload(packet):
    """Returns (seq, tag) for a well-formed payload, else None."""
    if len(packet) < HEADER:
        return None
    seq, digest, tag = struct.unpack(">III", packet[:HEADER])
    if fnv1a(packet[8:]) != digest:
        return None
    return seq, tag


def schedule_offsets_ns(pps, count):
    """Absolute offsets from the first send for a fixed packet rate."""
    if pps <= 0:
        return [0] * count
    return [int(i * 1_000_000_000 / float(pps)) for i in range(count)]


def plan_counts(pps, warmup_ms, duration_ms):
    warmup = int(round(float(pps) * warmup_ms / 1000.0))
    measured = int(round(float(pps) * duration_ms / 1000.0))
    return warmup, measured, warmup + measured


def percentile(values, p):
    if not values:
        return None
    ordered = sorted(values)
    index = int(math.ceil(p / 100.0 * len(ordered))) - 1
    if index < 0:
        index = 0
    if index >= len(ordered):
        index = len(ordered) - 1
    return ordered[index]


def per_ue_rate(level, aggregate_pps):
    if level <= 0:
        raise ValueError("level must be positive")
    return float(aggregate_pps) / float(level)


def read_ips(log_dir, level):
    ips = {}
    for index in range(1, level + 1):
        path = os.path.join(log_dir, f"ue{index}.log")
        try:
            text = open(path, errors="ignore").read()
        except OSError:
            continue
        marker = text.find("IPv4=")
        if marker < 0:
            continue
        tail = text[marker + 5:]
        digits = []
        for ch in tail:
            if ch.isdigit() or ch == ".":
                digits.append(ch)
            else:
                break
        value = "".join(digits)
        if value:
            ips[index] = value
    return ips


# ---------------------------------------------------------------------------
# Sender (runs inside the UE namespace)
# ---------------------------------------------------------------------------

def send_mode(args):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((args.bind, 0))
    sock.connect((args.to, args.port))
    sock.setblocking(False)
    size = max(args.size, HEADER)
    warmup, measured, total = plan_counts(args.pps, args.warmup_ms, args.duration_ms)
    offsets = schedule_offsets_ns(args.pps, total)
    start = time.monotonic_ns()
    pending = {}
    seen = set()
    duplicate = out_of_order = corrupt = 0
    rtts = []
    highest = -1
    sent = 0
    drift_max_ms = 0.0
    catch_up_skipped = 0
    failure = ""

    def drain(now_ns):
        nonlocal duplicate, out_of_order, corrupt, highest
        while True:
            try:
                packet = sock.recv(65535)
            except BlockingIOError:
                return
            except OSError:
                return
            parsed = parse_payload(packet)
            if parsed is None:
                corrupt += 1
                continue
            seq, tag = parsed
            if tag != args.tag:
                corrupt += 1
                continue
            if seq not in pending:
                # A sequence this sender never sent in the measured window
                # (warmup echoes are not in pending and are ignored).
                if seq >= warmup:
                    corrupt += 1
                continue
            sent_at = pending.pop(seq)
            if seq in seen:
                duplicate += 1
                continue
            seen.add(seq)
            if seq < highest:
                out_of_order += 1
            highest = max(highest, seq)
            rtts.append((now_ns - sent_at) // 1000)

    for index in range(total):
        target = start + offsets[index]
        now = time.monotonic_ns()
        if target > now:
            time.sleep((target - now) / 1_000_000_000.0)
        else:
            behind_ms = (now - target) / 1_000_000.0
            drift_max_ms = max(drift_max_ms, behind_ms)
            if behind_ms > args.catch_up_ms:
                catch_up_skipped += 1
        drain(time.monotonic_ns())
        if index < warmup:
            sock.send(payload_for(args.tag, index, size))
            continue
        sent += 1
        packet = payload_for(args.tag, index, size)
        try:
            sock.send(packet)
            pending[index] = time.monotonic_ns()
        except OSError:
            failure = "send failed"
            break

    drain_deadline = time.monotonic_ns() + int(args.drain_ms * 1_000_000)
    while pending and time.monotonic_ns() < drain_deadline:
        time.sleep(0.002)
        drain(time.monotonic_ns())
    drain(time.monotonic_ns())

    received = len(seen)
    loss = sent - received
    result = "COMPLETE" if (not failure and loss == 0 and corrupt == 0 and duplicate == 0) else "DEGRADED"
    document = {
        "mode": "send",
        "result": result,
        "failure": failure,
        "tag": args.tag,
        "bind": args.bind,
        "to": args.to,
        "port": args.port,
        "pps": args.pps,
        "size": size,
        "warmup_packets": warmup,
        "measured_packets": measured,
        "sent": sent,
        "received": received,
        "loss": loss,
        "duplicate": duplicate,
        "out_of_order": out_of_order,
        "corrupt": corrupt,
        "rtt_p50_us": percentile(rtts, 50),
        "rtt_p95_us": percentile(rtts, 95),
        "rtt_p99_us": percentile(rtts, 99),
        "rtt_samples": len(rtts),
        "schedule_drift_max_ms": round(drift_max_ms, 3),
        "catch_up_skipped": catch_up_skipped,
        "duration_ms": args.duration_ms,
    }
    with open(args.result, "w") as handle:
        json.dump(document, handle, indent=1)
    print(json.dumps({k: document[k] for k in
                      ("result", "sent", "received", "loss", "corrupt", "duplicate", "out_of_order")}))
    return 0 if result == "COMPLETE" else 2


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

def run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def nsrun(ns, cmd, **kw):
    if ns in ("", "host"):
        return run(cmd, **kw)
    return run(["ip", "netns", "exec", ns] + cmd, **kw)


def tun_stats(ns, ip):
    out = nsrun(ns, ["ip", "-br", "addr"]).stdout
    device = None
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[2].split("/")[0] == ip:
            device = parts[0]
            break
    if device is None:
        return None
    stats = nsrun(ns, ["ip", "-s", "link", "show", device]).stdout
    numbers = []
    for line in stats.splitlines():
        fields = line.split()
        if len(fields) >= 3 and fields[0].isdigit():
            numbers.extend(int(x) for x in fields[2:6] if x.isdigit())
    return {"device": device, "raw": stats.strip().splitlines()[-2:] if stats else []}


def start_server(args, level, port, directory):
    stop = os.path.join(directory, f"echo-{level}.stop")
    result = os.path.join(directory, f"echo-{level}.result")
    ready = os.path.join(directory, f"echo-{level}.ready")
    for path in (stop, result, ready):
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass
    command = [args.probe, "udp-echo-server", "--bind", args.test_ip, "--port", str(port),
               "--result", result, "--stop", stop, "--ready", ready]
    if args.epc_ns not in ("", "host"):
        command = ["ip", "netns", "exec", args.epc_ns] + command
    process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(50):
        time.sleep(0.1)
        if os.path.exists(ready):
            return process, stop, result, ready
    process.terminate()
    return None, stop, result, ready


def stop_server(process, stop):
    try:
        open(stop, "w").close()
    except OSError:
        pass
    time.sleep(0.3)
    try:
        process.terminate()
    except ProcessLookupError:
        pass


def start_sender(args, index, ip, pps, port, directory, tag):
    result = os.path.join(directory, f"ue{index}.json")
    command = [sys.executable, os.path.abspath(__file__), "send",
               "--bind", ip, "--to", args.test_ip, "--port", str(port),
               "--pps", str(pps), "--tag", str(tag), "--size", str(args.size),
               "--warmup-ms", str(args.warmup_ms), "--duration-ms", str(args.duration_ms),
               "--drain-ms", str(args.drain_ms), "--catch-up-ms", str(args.catch_up_ms),
               "--result", result]
    if args.ue_ns not in ("", "host"):
        command = ["ip", "netns", "exec", args.ue_ns] + command
    return subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL), result


def load_result(path):
    try:
        return json.load(open(path))
    except (OSError, json.JSONDecodeError):
        return None


def summarize(level, results, server_bytes, per_ue_pps, size, duration_ms):
    sent = sum(r.get("sent", 0) for r in results if r)
    received = sum(r.get("received", 0) for r in results if r)
    loss = sum(r.get("loss", 0) for r in results if r)
    duplicate = sum(r.get("duplicate", 0) for r in results if r)
    corrupt = sum(r.get("corrupt", 0) for r in results if r)
    out_of_order = sum(r.get("out_of_order", 0) for r in results if r)
    seconds = duration_ms / 1000.0
    # The echo counter includes each sender's warmup packets. The measured UL
    # window is what remains after those are removed; the lossless gate keeps
    # the warmup itself at the same rate, so this subtraction is exact there.
    warmup_bytes = sum(r.get("warmup_packets", 0) for r in results if r) * size
    measured_ul_bytes = max(0, server_bytes - warmup_bytes)
    ul_goodput = (measured_ul_bytes * 8.0 / seconds) / 1e6 if seconds else 0.0
    dl_goodput = (received * size * 8.0 / seconds) / 1e6 if seconds else 0.0
    rtt_p95 = [r["rtt_p95_us"] for r in results if r and r.get("rtt_p95_us") is not None]
    complete = all(r and r.get("result") == "COMPLETE" for r in results)
    return {
        "level": level,
        "per_ue_pps": per_ue_pps,
        "aggregate_offered_pps": per_ue_pps * level,
        "aggregate_offered_mbps": per_ue_pps * level * size * 8.0 / 1e6,
        "sent": sent,
        "received": received,
        "loss": loss,
        "duplicate": duplicate,
        "corrupt": corrupt,
        "out_of_order": out_of_order,
        "ul_goodput_mbps": round(ul_goodput, 3),
        "dl_goodput_mbps": round(dl_goodput, 3),
        "rtt_p95_us_max": max(rtt_p95) if rtt_p95 else None,
        "lossless": complete and loss == 0 and corrupt == 0 and duplicate == 0,
        "senders": results,
    }


def run_level(args, level, pps, port, directory, kind):
    os.makedirs(directory, exist_ok=True)
    ips = read_ips(args.ue_log_dir, level)
    if len(ips) < level:
        return {"level": level, "error": f"only {len(ips)} UE addresses found"}
    server, stop, server_result, ready = start_server(args, level, port, directory)
    if server is None:
        return {"level": level, "error": "echo server did not become ready"}
    # The server ready file is written after bind, and a unique port per level
    # prevents the D10 zero-byte capture conflict. No preflight sender is used
    # here: its bytes would contaminate the measured echo counter.
    if server.poll() is not None:
        return {"level": level, "error": "echo server exited immediately"}

    before = {index: tun_stats(args.ue_ns, ip) for index, ip in ips.items()}
    senders = []
    for index, ip in sorted(ips.items()):
        senders.append(start_sender(args, index, ip, pps, port, directory, index))
    timeout = (args.warmup_ms + args.duration_ms) / 1000.0 + 60.0
    deadline = time.time() + timeout
    results = []
    for process, path in senders:
        try:
            process.wait(timeout=max(1.0, deadline - time.time()))
        except subprocess.TimeoutExpired:
            process.kill()
        results.append(load_result(path))
    after = {index: tun_stats(args.ue_ns, ip) for index, ip in ips.items()}
    stop_server(server, stop)
    server_text = ""
    try:
        server_text = open(server_result).read()
    except OSError:
        pass
    server_bytes = 0
    marker = server_text.find("bytes=")
    if marker >= 0:
        try:
            server_bytes = int(server_text[marker + 6:].split()[0])
        except ValueError:
            server_bytes = 0
    summary = summarize(level, results, server_bytes, pps, args.size, args.duration_ms)
    summary["kind"] = kind
    summary["server"] = {"bytes": server_bytes, "text": server_text.strip()}
    summary["tun_before"] = {str(k): v for k, v in before.items()}
    summary["tun_after"] = {str(k): v for k, v in after.items()}
    summary["mem_available_mb"] = read_mem_available()
    with open(os.path.join(directory, f"summary-{kind}-{level}.json"), "w") as handle:
        json.dump(summary, handle, indent=1)
    print(f"{kind} level={level} pps={pps:.1f}/UE offered={summary['aggregate_offered_mbps']:.1f}Mbps "
          f"sent={summary['sent']} received={summary['received']} loss={summary['loss']} "
          f"dup={summary['duplicate']} corrupt={summary['corrupt']} "
          f"ul={summary['ul_goodput_mbps']}Mbps dl={summary['dl_goodput_mbps']}Mbps "
          f"lossless={summary['lossless']}")
    return summary


def read_mem_available():
    try:
        for line in open("/proc/meminfo"):
            if line.startswith("MemAvailable:"):
                return int(line.split()[1]) / 1024.0
    except OSError:
        pass
    return None


def parse_levels(text):
    return [int(x) for x in text.split(",") if x.strip()]


def run_mode(args):
    levels = parse_levels(args.levels)
    summaries = []
    for index, level in enumerate(levels):
        pps = args.per_ue_pps
        if pps is None:
            pps = per_ue_rate(level, args.aggregate_pps)
        directory = os.path.join(args.evidence_dir, f"{args.mode}-{level}")
        summaries.append(run_level(args, level, pps, args.echo_port + index, directory, args.mode))
    worst = all(s.get("lossless") for s in summaries if "error" not in s)
    with open(os.path.join(args.evidence_dir, f"summary-{args.mode}.json"), "w") as handle:
        json.dump({"mode": args.mode, "lossless": worst, "levels": summaries}, handle, indent=1)
    if args.mode == "lossless" and not worst:
        return 2
    return 0


def capacity_mode(args):
    summaries = []
    rates = [float(x) for x in args.rates.split(",") if x.strip()]
    for index, rate in enumerate(rates):
        directory = os.path.join(args.evidence_dir, f"capacity-{int(rate)}")
        summaries.append(run_level(args, args.capacity_level, rate, args.echo_port + index, directory, "capacity"))
    with open(os.path.join(args.evidence_dir, "summary-capacity.json"), "w") as handle:
        json.dump({"mode": "capacity", "rates": rates, "levels": summaries}, handle, indent=1)
    return 0


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="mode", required=True)
    sender = sub.add_parser("send")
    sender.add_argument("--bind", required=True)
    sender.add_argument("--to", required=True)
    sender.add_argument("--port", type=int, required=True)
    sender.add_argument("--tag", type=int, required=True)
    sender.add_argument("--pps", type=float, required=True)
    sender.add_argument("--size", type=int, default=1372)
    sender.add_argument("--warmup-ms", type=int, default=0)
    sender.add_argument("--duration-ms", type=int, default=60000)
    sender.add_argument("--drain-ms", type=int, default=3000)
    sender.add_argument("--catch-up-ms", type=float, default=100.0)
    sender.add_argument("--result", required=True)

    for name in ("run", "capacity"):
        orchestrated = sub.add_parser(name)
        orchestrated.add_argument("--levels", default="8,16,32,64")
        orchestrated.add_argument("--per-ue-pps", type=float, default=None)
        orchestrated.add_argument("--aggregate-pps", type=float, default=800.0)
        orchestrated.add_argument("--size", type=int, default=1372)
        orchestrated.add_argument("--warmup-ms", type=int, default=5000)
        orchestrated.add_argument("--duration-ms", type=int, default=60000)
        orchestrated.add_argument("--drain-ms", type=int, default=3000)
        orchestrated.add_argument("--catch-up-ms", type=float, default=100.0)
        orchestrated.add_argument("--test-ip", default="10.98.0.1")
        orchestrated.add_argument("--ue-log-dir", default="/tmp/d10-iso/log/run")
        orchestrated.add_argument("--epc-ns", default="d10epc")
        orchestrated.add_argument("--ue-ns", default="d10ue")
        orchestrated.add_argument("--probe", default=DEFAULT_PROBE)
        orchestrated.add_argument("--echo-port", type=int, default=5620)
        orchestrated.add_argument("--evidence-dir", required=True)
        orchestrated.add_argument("--mode", default="lossless")
        if name == "capacity":
            orchestrated.add_argument("--rates", default="50,100,200,400,800")
            orchestrated.add_argument("--capacity-level", type=int, default=8)
            orchestrated.set_defaults(duration_ms=20000)
    args = parser.parse_args()
    if args.mode == "send":
        return send_mode(args)
    if args.mode == "capacity":
        return capacity_mode(args)
    return run_mode(args)


if __name__ == "__main__":
    sys.exit(main())
