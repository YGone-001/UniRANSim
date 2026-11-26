#!/usr/bin/env python3
"""PCAP evidence for the D10-512-R1 acceptance.

Preflight first: tool, disk, namespaces, interfaces, echo server readiness and a
small probe. Then capture S1-MME/S1-U, the PDN TUN, the S1-U veth, the Uu
loopback and one representative UE TUN while probing several UEs. Every file is
rejected when it is empty or has zero packets; a formally present but empty
capture is never reported as evidence.
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
import time


def run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def nsrun(ns, cmd, **kw):
    if ns in ("", "host"):
        return run(cmd, **kw)
    return run(["ip", "netns", "exec", ns] + cmd, **kw)


def wait_file(path, timeout):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if os.path.exists(path):
            return True
        time.sleep(0.1)
    return False


def read_log_ip(log_dir, index):
    try:
        text = open(os.path.join(log_dir, f"ue{index}.log"), errors="ignore").read()
    except OSError:
        return None
    marker = text.find("IPv4=")
    if marker < 0:
        return None
    digits = []
    for ch in text[marker + 5:]:
        if ch.isdigit() or ch == ".":
            digits.append(ch)
        else:
            break
    return "".join(digits) or None


def tun_for(ns, ip):
    for line in nsrun(ns, ["ip", "-br", "addr"]).stdout.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[2].split("/")[0] == ip:
            return parts[0]
    return None


def iface_exists(ns, iface):
    out = nsrun(ns, ["ip", "link", "show", iface])
    return out.returncode == 0


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--ue-log-dir", default="/tmp/d10-iso/log/run")
    parser.add_argument("--indices", default="1,2,64,128,256,384,512")
    parser.add_argument("--epc-ns", default="d10epc")
    parser.add_argument("--ue-ns", default="d10ue")
    parser.add_argument("--probe", default="cmake-build-release/lte-uu-traffic-probe")
    parser.add_argument("--test-ip", default="10.98.0.1")
    parser.add_argument("--echo-port", type=int, default=5670)
    parser.add_argument("--duration", type=float, default=6.0)
    parser.add_argument("--evidence-dir", required=True)
    parser.add_argument("--tcpdump", default="tcpdump")
    args = parser.parse_args()

    os.makedirs(args.evidence_dir, exist_ok=True)
    summary = {"result": "FAILED", "files": {}, "indices": {}, "preflight": {}}

    # ---- preflight ----------------------------------------------------
    if shutil.which(args.tcpdump) is None:
        summary["preflight"]["error"] = "tcpdump is not installed"
        json.dump(summary, open(os.path.join(args.evidence_dir, "capture-summary.json"), "w"), indent=1)
        return 2
    free = shutil.disk_usage(args.evidence_dir).free
    if free < 200 * 1024 * 1024:
        summary["preflight"]["error"] = f"disk free is only {free} bytes"
        json.dump(summary, open(os.path.join(args.evidence_dir, "capture-summary.json"), "w"), indent=1)
        return 2
    namespaces = run(["ip", "netns", "list"]).stdout
    if args.epc_ns not in namespaces or args.ue_ns not in namespaces:
        summary["preflight"]["error"] = "a required network namespace is missing"
        json.dump(summary, open(os.path.join(args.evidence_dir, "capture-summary.json"), "w"), indent=1)
        return 2
    indices = [int(x) for x in args.indices.split(",") if x.strip()]
    ips = {}
    for index in indices:
        ip = read_log_ip(args.ue_log_dir, index)
        if ip is None:
            summary["preflight"]["error"] = f"UE {index} has no address"
            json.dump(summary, open(os.path.join(args.evidence_dir, "capture-summary.json"), "w"), indent=1)
            return 2
        ips[index] = ip

    # ---- echo server --------------------------------------------------
    stop = os.path.join(args.evidence_dir, "echo.stop")
    ready = os.path.join(args.evidence_dir, "echo.ready")
    server_result = os.path.join(args.evidence_dir, "echo.result")
    for path in (stop, ready, server_result):
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass
    server = subprocess.Popen(["ip", "netns", "exec", args.epc_ns, args.probe, "udp-echo-server",
                               "--bind", args.test_ip, "--port", str(args.echo_port),
                               "--result", server_result, "--stop", stop, "--ready", ready],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if not wait_file(ready, 5):
        server.terminate()
        summary["preflight"]["error"] = "echo server did not bind its unique port"
        json.dump(summary, open(os.path.join(args.evidence_dir, "capture-summary.json"), "w"), indent=1)
        return 2

    # ---- captures -----------------------------------------------------
    captures = []

    def start_capture(ns, iface, name, extra=None):
        path = os.path.join(args.evidence_dir, name)
        command = ["ip", "netns", "exec", ns, args.tcpdump, "-i", iface, "-n", "-s0", "-w", path]
        if extra:
            command += extra
        process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        captures.append({"process": process, "path": path, "ns": ns, "iface": iface,
                         "filter": extra})
        return path

    uniq_ue_tun = tun_for(args.ue_ns, ips[indices[0]])
    if uniq_ue_tun is None:
        server.terminate()
        summary["preflight"]["error"] = "no TUN device for the first representative UE"
        json.dump(summary, open(os.path.join(args.evidence_dir, "capture-summary.json"), "w"), indent=1)
        return 2
    start_capture(args.epc_ns, "d10e0", "s1-mme-s1u.pcap")
    start_capture(args.epc_ns, "d10tun", "pdn-inner.pcap")
    start_capture(args.ue_ns, "d10e1", "s1u-veth.pcap")
    start_capture(args.ue_ns, "lo", "uu-loopback.pcap", ["udp", "port", "47100"])
    start_capture(args.ue_ns, uniq_ue_tun, "ue-tun.pcap")
    time.sleep(1.0)

    # A small probe on every representative UE, each on its own source port.
    for index, ip in ips.items():
        result = os.path.join(args.evidence_dir, f"probe-{index}.result")
        nsrun(args.ue_ns, [args.probe, "udp-client", "--bind", ip, "--to", args.test_ip,
                           "--port", str(args.echo_port), "--count", "5", "--size", "1372",
                           "--timeout-ms", "3000", "--result", result])
        try:
            text = open(result).read()
        except OSError:
            text = ""
        summary["indices"][str(index)] = {
            "ip": ip,
            "probe_ok": "result=COMPLETE" in text and "loss=0" in text,
        }
    time.sleep(args.duration)
    for capture in captures:
        capture["process"].terminate()
    for capture in captures:
        try:
            capture["process"].wait(timeout=5)
        except subprocess.TimeoutExpired:
            capture["process"].kill()
    open(stop, "w").close()
    time.sleep(0.3)
    server.terminate()

    # ---- verification -------------------------------------------------
    ok = True
    for capture in captures:
        path = capture["path"]
        name = os.path.basename(path)
        size = os.path.getsize(path) if os.path.exists(path) else 0
        packets = 0
        decoded = ""
        if size > 0:
            counted = run([args.tcpdump, "-r", path, "-nn"], timeout=60)
            packets = len([line for line in counted.stdout.splitlines() if line.strip()])
            verbose = run([args.tcpdump, "-r", path, "-nn", "-vv"], timeout=60)
            keep = []
            for line in verbose.stdout.splitlines():
                if any(marker in line for marker in ("GTP", "TEID", "SCTP", "10.80.", "10.98.0.1")):
                    keep.append(line)
                if len(keep) >= 8:
                    break
            decoded = "\n".join(keep)
            with open(os.path.join(args.evidence_dir, name + ".decode.txt"), "w") as handle:
                handle.write(decoded)
        summary["files"][name] = {"bytes": size, "packets": packets,
                                  "interface": capture["iface"], "ns": capture["ns"],
                                  "filter": capture["filter"]}
        if size == 0 or packets == 0:
            ok = False
    summary["result"] = "COMPLETE" if ok else "FAILED"
    summary["ue_tun"] = uniq_ue_tun
    with open(os.path.join(args.evidence_dir, "capture-summary.json"), "w") as handle:
        json.dump(summary, handle, indent=1)
    print("pcap " + summary["result"] + " " + json.dumps({k: v["packets"] for k, v in summary["files"].items()}))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
