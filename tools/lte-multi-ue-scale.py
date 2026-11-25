#!/usr/bin/env python3
"""D10-512 multi-UE scale harness (isolated EPC).

Starts the production lte-ue processes in the UE namespace, waits for their
DRB, installs per-UE source policy routing to the isolated PDN test endpoint,
and probes each UE's real UL/DL path.  The host-memory model is explicit:

  HOST_MEMORY_INCREMENT_MB_PER_UE   host MemAvailable increment estimate
  PROCESS_RSS_MIB_PER_UE            process RSS observation (not the gate)

The two are deliberately separate.  The D10 measured 719 MB over 256 UEs
(2.81 MB/UE of host MemAvailable), while one UE process was about 8.6 MiB RSS.
A 9 MB/UE RSS sum must never be used as the host gate.

Every batch is gated by:

  projected_after_batch = MemAvailable - batch * current_estimate >= 512 MB

with a hard floor on the current MemAvailable, swap-pressure and memory-PSI
stops.  Decisions are reported as ALLOW, PAUSE_RESOURCE_PRESSURE,
BLOCKED_RESOURCE_LIMIT, STOP_MEMORY_HARD_FLOOR, STOP_SWAP_PRESSURE or
STOP_EPC_HEALTH_FAILURE, each with an audit reason.
"""
import argparse
import json
import os
import re
import statistics
import subprocess
import sys
import threading
import time

HOST_MEMORY_INCREMENT_MB_PER_UE = 3.0
PROCESS_RSS_MIB_PER_UE = 8.6
MIN_MEM_AVAILABLE_MB = 512
SWAP_GROWTH_LIMIT_MB = 64.0
SWAP_PAGE_LIMIT_MB = 64.0
PSI_SOME_LIMIT = 30.0
PSI_FULL_LIMIT = 5.0
# The host increment for a UE cannot materially exceed its process RSS; a
# larger sample is the shared EPC/page-cache background, not the UE.
ESTIMATE_CAP_MB_PER_UE = PROCESS_RSS_MIB_PER_UE * 2.0
# The estimate follows the median of this many recent clean samples and is
# not adopted until this many exist, so one noisy batch cannot ratchet it.
ESTIMATE_WINDOW = 4
ESTIMATE_MIN_SAMPLES = 3
# Below this fleet size a MemAvailable swing of 100 MB is 6-25 MB/UE of pure
# page-cache noise; the measured estimate is only meaningful once the whole
# fleet can average it.  Until then the 3.0 MB/UE model and the absolute
# floor gates carry the decision.
ESTIMATE_MIN_FLEET = 128

ALLOW = "ALLOW"
PAUSE_RESOURCE_PRESSURE = "PAUSE_RESOURCE_PRESSURE"
BLOCKED_RESOURCE_LIMIT = "BLOCKED_RESOURCE_LIMIT"
STOP_MEMORY_HARD_FLOOR = "STOP_MEMORY_HARD_FLOOR"
STOP_SWAP_PRESSURE = "STOP_SWAP_PRESSURE"
STOP_EPC_HEALTH_FAILURE = "STOP_EPC_HEALTH_FAILURE"

# ---------------------------------------------------------------------------
# Pure parsing / decision functions.  The unit tests exercise these directly
# with fixtures; nothing here reads or changes the host.
# ---------------------------------------------------------------------------

def parse_meminfo(text):
    values = {}
    for line in text.splitlines():
        fields = line.split()
        if len(fields) >= 2 and fields[0].endswith(":"):
            try:
                values[fields[0][:-1]] = int(fields[1])
            except ValueError:
                pass
    required = ("MemTotal", "MemAvailable", "MemFree", "Cached", "SwapTotal", "SwapFree")
    if any(name not in values for name in required):
        raise ValueError("meminfo is missing required fields")
    return values


def memory_from_meminfo(values):
    swap_total = values["SwapTotal"]
    swap_free = values["SwapFree"]
    return {
        "mem_total_mb": values["MemTotal"] / 1024.0,
        "mem_available_mb": values["MemAvailable"] / 1024.0,
        "mem_free_mb": values["MemFree"] / 1024.0,
        "cached_mb": values["Cached"] / 1024.0,
        "swap_total_mb": swap_total / 1024.0,
        "swap_free_mb": swap_free / 1024.0,
        "swap_used_mb": (swap_total - swap_free) / 1024.0,
    }


def parse_vmstat(text):
    result = {"pswpin": 0, "pswpout": 0}
    for line in text.splitlines():
        fields = line.split()
        if len(fields) == 2 and fields[0] in result:
            result[fields[0]] = int(fields[1])
    return result


def parse_pressure(text):
    result = {"some_avg10": 0.0, "full_avg10": 0.0}
    for line in text.splitlines():
        fields = line.split()
        if not fields:
            continue
        kind = fields[0]
        if kind not in ("some", "full"):
            continue
        for field in fields[1:]:
            if field.startswith("avg10="):
                result[kind + "_avg10"] = float(field.split("=", 1)[1])
    return result


def median(values):
    if not values:
        raise ValueError("a median needs at least one sample")
    return float(statistics.median(values))


def stable_available(samples):
    """Median MemAvailable of the supplied samples, in MB."""
    return median([float(sample) for sample in samples])


def calibrated_estimate(samples, current=HOST_MEMORY_INCREMENT_MB_PER_UE,
                        min_samples=ESTIMATE_MIN_SAMPLES):
    """A rolling-median per-UE host increment.

    One batch's MemAvailable delta is not an increment: page cache and other
    background activity can move it by tens of megabytes while the UEs' own
    shared pages barely change.  A single such sample once ratcheted the
    estimate to 32.6 MB/UE and stopped the fleet at 132 of 256.  The estimate
    therefore follows the median of the recent samples and is only adopted
    once enough of them exist; the floor and cap still bound it.
    """
    usable = [float(sample) for sample in samples if sample is not None]
    if len(usable) < min_samples:
        return max(HOST_MEMORY_INCREMENT_MB_PER_UE, current)
    window = usable[-ESTIMATE_WINDOW:]
    return min(ESTIMATE_CAP_MB_PER_UE,
               max(HOST_MEMORY_INCREMENT_MB_PER_UE, median(window)))


def policy_route_present(rule_text, route_text, priority, test_ip):
    """The per-UE rule and its test-endpoint route are both visible."""
    prefix = f"{priority}:"
    rule_ok = any(line.split() and line.split()[0] == prefix and f"lookup {priority}" in line
                  for line in rule_text.splitlines())
    route_ok = any(test_ip in line for line in route_text.splitlines())
    return rule_ok and route_ok


def install_policy_route(ns, ip, table, test_ip, tun):
    """Replace any stale rule at this priority, then verify the new one.

    A leftover rule from an earlier run used to occupy the priority, so the
    add failed and the UE looked attached while its probe had no route.  The
    caller must treat a False result as a failed UE, not as readiness.
    """
    while nsrun(ns, ["ip", "rule", "del", "priority", table]).returncode == 0:
        pass
    nsrun(ns, ["ip", "route", "flush", "table", table])
    nsrun(ns, ["ip", "rule", "add", "from", ip, "lookup", table, "priority", table])
    nsrun(ns, ["ip", "route", "add", test_ip + "/32", "dev", tun, "table", table])
    rules = nsrun(ns, ["ip", "rule", "show"]).stdout
    routes = nsrun(ns, ["ip", "route", "show", "table", table]).stdout
    return policy_route_present(rules, routes, table, test_ip)


def classify_batch(batch, started):
    """Split a requested batch into started and failed indices."""
    started_set = set(started)
    return {
        "started": sorted(started_set),
        "failed": [index for index in batch if index not in started_set],
    }


def assert_new_start(procs, index):
    """A UE index is started at most once in one harness run."""
    if index in procs:
        raise RuntimeError(f"duplicate UE start for index {index}")


def missing_processes(started, alive):
    """Started indices whose process is no longer running."""
    alive_set = set(alive)
    return [index for index in started if index not in alive_set]


def measured_increment(before_mb, after_mb, new_ue_count):
    if new_ue_count <= 0:
        raise ValueError("new_ue_count must be positive")
    return max(0.0, (float(before_mb) - float(after_mb)) / float(new_ue_count))


def stage_increment(baseline_mb, available_mb, fleet_size):
    """Cumulative host cost per UE since the pre-fleet baseline.

    A single batch's MemAvailable delta swings by tens of megabytes from page
    cache while the fleet's own shared pages barely move; that noise once
    pushed the projection to 10.5 MB/UE at 36 UEs.  The cumulative view over
    every UE started so far is the observation the gate follows.
    """
    if fleet_size <= 0:
        raise ValueError("fleet_size must be positive")
    return max(0.0, (float(baseline_mb) - float(available_mb)) / float(fleet_size))


def background_confounded(non_ue_delta_mb, ue_delta_mb, ratio=0.2):
    """A batch whose background RSS moved materially is not a clean sample."""
    if ue_delta_mb <= 0:
        return abs(non_ue_delta_mb) > 0
    return abs(non_ue_delta_mb) > ratio * ue_delta_mb


def precheck(target, available_mb, estimate, reserve=MIN_MEM_AVAILABLE_MB, current=0):
    remaining = max(0, target - current)
    estimated = remaining * estimate
    required = estimated + reserve
    projected_after = available_mb - estimated
    decision = ALLOW if projected_after >= reserve else BLOCKED_RESOURCE_LIMIT
    return {
        "decision": decision,
        "target": target,
        "current": current,
        "remaining": remaining,
        "estimate_mb_per_ue": estimate,
        "estimated_ue_memory_mb": estimated,
        "reserve_mb": reserve,
        "available_mb": available_mb,
        "projected_after_mb": projected_after,
        "reason": (
            "the target fits the host estimate with the reserve"
            if decision == ALLOW
            else "the target estimate would cross the MemAvailable reserve"
        ),
    }


def batch_gate(current, target, available_mb, estimate, batch, reserve=MIN_MEM_AVAILABLE_MB,
               swap_in_delta_mb=0.0, swap_out_delta_mb=0.0, psi_some_avg10=0.0,
               psi_full_avg10=0.0, epc_healthy=True, swap_used_delta_mb=0.0):
    """The per-batch gate.  Every stop is one auditable decision."""
    after_batch = available_mb - batch * estimate
    remaining = max(0, target - current - batch)
    after_fleet = available_mb - (target - current) * estimate
    reason = ""
    decision = ALLOW
    if not epc_healthy:
        decision = STOP_EPC_HEALTH_FAILURE
        reason = "the isolated EPC stopped answering its health check"
    elif available_mb <= reserve:
        decision = STOP_MEMORY_HARD_FLOOR
        reason = "MemAvailable is at or below the 512 MB hard floor"
    elif swap_used_delta_mb >= SWAP_GROWTH_LIMIT_MB or (
            swap_in_delta_mb + swap_out_delta_mb >= SWAP_PAGE_LIMIT_MB and swap_used_delta_mb > 0.0):
        decision = STOP_SWAP_PRESSURE
        reason = ("material SwapUsed growth was observed for this batch; "
                  "a few background page-ins/outs alone are recorded, not attributed to the UEs")
    elif psi_some_avg10 >= PSI_SOME_LIMIT or psi_full_avg10 >= PSI_FULL_LIMIT:
        decision = PAUSE_RESOURCE_PRESSURE
        reason = "memory PSI shows sustained material pressure"
    elif after_batch < reserve:
        decision = STOP_MEMORY_HARD_FLOOR
        reason = "the next batch would take MemAvailable below the 512 MB floor"
    elif after_fleet < reserve:
        decision = PAUSE_RESOURCE_PRESSURE
        reason = "the remaining fleet would cross the reserve; stop expanding safely"
    else:
        reason = "the batch fits the floor and the remaining fleet forecast"
    return {
        "decision": decision,
        "reason": reason,
        "current": current,
        "target": target,
        "batch": batch,
        "remaining_after_batch": remaining,
        "available_mb": available_mb,
        "estimate_mb_per_ue": estimate,
        "projected_after_batch_mb": after_batch,
        "projected_after_fleet_mb": after_fleet,
        "reserve_mb": reserve,
        "swap_in_delta_mb": swap_in_delta_mb,
        "swap_out_delta_mb": swap_out_delta_mb,
        "swap_used_delta_mb": swap_used_delta_mb,
        "psi_some_avg10": psi_some_avg10,
        "psi_full_avg10": psi_full_avg10,
    }


# ---------------------------------------------------------------------------
# Host observation.
# ---------------------------------------------------------------------------

def read_text(path):
    try:
        with open(path) as handle:
            return handle.read()
    except OSError:
        return ""


def read_snapshot():
    meminfo = parse_meminfo(read_text("/proc/meminfo"))
    vmstat = parse_vmstat(read_text("/proc/vmstat"))
    pressure = parse_pressure(read_text("/proc/pressure/memory"))
    snapshot = memory_from_meminfo(meminfo)
    snapshot.update(vmstat)
    snapshot.update(pressure)
    return snapshot


def sample_available(samples=3, delay=0.2):
    values = []
    for _ in range(samples):
        values.append(read_snapshot()["mem_available_mb"])
        time.sleep(delay)
    return stable_available(values), values


def run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def nsrun(ns, cmd, **kw):
    if ns in ("", "host"):
        return run(cmd, **kw)
    return run(["ip", "netns", "exec", ns] + cmd, **kw)


def netns_ip(ns, ip):
    out = nsrun(ns, ["ip", "-br", "addr"]).stdout
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[2].split("/")[0] == ip:
            return parts[0]
    return None


def netns_pids(ns):
    if ns in ("", "host"):
        pids = set()
        for name in ("mmed", "hssd", "sgwcd", "sgwud", "smfd", "pcrfd", "upfd", "mongod"):
            for value in run(["pgrep", "-x", name]).stdout.split():
                if value.isdigit():
                    pids.add(int(value))
        return sorted(pids)
    out = run(["ip", "netns", "pids", ns]).stdout
    return [int(value) for value in out.split() if value.isdigit()]


def read_rss_kb(pid):
    text = read_text(f"/proc/{pid}/status")
    match = re.search(r"^VmRSS:\s+(\d+)\s+kB", text, re.M)
    return int(match.group(1)) if match else 0


def process_rss_mb(pids):
    return sum(read_rss_kb(pid) for pid in pids) / 1024.0


def read_pss_kb(pid):
    text = read_text(f"/proc/{pid}/smaps_rollup")
    match = re.search(r"^Pss:\s+(\d+)\s+kB", text, re.M)
    return int(match.group(1)) if match else 0


def process_pss_mb(pids):
    """Proportional set size: shared pages are charged to their sharers."""
    return sum(read_pss_kb(pid) for pid in pids) / 1024.0


def epc_healthy(epc_ns, mme_metrics_host="127.0.0.2", port=9090):
    """The isolated MME metrics endpoint is the cheapest liveness check."""
    pids = netns_pids(epc_ns)
    if not pids:
        return False
    result = nsrun(epc_ns, ["curl", "-s", "--max-time", "2",
                            f"http://{mme_metrics_host}:{port}/metrics"])
    return "mme_session" in result.stdout


class Monitor(threading.Thread):
    """One-second host resource series for the evidence directory."""

    def __init__(self, evidence_dir, ue_pids_provider, epc_ns, interval=1.0):
        super().__init__(daemon=True)
        self.evidence_dir = evidence_dir
        self.ue_pids_provider = ue_pids_provider
        self.epc_ns = epc_ns
        self.interval = interval
        self.stop_event = threading.Event()
        self.pressure_events = []
    def current_ue_pids(self):
        provider = self.ue_pids_provider
        return provider() if callable(provider) else list(provider)

    def run(self):
        os.makedirs(self.evidence_dir, exist_ok=True)
        mem_path = os.path.join(self.evidence_dir, "memory-timeseries.csv")
        swap_path = os.path.join(self.evidence_dir, "swap-timeseries.csv")
        psi_path = os.path.join(self.evidence_dir, "memory-pressure.csv")
        rss_path = os.path.join(self.evidence_dir, "process-rss.csv")
        new = not os.path.exists(mem_path)
        with open(mem_path, "a") as mem, open(swap_path, "a") as swap, \
                open(psi_path, "a") as psi, open(rss_path, "a") as rss:
            if new:
                mem.write("timestamp,mem_available_mb,mem_free_mb,cached_mb\n")
                swap.write("timestamp,swap_used_mb,swap_free_mb,pswpin,pswpout\n")
                psi.write("timestamp,some_avg10,full_avg10\n")
                rss.write("timestamp,ue_sum_mb,epc_sum_mb,ue_pss_mb,epc_pss_mb,mme_sessions\n")
            while not self.stop_event.wait(self.interval):
                snapshot = read_snapshot()
                stamp = time.time()
                mem.write(f"{stamp:.3f},{snapshot['mem_available_mb']:.1f},"
                          f"{snapshot['mem_free_mb']:.1f},{snapshot['cached_mb']:.1f}\n")
                swap.write(f"{stamp:.3f},{snapshot['swap_used_mb']:.1f},"
                           f"{snapshot['swap_free_mb']:.1f},{snapshot['pswpin']},{snapshot['pswpout']}\n")
                psi.write(f"{stamp:.3f},{snapshot['some_avg10']:.2f},{snapshot['full_avg10']:.2f}\n")
                mem.flush(); swap.flush(); psi.flush()
                ue_pids = [pid for pid in self.current_ue_pids() if os.path.exists(f"/proc/{pid}")]
                ue = process_rss_mb(ue_pids)
                ue_pss = process_pss_mb(ue_pids)
                epc_pids = netns_pids(self.epc_ns)
                epc = process_rss_mb(epc_pids)
                epc_pss = process_pss_mb(epc_pids)
                mme = nsrun(self.epc_ns, ["curl", "-s", "--max-time", "2",
                                          "http://127.0.0.2:9090/metrics"]).stdout
                session = re.search(r"^mme_session (\d+)", mme, re.M)
                rss.write(f"{stamp:.3f},{ue:.1f},{epc:.1f},{ue_pss:.1f},{epc_pss:.1f},"
                          f"{session.group(1) if session else -1}\n")
                rss.flush()
                if snapshot["some_avg10"] >= 10.0 or snapshot["full_avg10"] >= 1.0:
                    self.pressure_events.append(stamp)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--subs", required=True)
    ap.add_argument("--target", type=int, required=True)
    ap.add_argument("--start", type=int, default=3)
    ap.add_argument("--ns", default="d10ue")
    ap.add_argument("--ue", default="cmake-build-release/lte-ue")
    ap.add_argument("--dir", default="/tmp/d10/gen")
    ap.add_argument("--log", default="/tmp/d10/log")
    ap.add_argument("--epc-ns", default="d10epc")
    ap.add_argument("--test-ip", default="10.98.0.1")
    ap.add_argument("--uu-base", type=int, default=48000)
    ap.add_argument("--link-base", type=int, default=30000)
    ap.add_argument("--tun-base", default="d10u")
    ap.add_argument("--batch", type=int, default=4)
    ap.add_argument("--probe", default="cmake-build-release/lte-uu-traffic-probe")
    ap.add_argument("--probe-port", type=int, default=5611)
    ap.add_argument("--evidence-dir", default="reports/evidence/phase-18-f-b6-d10-512/resource")
    ap.add_argument("--min-available-mb", type=float, default=MIN_MEM_AVAILABLE_MB)
    ap.add_argument("--host-increment-mb", type=float, default=HOST_MEMORY_INCREMENT_MB_PER_UE)
    ap.add_argument("--stability-seconds", type=int, default=0)
    ap.add_argument("--detach-after-ms", type=int, default=0,
                    help="start UEs in the production detach scenario and wait for EPS Detach accepted")
    ap.add_argument("--precheck-only", action="store_true")
    args = ap.parse_args()

    os.makedirs(args.dir, exist_ok=True)
    os.makedirs(args.log, exist_ok=True)
    os.makedirs(args.evidence_dir, exist_ok=True)
    subs = json.load(open(args.subs))
    if len(subs) < args.target:
        sys.exit(f"need {args.target} subscribers, have {len(subs)}")

    snapshot = read_snapshot()
    baseline = {
        "timestamp": time.time(),
        "mem_total_mb": snapshot["mem_total_mb"],
        "mem_available_mb": snapshot["mem_available_mb"],
        "swap_total_mb": snapshot["swap_total_mb"],
        "swap_free_mb": snapshot["swap_free_mb"],
        "swap_used_mb": snapshot["swap_used_mb"],
        "psi_some_avg10": snapshot["some_avg10"],
        "psi_full_avg10": snapshot["full_avg10"],
        "target": args.target,
        "host_increment_mb_per_ue": args.host_increment_mb,
        "process_rss_mib_per_ue": PROCESS_RSS_MIB_PER_UE,
        "min_available_mb": args.min_available_mb,
        "memory_estimate_source": "D10_MEASURED_INCREMENT",
    }
    json.dump(baseline, open(os.path.join(args.evidence_dir, "memory-baseline.json"), "w"), indent=2)
    print(f"MemTotal={snapshot['mem_total_mb']:.0f}MB "
          f"MemAvailable={snapshot['mem_available_mb']:.0f}MB "
          f"SwapTotal={snapshot['swap_total_mb']:.0f}MB "
          f"SwapUsed={snapshot['swap_used_mb']:.0f}MB "
          f"SwapFree={snapshot['swap_free_mb']:.0f}MB "
          f"PSI(some/full)={snapshot['some_avg10']:.1f}/{snapshot['full_avg10']:.1f} "
          f"target={args.target} estimate={args.host_increment_mb:.1f}MB/UE reserve={args.min_available_mb:.0f}MB")

    decision = precheck(args.target, snapshot["mem_available_mb"], args.host_increment_mb,
                        args.min_available_mb)
    gate_decisions = [decision]
    json.dump(gate_decisions, open(os.path.join(args.evidence_dir, "resource-gate-decisions.json"), "w"),
              indent=2)
    print(f"precheck decision={decision['decision']} "
          f"estimated={decision['estimated_ue_memory_mb']:.0f}MB "
          f"projected_after={decision['projected_after_mb']:.0f}MB reason={decision['reason']}")
    if args.precheck_only:
        return 0 if decision["decision"] == ALLOW else 3
    if decision["decision"] != ALLOW:
        return 3

    procs = {}
    history = []
    estimate = args.host_increment_mb
    stop_reason = None

    def write_cfg(i):
        s = subs[i - 1]
        cfg = {
            "imsi": s["imsi"], "mcc": "460", "mnc": "02", "ueId": i,
            "k": s["k"], "opc": s["opc"], "amf": s["amf"],
            "initialSqn": "000000000000", "pdnType": "IPv4",
            "apn": s.get("apn", "cmnet"), "networkCapability": "A020",
            "lifecycle": {"scenario": "detach" if args.detach_after_ms > 0 else "attach-only",
                          "triggerAfterMs": args.detach_after_ms if args.detach_after_ms > 0 else 600000,
                          "procedureTimeoutMs": 20000, "maxRetries": 3,
                          "pagingWaitMs": 60000, "switchOff": False,
                          "recoveryDelayMs": 6000, "recoveryRetryMs": 5000,
                          "recoveryMaxAttempts": 3},
            "enbLink": {"localAddress": "127.0.0.1", "localPort": args.link_base + i,
                        "address": "127.0.0.1", "port": 4998, "timeoutMs": 15000},
            "uu": {"localAddress": "127.0.0.1", "localPort": args.uu_base + i,
                   "address": "127.0.0.1", "port": 47100},
            "tun": {"required": True, "namePrefix": f"{args.tun_base}{i:03d}",
                    "mtu": 1400, "routes": []},
        }
        import yaml
        path = os.path.join(args.dir, f"ue{i}.yaml")
        with open(path, "w") as handle:
            yaml.safe_dump(cfg, handle, sort_keys=False)
        os.chmod(path, 0o600)
        return path

    def start_one(i):
        assert_new_start(procs, i)
        path = write_cfg(i)
        log = os.path.join(args.log, f"ue{i}.log")
        handle = open(log, "w")
        process = subprocess.Popen(["setsid", "ip", "netns", "exec", args.ns, args.ue, "-c", path],
                                   stdout=handle, stderr=subprocess.STDOUT)
        procs[i] = (process, handle, log, None)

    def wait_one(i, timeout=45):
        process, handle, log, _ = procs[i]
        deadline = time.time() + timeout
        while time.time() < deadline:
            if process.poll() is not None:
                return None
            try:
                text = open(log).read()
            except OSError:
                text = ""
            if args.detach_after_ms > 0 and "EPS Detach accepted" in text:
                procs[i] = (process, handle, log, "detached")
                return "detached"
            if "DRB user plane configured" in text:
                match = re.search(r"IPv4=([0-9.]+)", text)
                if match:
                    ip = match.group(1)
                    tun = netns_ip(args.ns, ip)
                    if tun:
                        table = str(10000 + i)
                        if not install_policy_route(args.ns, ip, table, args.test_ip, tun):
                            print(f"UE {i} attached but its policy route to {args.test_ip} "
                                  f"was not installed in table {table}")
                            return None
                        procs[i] = (process, handle, log, ip)
                        return ip
            if any(marker in text for marker in
                   ("PROCEDURE_FAILED", "AUTHENTICATION_FAILED", "DRB configuration failed",
                    "Detach failed")):
                return None
            time.sleep(0.2)
        return None

    monitor = Monitor(args.evidence_dir, lambda: [value[0].pid for value in procs.values()],
                      args.epc_ns)
    monitor.start()

    def probe(ips, tag):
        ok = lost = 0
        details = []
        for index, ip in enumerate(ips):
            for size in (36, 1372):  # 64-byte IP and 1400-byte IP
                result_path = os.path.join(args.log, f"probe-{tag}-{index}-{size}.result")
                nsrun(args.ns, [args.probe, "udp-client", "--bind", ip, "--to", args.test_ip,
                                "--port", str(args.probe_port), "--count", "5",
                                "--size", str(size), "--result", result_path])
                text = read_text(result_path)
                if "result=COMPLETE" in text and "loss=0" in text and "corrupt=0" in text:
                    ok += 1
                else:
                    lost += 1
                    details.append((ip, size, text.splitlines()[:4]))
        return ok, lost, details

    server_stop = os.path.join(args.log, "probe.stop")
    server_result = os.path.join(args.log, "probe-server.result")
    for path in (server_stop, server_result):
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass
    probe_server_cmd = [args.probe, "udp-echo-server", "--bind", args.test_ip,
                        "--port", str(args.probe_port), "--result", server_result,
                        "--stop", server_stop]
    if args.epc_ns not in ("", "host"):
        probe_server_cmd = ["ip", "netns", "exec", args.epc_ns] + probe_server_cmd
    server = subprocess.Popen(probe_server_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(0.5)

    stages = [s for s in (1, 2, 4, 8, 16, 32, 64, 128, 256, 320, 384, 448, 512)
              if s >= args.start and s <= args.target]
    if not stages or stages[-1] != args.target:
        stages.append(args.target)
    done = args.start - 1
    fleet_baseline_mb, fleet_baseline_samples = sample_available()
    stage_samples = []
    stage_history = []
    previous = read_snapshot()
    for stage in stages:
        while done < stage and stop_reason is None:
            batch = list(range(done + 1, min(stage, done + args.batch) + 1))
            before_mb, before_samples = sample_available()
            before = read_snapshot()
            swap_in_mb = max(0.0, (before["pswpin"] - previous["pswpin"])) * 4.0 / 1024.0
            swap_out_mb = max(0.0, (before["pswpout"] - previous["pswpout"])) * 4.0 / 1024.0
            ue_rss_before = process_rss_mb([value[0].pid for value in procs.values()])
            epc_rss_before = process_rss_mb(netns_pids(args.epc_ns))
            swap_used_mb = max(0.0, before["swap_used_mb"] - previous["swap_used_mb"])
            gate = batch_gate(done, args.target, before_mb, estimate, len(batch),
                              args.min_available_mb, swap_in_mb, swap_out_mb,
                              before["some_avg10"], before["full_avg10"],
                              epc_healthy(args.epc_ns), swap_used_mb)
            print(f"batch {batch[0]}-{batch[-1]} decision={gate['decision']} "
                  f"available={before_mb:.0f}MB projected_after={gate['projected_after_batch_mb']:.0f}MB")
            gate_decisions.append({**gate, "timestamp": time.time()})
            json.dump(gate_decisions, open(os.path.join(args.evidence_dir, "resource-gate-decisions.json"), "w"),
                      indent=2)
            if gate["decision"] != ALLOW:
                stop_reason = gate["reason"]
                history.append({**gate, "timestamp": time.time()})
                break
            for index in batch:
                start_one(index)
            started = []
            failed = []
            for index in batch:
                ip = wait_one(index)
                if ip is None:
                    failed.append(index)
                else:
                    started.append((index, ip))
                    if index > done:
                        done = index
            after_mb, after_samples = sample_available()
            after = read_snapshot()
            measured = measured_increment(before_mb, after_mb, len(started)) if started else None
            ue_rss = process_rss_mb([value[0].pid for value in procs.values()])
            ue_pss = process_pss_mb([value[0].pid for value in procs.values()])
            epc_rss_after = process_rss_mb(netns_pids(args.epc_ns))
            confounded = background_confounded(epc_rss_after - epc_rss_before,
                                                ue_rss - ue_rss_before)
            record = {
                "timestamp": time.time(),
                "batch": batch,
                "started": [item[0] for item in started],
                "failed": failed,
                "mem_available_before_mb": before_mb,
                "mem_available_before_samples": before_samples,
                "mem_available_after_mb": after_mb,
                "mem_available_after_samples": after_samples,
                "swap_used_mb": after["swap_used_mb"],
                "psi_some_avg10": after["some_avg10"],
                "psi_full_avg10": after["full_avg10"],
                "measured_mb_per_ue": measured,
                "background_confounded": confounded,
                "estimate_mb_per_ue_next": estimate,
                "ue_rss_mb": ue_rss,
                "ue_pss_mb": ue_pss,
                "ue_rss_before_mb": ue_rss_before,
                "epc_rss_before_mb": epc_rss_before,
                "epc_rss_after_mb": epc_rss_after,
                "swap_in_delta_mb": swap_in_mb,
                "swap_out_delta_mb": swap_out_mb,
                "swap_used_delta_mb": swap_used_mb,
                "gate_decision": gate["decision"],
                "gate_reason": gate["reason"],
            }
            history.append(record)
            previous = after
            json.dump(history, open(os.path.join(args.evidence_dir, "memory-batch-history.json"), "w"),
                      indent=2)
            classified = classify_batch(batch, [item[0] for item in started])
            if classified["failed"]:
                stop_reason = f"batch {batch} had failed UEs: {classified['failed']}"
                break
            if args.detach_after_ms == 0:
                alive_indexes = [index for index, value in procs.items() if value[0].poll() is None]
                gone = missing_processes(list(procs), alive_indexes)
                if gone:
                    stop_reason = f"UE processes exited unexpectedly: {gone}"
                    break
            if after["mem_available_mb"] <= args.min_available_mb:
                stop_reason = "MemAvailable reached the 512 MB hard floor"
                break
        if stop_reason is not None:
            break
        active = [(index, value) for index, value in procs.items()
                  if value[3] and value[3] != "detached"]
        ips = [value[3] for _, value in active]
        if args.detach_after_ms > 0:
            ok = lost = 0
        else:
            ok, lost, details = probe(ips, str(stage))
        mme = nsrun(args.epc_ns, ["curl", "-s", "--max-time", "3",
                                  "http://127.0.0.2:9090/metrics"]).stdout
        session = re.search(r"^mme_session (\d+)", mme, re.M)
        stage_snapshot = read_snapshot()
        if args.detach_after_ms == 0 and done >= 4:
            stage_cost = stage_increment(fleet_baseline_mb, stage_snapshot["mem_available_mb"], done)
            adopted = done >= ESTIMATE_MIN_FLEET
            if adopted:
                stage_samples.append(stage_cost)
                estimate = calibrated_estimate(stage_samples, args.host_increment_mb, min_samples=1)
            stage_history.append({
                "timestamp": time.time(),
                "stage": stage,
                "started_total": done,
                "active": len(active),
                "mem_available_mb": stage_snapshot["mem_available_mb"],
                "fleet_baseline_mb": fleet_baseline_mb,
                "baseline_samples": fleet_baseline_samples,
                "cumulative_mb_per_ue": stage_cost,
                "adopted": adopted,
                "estimate_mb_per_ue_next": estimate,
            })
            json.dump(stage_history, open(os.path.join(args.evidence_dir, "memory-stage-history.json"), "w"),
                      indent=2)
        print(f"STAGE {stage}: active={len(active)} probe_ok={ok} probe_fail={lost} "
              f"mme_session={session.group(1) if session else '?'} "
              f"MemAvailable={stage_snapshot['mem_available_mb']:.0f}MB "
              f"SwapUsed={stage_snapshot['swap_used_mb']:.0f}MB estimate={estimate:.1f}MB/UE")

    if args.stability_seconds > 0 and stop_reason is None:
        end = time.time() + args.stability_seconds
        while time.time() < end:
            time.sleep(1.0)

    print(f"RESULT stop_reason={stop_reason} online={sum(1 for v in procs.values() if v[3])} "
          f"estimate={estimate:.2f}MB/UE")
    monitor.stop_event.set()
    monitor.join(timeout=3)
    try:
        open(server_stop, "w").close()
    except OSError:
        pass
    time.sleep(0.3)
    server.terminate()
    return 0 if stop_reason is None else 3


if __name__ == "__main__":
    sys.exit(main())
