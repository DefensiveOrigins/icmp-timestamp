#!/usr/bin/env python3
"""
timecheck.py — Query ICMP Timestamp (type 13/14) and report clock offsets.

Uses Scapy (AF_PACKET) so it bypasses iptables/netfilter, like hping3.

Install:  pip install scapy
Run:      sudo python3 timecheck.py hosts.txt
          sudo python3 timecheck.py hosts.txt --timeout 3 --verbose
          sudo python3 timecheck.py hosts.txt --csv results.csv
          sudo python3 timecheck.py hosts.txt --warn-threshold 500

Clock offset uses the NTP formula:
    offset = ((T2 - T1) + (T3 - T4)) / 2
A positive offset means the remote clock is ahead of ours.
"""

import argparse
import csv
import sys
import statistics
from dataclasses import dataclass
from typing import Optional
from datetime import datetime, timezone, timedelta

try:
    from scapy.all import IP, ICMP, sr1, conf
    conf.verb = 0
except ImportError:
    print("ERROR: Scapy is not installed.  Run:  pip install scapy", file=sys.stderr)
    sys.exit(1)


# ---------------------------------------------------------------------------
# Result container
# ---------------------------------------------------------------------------
@dataclass
class HostResult:
    host:        str
    success:     bool
    error:       str   = ""
    src_ip:      str   = ""
    remote_time: str   = ""
    rtt_ms:      float = 0.0
    offset_ms:   float = 0.0
    t1:          int   = 0
    t2:          int   = 0
    t3:          int   = 0
    t4:          int   = 0


# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------
def now_ms_since_midnight() -> int:
    now_utc  = datetime.now(timezone.utc)
    midnight = now_utc.replace(hour=0, minute=0, second=0, microsecond=0)
    return int((now_utc - midnight).total_seconds() * 1000)


def ms_to_timestr(ms: int) -> str:
    now_utc  = datetime.now(timezone.utc)
    midnight = now_utc.replace(hour=0, minute=0, second=0, microsecond=0)
    dt = midnight + timedelta(milliseconds=ms)
    return dt.strftime("%H:%M:%S.") + f"{ms % 1000:03d}"


def fmt_offset(ms: float) -> str:
    """
    Auto-scale an offset value to a human-readable string with appropriate units.
    Keeps values compact regardless of magnitude.
      < 10 s       → X.X ms
      < 10 min     → X.X s
      < 10 hr      → X.X min
      < 10 days    → X.X hr
      >= 10 days   → X.X days
    """
    sign  = "+" if ms >= 0 else "-"
    a     = abs(ms)

    if a < 10_000:                          # < 10 s
        return f"{sign}{a:.1f} ms"
    elif a < 600_000:                       # < 10 min
        return f"{sign}{a/1000:.1f} s"
    elif a < 36_000_000:                    # < 10 hr
        return f"{sign}{a/60_000:.1f} min"
    elif a < 864_000_000:                   # < 10 days
        return f"{sign}{a/3_600_000:.1f} hr"
    else:
        return f"{sign}{a/86_400_000:.1f} days"


def fmt_rtt(ms: float) -> str:
    return f"{ms:.1f} ms"


def severity(offset_ms: float, warn_threshold: float) -> str:
    a = abs(offset_ms)
    if a < 100:
        return "OK"
    elif a < warn_threshold:
        return "WARN"
    else:
        return "HIGH"


# ---------------------------------------------------------------------------
# Per-host query
# ---------------------------------------------------------------------------
def query_host(host: str, timeout: float, debug: bool) -> HostResult:
    import time

    t1 = now_ms_since_midnight()
    pkt = IP(dst=host) / ICMP(type=13, id=0x1234, seq=1,
                               ts_ori=t1, ts_rx=0, ts_tx=0)

    if debug:
        print(f"  [DEBUG {host}] Sending type=13 (T1={t1}ms)")

    wall_send = time.time()
    resp = sr1(pkt, timeout=timeout, verbose=0)
    wall_recv = time.time()

    if resp is None:
        return HostResult(host=host, success=False,
                          error=f"TIMEOUT (no reply within {timeout}s)")

    icmp = resp[ICMP]

    if debug:
        print(f"  [DEBUG {host}] Got ICMP type={icmp.type} code={icmp.code}  "
              f"RTT={(wall_recv-wall_send)*1000:.1f}ms")

    if icmp.type != 14:
        return HostResult(host=host, success=False,
                          error=f"UNEXPECTED ICMP type={icmp.type} code={icmp.code}")

    t2, t3    = icmp.ts_rx, icmp.ts_tx
    t4        = now_ms_since_midnight()
    rtt_ms    = (wall_recv - wall_send) * 1000
    offset_ms = ((t2 - t1) + (t3 - t4)) / 2.0

    if debug:
        print(f"  [DEBUG {host}] T1={t1} T2={t2} T3={t3} T4={t4}  "
              f"offset={offset_ms:+.1f}ms")

    return HostResult(
        host=host, success=True,
        src_ip=resp[IP].src,
        remote_time=ms_to_timestr(t3),
        rtt_ms=rtt_ms,
        offset_ms=offset_ms,
        t1=t1, t2=t2, t3=t3, t4=t4,
    )


# ---------------------------------------------------------------------------
# Console table output
# ---------------------------------------------------------------------------
def print_table(results: list[HostResult], warn_threshold: float, verbose: bool):
    successful = [r for r in results if r.success]
    failed     = [r for r in results if not r.success]

    # --- build every cell value first so we can measure widths ---
    COL_HOST   = max((len(r.host) for r in results), default=4)
    COL_HOST   = max(COL_HOST, 4)

    # Pre-render offset and deviation strings for successful hosts
    mean = statistics.mean(r.offset_ms for r in successful) if successful else 0.0

    rows = []
    for r in results:
        if not r.success:
            rows.append(dict(
                host=r.host, time="---", local="---",
                group="---", rtt="---", status=r.error,
            ))
        else:
            vs_mean = r.offset_ms - mean
            rows.append(dict(
                host=r.host,
                time=r.remote_time,
                local=fmt_offset(r.offset_ms),
                group=fmt_offset(vs_mean),
                rtt=fmt_rtt(r.rtt_ms),
                status=severity(r.offset_ms, warn_threshold),
                flag=("  <<<" if severity(r.offset_ms, warn_threshold) == "HIGH"
                      else ("  <" if severity(r.offset_ms, warn_threshold) == "WARN"
                            else "")),
            ))

    # Dynamic column widths
    W_HOST  = max(len(r["host"])  for r in rows)
    W_TIME  = max(len(r["time"])  for r in rows)
    W_LOCAL = max(len(r["local"]) for r in rows)
    W_GROUP = max(len(r["group"]) for r in rows)
    W_RTT   = max(len(r["rtt"])   for r in rows)

    # Apply minimums / header widths
    W_HOST  = max(W_HOST,  4)
    W_TIME  = max(W_TIME,  17)    # "REMOTE TIME (UTC)"
    W_LOCAL = max(W_LOCAL, 12)    # "vs LOCAL CLK"
    W_GROUP = max(W_GROUP, 13)    # "vs GROUP MEAN"
    W_RTT   = max(W_RTT,   7)     # "RTT"

    def row_str(host, time, local, group, rtt, status, flag=""):
        return (f"{host:<{W_HOST}}  {time:<{W_TIME}}  "
                f"{local:>{W_LOCAL}}  {group:>{W_GROUP}}  "
                f"{rtt:>{W_RTT}}  {status}{flag}")

    hdr   = row_str("HOST", "REMOTE TIME (UTC)", "vs LOCAL CLK",
                    "vs GROUP MEAN", "RTT", "STATUS")
    sep   = "-" * len(hdr)
    tsep  = "=" * len(hdr)

    print()
    print(hdr)
    print(sep)

    for r in rows:
        flag = r.get("flag", "")
        print(row_str(r["host"], r["time"], r["local"],
                      r["group"], r["rtt"], r["status"], flag))
        if verbose and rows[rows.index(r)]:
            orig = next((hr for hr in results if hr.host == r["host"]), None)
            if orig and orig.success:
                indent = " " * (W_HOST + 2)
                print(f"{indent}T1={orig.t1} T2={orig.t2} T3={orig.t3} T4={orig.t4}  "
                      f"IP={orig.src_ip}")

    # --- statistics ---
    print()
    print(tsep)

    if not successful:
        print("  No successful responses — cannot compute statistics.")
        print(tsep)
        return

    offsets = [r.offset_ms for r in successful]
    median  = statistics.median(offsets)
    stdev   = statistics.stdev(offsets) if len(offsets) > 1 else 0.0
    spread  = max(offsets) - min(offsets)

    print(f"  Hosts queried   : {len(results)}  ({len(successful)} OK, {len(failed)} failed)")
    print(f"  Mean offset     : {fmt_offset(mean)}")
    print(f"  Median offset   : {fmt_offset(median)}")
    print(f"  Std deviation   : {fmt_offset(stdev)}")
    print(f"  Range           : {fmt_offset(min(offsets))}  to  {fmt_offset(max(offsets))}  "
          f"(spread = {fmt_offset(spread)})")
    print()

    if stdev > 0:
        outliers = [r for r in successful if abs(r.offset_ms - mean) > 2 * stdev]
        if outliers:
            print(f"  Outliers (|offset - mean| > 2σ = {fmt_offset(2*stdev)}):")
            for r in outliers:
                print(f"    {r.host:<{W_HOST}}  "
                      f"offset={fmt_offset(r.offset_ms)}  "
                      f"deviation={fmt_offset(r.offset_ms - mean)}")
        else:
            print(f"  No outliers detected  (2σ threshold = {fmt_offset(2*stdev)})")
    else:
        print("  All offsets are identical — no outliers.")

    print()
    if spread < 100:
        assessment = "Clocks look well-synchronized (spread < 100 ms)."
    elif spread < 1_000:
        assessment = f"Moderate clock drift detected (spread = {fmt_offset(spread)}). Check NTP config."
    else:
        assessment = (f"SIGNIFICANT clock skew detected (spread = {fmt_offset(spread)}). "
                      f"NTP may not be running or is misconfigured.")
    print(f"  Assessment: {assessment}")
    print(tsep)
    print()


# ---------------------------------------------------------------------------
# CSV output
# ---------------------------------------------------------------------------
def write_csv(results: list[HostResult], path: str, warn_threshold: float):
    successful = [r for r in results if r.success]
    mean = statistics.mean(r.offset_ms for r in successful) if successful else 0.0

    fieldnames = [
        "host", "success", "src_ip", "remote_time_utc",
        "offset_ms", "offset_vs_mean_ms", "rtt_ms",
        "status", "t1", "t2", "t3", "t4", "error",
    ]

    with open(path, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for r in results:
            writer.writerow(dict(
                host=r.host,
                success=r.success,
                src_ip=r.src_ip,
                remote_time_utc=r.remote_time,
                offset_ms=f"{r.offset_ms:.3f}" if r.success else "",
                offset_vs_mean_ms=f"{r.offset_ms - mean:.3f}" if r.success else "",
                rtt_ms=f"{r.rtt_ms:.3f}" if r.success else "",
                status=severity(r.offset_ms, warn_threshold) if r.success else "FAILED",
                t1=r.t1, t2=r.t2, t3=r.t3, t4=r.t4,
                error=r.error,
            ))

    print(f"CSV written to: {path}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Query ICMP Timestamp and report NTP-style clock offsets."
    )
    parser.add_argument("hosts_file",
                        help="File with one hostname or IP per line")
    parser.add_argument("--timeout", "-t", type=float, default=2.0,
                        help="Per-host reply timeout in seconds (default: 2)")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Show raw T1/T2/T3/T4 and source IP per host")
    parser.add_argument("--debug", "-d", action="store_true",
                        help="Print packet-level trace for each host")
    parser.add_argument("--warn-threshold", type=float, default=1000.0,
                        metavar="MS",
                        help="Offset (ms) above which a host is flagged HIGH "
                             "(default: 1000)")
    parser.add_argument("--csv", metavar="FILE",
                        help="Also write results to a CSV file")
    args = parser.parse_args()

    try:
        with open(args.hosts_file) as fh:
            hosts = [l.strip() for l in fh
                     if l.strip() and not l.startswith("#")]
    except FileNotFoundError:
        print(f"ERROR: '{args.hosts_file}' not found.", file=sys.stderr)
        sys.exit(1)

    if not hosts:
        print("ERROR: No hosts found in file.", file=sys.stderr)
        sys.exit(1)

    print(f"\nQuerying {len(hosts)} host(s) via ICMP Timestamp -- "
          f"{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")

    results = []
    for host in hosts:
        r = query_host(host, timeout=args.timeout, debug=args.debug)
        results.append(r)
        if not args.debug:
            print("." if r.success else "F", end="", flush=True)

    print_table(results, warn_threshold=args.warn_threshold, verbose=args.verbose)

    if args.csv:
        write_csv(results, args.csv, warn_threshold=args.warn_threshold)


if __name__ == "__main__":
    main()
