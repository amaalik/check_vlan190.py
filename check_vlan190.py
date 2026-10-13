#!/usr/bin/env python3
"""
check_vlan190.py - SSH into a range of switches, list their VLANs, and report
which switches do NOT have a given VLAN (default: 190).

Requirements:  Python 3.8+   and   pip install --upgrade netmiko
               (a recent Netmiko is needed for the aruba_aoscx driver)

Defaults are set for ArubaOS-CX switches (device_type=aruba_aoscx, "show vlan").

Examples:
    python check_vlan190.py
    python check_vlan190.py --workers 10 --quiet
    python check_vlan190.py --vlan 190 --start 10.100.99.21 --end 10.100.99.97
    python check_vlan190.py --device-type cisco_ios          # other vendors

Outputs (in ./vlan_report_<timestamp>/):
    all_switches.csv        one row per switch: status, hostname, VLAN count, VLAN present?
    vlans_by_switch.csv     every VLAN found on every switch
    missing_vlan.csv        switches reachable but WITHOUT the VLAN
    could_not_check.csv     switches that failed (unreachable / auth / parse error)
    report.html             printable summary report
    raw/<ip>.txt            raw command output from each switch
"""
import argparse
import csv
import getpass
import html
import ipaddress
import os
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException

# =============================================================================
# CONFIGURATION - change these placeholders
# =============================================================================
USERNAME = "admin"          # <-- placeholder: SSH username
PASSWORD = "password"          # <-- placeholder: SSH password
ENABLE_SECRET = ""                  # <-- placeholder: enable password (leave empty if not needed)

# Optional: instead of editing this file, set environment variables
#   SWITCH_USER, SWITCH_PASS, SWITCH_ENABLE
# Environment variables win over the placeholders above.

DEFAULT_START_IP = "10.100.99.21"
DEFAULT_END_IP = "X.X.X.X"
DEFAULT_VLAN = 190
DEFAULT_DEVICE_TYPE = "aruba_aoscx" # ArubaOS-CX (e.g. 10.13). Others: cisco_ios, cisco_nxos, arista_eos, hp_procurve
# IPs inside the range that are NOT switches and should be skipped:
SKIP_IPS = set()                    # e.g. {"10.100.99.50", "10.100.99.60"}
# =============================================================================

# Regexes that pull the VLAN ID / name / status out of the CLI output.
# ArubaOS-CX "show vlan" rows look like:
#   VLAN  Name            Status  Reason          Type     Interfaces
#   190   MGMT_190        up      ok              static   1/1/1,lag1
#   200   SERVERS         down    no_member_port  static
ARUBA_CX_RE = re.compile(
    r"^\s*(?P<id>\d{1,4})\s+(?P<name>\S+)\s+(?P<status>up|down)\s+(?P<reason>\S+)\s+(?P<type>\S+)",
    re.IGNORECASE,
)
CISCO_LIKE_RE = re.compile(
    r"^\s*(?P<id>\d{1,4})\s+(?P<name>\S+)\s+(?P<status>active|act/unsup|act/lshut|suspend|sus/lshut|sus/ishut)\b",
    re.IGNORECASE,
)
GENERIC_RE = re.compile(r"^\s*(?P<id>\d{1,4})\s+(?P<name>\S+)(?:\s+.*)?$")

# device_type -> (command, regex)
PROFILES = {
    "aruba_aoscx": ("show vlan", ARUBA_CX_RE),      # <-- your switches (ArubaOS-CX)
    "cisco_ios": ("show vlan brief", CISCO_LIKE_RE),
    "cisco_xe": ("show vlan brief", CISCO_LIKE_RE),
    "cisco_nxos": ("show vlan brief", CISCO_LIKE_RE),
    "arista_eos": ("show vlan", CISCO_LIKE_RE),
    "hp_procurve": ("show vlans", GENERIC_RE),       # ArubaOS-Switch (old ProCurve)
}


@dataclass
class SwitchResult:
    ip: str
    state: str = "PENDING"          # OK / AUTH_FAILED / UNREACHABLE / PARSE_ERROR / ERROR
    hostname: str = ""
    vlans: list = field(default_factory=list)   # list of (id, name, status)
    has_vlan: bool = False
    vlan_status: str = ""           # e.g. "up (ok)" or "down (no_member_port)" for the target VLAN
    error: str = ""
    raw: str = ""


def build_ip_list(start: str, end: str):
    first = int(ipaddress.IPv4Address(start))
    last = int(ipaddress.IPv4Address(end))
    if first > last:
        raise ValueError("start IP is greater than end IP")
    ips = [str(ipaddress.IPv4Address(i)) for i in range(first, last + 1)]
    return [ip for ip in ips if ip not in SKIP_IPS]


def parse_vlans(output: str, regex):
    seen = {}
    for line in output.splitlines():
        m = regex.match(line)
        if not m:
            continue
        vid = int(m.group("id"))
        if 1 <= vid <= 4094 and vid not in seen:
            gd = m.groupdict()
            status = (gd.get("status") or "").lower()
            if gd.get("reason"):
                status = f"{status} ({gd['reason']})"
            seen[vid] = (vid, m.group("name"), status)
    return sorted(seen.values())


def check_switch(ip, args, username, password, secret):
    res = SwitchResult(ip=ip)
    command, regex = PROFILES.get(args.device_type, ("show vlan brief", GENERIC_RE))
    if args.command:
        command = args.command

    params = {
        "device_type": args.device_type,
        "host": ip,
        "username": username,
        "password": password,
        "secret": secret,
        "conn_timeout": args.timeout,
        "auth_timeout": args.timeout,
        "banner_timeout": args.timeout,
    }

    last_exc = None
    for _attempt in range(args.retries + 1):
        try:
            with ConnectHandler(**params) as conn:
                if secret:
                    conn.enable()
                res.hostname = conn.find_prompt().rstrip("#>").strip()
                res.raw = conn.send_command(command, read_timeout=60)
            res.vlans = parse_vlans(res.raw, regex)
            if not res.vlans:
                res.state = "PARSE_ERROR"
                res.error = f"No VLANs parsed from '{command}' (wrong device type or command?)"
            else:
                res.state = "OK"
                res.has_vlan = any(v[0] == args.vlan for v in res.vlans)
                res.vlan_status = next((v[2] for v in res.vlans if v[0] == args.vlan), "")
            return res
        except NetmikoAuthenticationException as exc:
            res.state, res.error = "AUTH_FAILED", "Authentication failed"
            return res                      # retrying would only risk account lockout
        except NetmikoTimeoutException as exc:
            last_exc = exc
            res.state, res.error = "UNREACHABLE", "Connection timed out"
        except Exception as exc:            # noqa: BLE001 - report anything else
            last_exc = exc
            res.state, res.error = "ERROR", f"{type(exc).__name__}: {exc}".splitlines()[0][:200]
    return res


def write_csv(path: Path, header, rows):
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(header)
        w.writerows(rows)


def build_html(results, vlan, outfile: Path, when: str):
    ok = [r for r in results if r.state == "OK"]
    missing = [r for r in ok if not r.has_vlan]
    present = [r for r in ok if r.has_vlan]
    failed = [r for r in results if r.state != "OK"]
    e = html.escape

    def rows_missing():
        if not missing:
            return '<tr><td colspan="4" class="muted">None - every reachable switch has the VLAN.</td></tr>'
        return "".join(
            f"<tr><td>{e(r.ip)}</td><td>{e(r.hostname)}</td><td>{len(r.vlans)}</td>"
            f'<td><span class="b fail">MISSING</span></td></tr>'
            for r in missing
        )

    def rows_failed():
        if not failed:
            return '<tr><td colspan="3" class="muted">None.</td></tr>'
        return "".join(
            f"<tr><td>{e(r.ip)}</td><td><span class=\"b warn\">{e(r.state)}</span></td><td>{e(r.error)}</td></tr>"
            for r in failed
        )

    page = f"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<title>VLAN {vlan} audit</title>
<style>
body{{font-family:"Segoe UI",Arial,sans-serif;background:#f3f5f9;color:#1d2733;margin:0}}
.hd{{background:#0b2545;color:#fff;padding:18px 32px}}.hd h1{{margin:0;font-size:22px}}.hd div{{opacity:.8;font-size:13px}}
.wrap{{max-width:1100px;margin:0 auto;padding:22px}}
.cards{{display:flex;gap:14px;flex-wrap:wrap;margin-bottom:18px}}
.c{{flex:1;min-width:150px;background:#fff;border:1px solid #e3e8ef;border-radius:8px;padding:14px;text-align:center}}
.c b{{display:block;font-size:30px}}.c.ok b{{color:#1e8e3e}}.c.fail b{{color:#c5221f}}.c.warn b{{color:#b06000}}
section{{background:#fff;border:1px solid #e3e8ef;border-radius:8px;padding:16px 20px;margin-bottom:18px}}
h2{{margin:0 0 10px;font-size:17px}}table{{width:100%;border-collapse:collapse;font-size:13px}}
th{{background:#eef2f7;text-align:left;padding:8px 10px}}td{{padding:8px 10px;border-bottom:1px solid #e3e8ef}}
.b{{padding:2px 10px;border-radius:999px;font-size:11px;font-weight:700}}
.b.fail{{background:#fce8e6;color:#c5221f}}.b.warn{{background:#fff4d6;color:#b06000}}.muted{{color:#6b7785}}
</style></head><body>
<div class="hd"><h1>VLAN {vlan} Audit Report</h1><div>Generated {e(when)} | {len(results)} switches scanned</div></div>
<div class="wrap">
<div class="cards">
<div class="c ok"><b>{len(present)}</b>Have VLAN {vlan}</div>
<div class="c fail"><b>{len(missing)}</b>Missing VLAN {vlan}</div>
<div class="c warn"><b>{len(failed)}</b>Could not check</div>
</div>
<section><h2>Switches WITHOUT VLAN {vlan}</h2>
<table><tr><th>IP</th><th>Hostname</th><th>VLANs found</th><th>Result</th></tr>{rows_missing()}</table></section>
<section><h2>Switches that could not be checked</h2>
<p class="muted">These are NOT confirmed as missing the VLAN - they need to be investigated separately.</p>
<table><tr><th>IP</th><th>State</th><th>Detail</th></tr>{rows_failed()}</table></section>
</div></body></html>"""
    outfile.write_text(page, encoding="utf-8")


def main():
    ap = argparse.ArgumentParser(description="Audit VLAN presence across switches over SSH")
    ap.add_argument("--start", default=DEFAULT_START_IP)
    ap.add_argument("--end", default=DEFAULT_END_IP)
    ap.add_argument("--vlan", type=int, default=DEFAULT_VLAN)
    ap.add_argument("--device-type", default=DEFAULT_DEVICE_TYPE)
    ap.add_argument("--command", help="override the VLAN show command")
    ap.add_argument("--workers", type=int, default=15, help="parallel SSH sessions")
    ap.add_argument("--timeout", type=int, default=20, help="SSH timeout in seconds")
    ap.add_argument("--retries", type=int, default=1, help="retries on timeout")
    ap.add_argument("--output-dir", default=None)
    ap.add_argument("--quiet", action="store_true", help="do not print each switch's VLAN list")
    args = ap.parse_args()

    username = os.environ.get("SWITCH_USER", USERNAME)
    password = os.environ.get("SWITCH_PASS", PASSWORD)
    secret = os.environ.get("SWITCH_ENABLE", ENABLE_SECRET)

    # Prompt if the placeholders were never changed
    if username == "your_username":
        username = input("SSH username: ").strip()
    if password == "your_password":
        password = getpass.getpass("SSH password: ")

    ips = build_ip_list(args.start, args.end)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    outdir = Path(args.output_dir or f"vlan_report_{stamp}")
    (outdir / "raw").mkdir(parents=True, exist_ok=True)

    print(f"Checking {len(ips)} switches ({args.start} - {args.end}) for VLAN {args.vlan} "
          f"using device_type={args.device_type}, {args.workers} workers...\n")

    results = []
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {pool.submit(check_switch, ip, args, username, password, secret): ip for ip in ips}
        for fut in as_completed(futures):
            r = fut.result()
            results.append(r)
            if r.raw:
                (outdir / "raw" / f"{r.ip}.txt").write_text(r.raw, encoding="utf-8")

            if r.state == "OK":
                tag = "HAS VLAN" if r.has_vlan else f"MISSING VLAN {args.vlan}"
                extra = f"  [VLAN {args.vlan}: {r.vlan_status}]" if r.has_vlan and r.vlan_status else ""
                print(f"[{tag:>16}] {r.ip:<15} {r.hostname}  ({len(r.vlans)} VLANs){extra}")
                if not args.quiet:
                    listing = ", ".join(f"{v[0]}:{v[1]}" for v in r.vlans)
                    print(f"{'':>19}VLANs: {listing}")
            else:
                print(f"[{r.state:>16}] {r.ip:<15} {r.error}")

    results.sort(key=lambda r: tuple(int(x) for x in r.ip.split(".")))

    # ---- CSV / HTML outputs ----
    write_csv(
        outdir / "all_switches.csv",
        ["ip", "hostname", "state", f"vlan_{args.vlan}_present", f"vlan_{args.vlan}_status", "vlan_count", "error"],
        [[r.ip, r.hostname, r.state,
          ("YES" if r.has_vlan else "NO") if r.state == "OK" else "UNKNOWN",
          r.vlan_status, len(r.vlans), r.error] for r in results],
    )
    write_csv(
        outdir / "vlans_by_switch.csv",
        ["ip", "hostname", "vlan_id", "vlan_name", "status"],
        [[r.ip, r.hostname, v[0], v[1], v[2]] for r in results for v in r.vlans],
    )
    missing = [r for r in results if r.state == "OK" and not r.has_vlan]
    failed = [r for r in results if r.state != "OK"]
    write_csv(outdir / "missing_vlan.csv", ["ip", "hostname", "vlan_count"],
              [[r.ip, r.hostname, len(r.vlans)] for r in missing])
    write_csv(outdir / "could_not_check.csv", ["ip", "state", "error"],
              [[r.ip, r.state, r.error] for r in failed])
    build_html(results, args.vlan, outdir / "report.html", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    # ---- Console summary ----
    present = [r for r in results if r.state == "OK" and r.has_vlan]
    print("\n" + "=" * 60)
    print(f"SUMMARY  |  have VLAN {args.vlan}: {len(present)}  |  "
          f"MISSING: {len(missing)}  |  could not check: {len(failed)}")
    print("=" * 60)
    if missing:
        print(f"\nSwitches WITHOUT VLAN {args.vlan}:")
        for r in missing:
            print(f"  {r.ip:<15} {r.hostname}")
    if failed:
        print("\nSwitches that could not be checked (not confirmed missing):")
        for r in failed:
            print(f"  {r.ip:<15} {r.state}: {r.error}")
    print(f"\nReports saved in: {outdir.resolve()}")

    sys.exit(0 if not missing and not failed else 1)


if __name__ == "__main__":
    main()
