#!/usr/bin/env python3
"""
Contextual vulnerability triage - Banque Meridia CTI unit.

Score = min(10, (a*CVSS + b*EPSS*10 + KEV_bonus + Exposure_w + Asset_w + Unpatched_bonus) * Mitigation)

Usage:
    python3 triage.py                 # use values from cves.json
    python3 triage.py --live          # refresh EPSS (FIRST API) and KEV (CISA feed) first
    python3 triage.py -i cves.json -o agenda.csv
"""
import argparse
import csv
import json
import sys
import urllib.request

# ---- Model constants ---------------------------------------------------------
ALPHA = 0.35            # technical severity (CVSS 0-10 -> 0-3.5)
BETA = 0.30             # exploitation probability (EPSS*10 -> 0-3.0)
KEV_BONUS = 1.5         # confirmed in-the-wild exploitation
UNPATCHED_BONUS = 0.3   # no vendor fix available yet
EXPOSURE_W = {"internet": 1.5, "partner": 0.8, "internal": 0.4, "isolated": 0.2}
ASSET_W = {"critical": 1.0, "high": 0.6, "moderate": 0.3, "low": 0.0}

# Tier thresholds (score out of 10)
TIERS = [(8.5, "P0"), (7.0, "P1"), (4.5, "P2"), (2.5, "P3"), (0.0, "P4")]
SLA = {
    "P0": "Emergency (< 4h - 24h)",
    "P1": "High priority (< 72h)",
    "P2": "Next sprint (< 14 days)",
    "P3": "Maintenance window (< 30-60 days)",
    "P4": "Accepted / periodic review (> 60 days)",
}
ICON = {"P0": "[RED]", "P1": "[ORG]", "P2": "[YEL]", "P3": "[BLU]", "P4": "[WHT]"}

EPSS_API = "https://api.first.org/data/v1/epss?cve="
KEV_FEED = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def refresh_live(cves):
    """Best effort: refresh EPSS and KEV from public feeds, keep file values on failure."""
    ids = ",".join(c["cve"] for c in cves)
    try:
        with urllib.request.urlopen(EPSS_API + ids, timeout=15) as r:
            data = {d["cve"]: float(d["epss"]) for d in json.load(r)["data"]}
        for c in cves:
            if c["cve"] in data:
                c["epss"] = data[c["cve"]]
        print("[+] EPSS refreshed from FIRST API", file=sys.stderr)
    except Exception as e:
        print(f"[!] EPSS refresh failed ({e}), using file values", file=sys.stderr)
    try:
        with urllib.request.urlopen(KEV_FEED, timeout=30) as r:
            kev = {v["cveID"] for v in json.load(r)["vulnerabilities"]}
        for c in cves:
            c["kev"] = c["cve"] in kev
        print("[+] KEV status refreshed from CISA feed", file=sys.stderr)
    except Exception as e:
        print(f"[!] KEV refresh failed ({e}), using file values", file=sys.stderr)


def score(c, asset):
    exposure = c.get("exposure_override", asset["exposure"])
    raw = (ALPHA * c["cvss"]
           + BETA * c["epss"] * 10
           + (KEV_BONUS if c["kev"] else 0)
           + EXPOSURE_W[exposure]
           + ASSET_W[asset["criticality"]]
           + (0 if c["patch_available"] else UNPATCHED_BONUS))
    return round(min(10.0, raw * c.get("mitigation_factor", 1.0)), 2), exposure


def tier(s, c, exposure, asset):
    p = next(t for th, t in TIERS if s >= th)
    # Guard 1: P0 needs proof of exploitation (KEV or EPSS >= 50%)
    actively_exploited = c["kev"] or c["epss"] >= 0.5
    # Guard 2: P0 needs an exposed perimeter or a core business asset
    exposed_or_core = exposure in ("internet", "partner") or asset["criticality"] == "critical"
    if p == "P0" and not (actively_exploited and exposed_or_core):
        p = "P1"
    return p


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-i", "--input", default="cves.json")
    ap.add_argument("-o", "--output", default="remediation_agenda.csv")
    ap.add_argument("--live", action="store_true", help="refresh EPSS/KEV from public feeds")
    args = ap.parse_args()

    with open(args.input) as f:
        data = json.load(f)
    assets, cves = data["assets"], data["cves"]
    if args.live:
        refresh_live(cves)

    rows = []
    for c in cves:
        a = assets[c["asset"]]
        s, exp = score(c, a)
        p = tier(s, c, exp, a)
        rows.append({
            "priority": p, "cve": c["cve"], "asset": c["asset"], "title": c["title"],
            "cvss": c["cvss"], "epss_pct": round(c["epss"] * 100, 1), "kev": "YES" if c["kev"] else "NO",
            "exposure": exp, "score": s, "sla": SLA[p],
        })

    rows.sort(key=lambda r: (r["priority"], -r["score"]))
    for i, r in enumerate(rows, 1):
        r["rank"] = i

    hdr = f"{'#':>2} {'Tier':<10}{'CVE':<16}{'Asset':<9}{'CVSS':>5}{'EPSS%':>7}{'KEV':>5}{'Score':>7}  SLA"
    print(hdr)
    print("-" * len(hdr) + "-" * 25)
    for r in rows:
        print(f"{r['rank']:>2} {ICON[r['priority']]} {r['priority']:<4}{r['cve']:<16}{r['asset']:<9}"
              f"{r['cvss']:>5}{r['epss_pct']:>7}{r['kev']:>5}{r['score']:>7}  {r['sla']}")

    with open(args.output, "w", newline="") as f:
        fields = ["rank", "priority", "cve", "asset", "title", "cvss", "epss_pct", "kev", "exposure", "score", "sla"]
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows({k: r[k] for k in fields} for r in rows)
    print(f"\n[+] Agenda written to {args.output}")


if __name__ == "__main__":
    main()
