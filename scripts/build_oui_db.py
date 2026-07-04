#!/usr/bin/env python3
"""Refresh data/police_ouis.json from the IEEE OUI registry.

Design: the curated JSON is the source of truth for *attribution* (which vendors
matter, their category / confidence / notes, and any hand-added OUIs). This builder
does NOT overwrite that judgement. It:

  1. loads the existing curated JSON (attribution + explicit OUIs + exclusions),
  2. re-fetches the IEEE MA-L / MA-M / MA-S registries,
  3. re-validates every curated OUI against IEEE (flagging removed/renamed blocks
     and refreshing the authoritative org/location text),
  4. for a safelist of unambiguously-named vendors, auto-discovers any *new* IEEE
     blocks registered to them (skipping documented exclusions),
  5. writes the merged JSON back (or, with --check, only reports the drift).

Run via `end-0f-watch update-db` or directly: `python scripts/build_oui_db.py`.
Offline: `--offline --ieee-dir data/` to use previously downloaded CSVs.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import re
import sys
import urllib.request
from typing import Dict, List, Optional, Tuple

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, ".."))
DEFAULT_JSON = os.path.join(ROOT, "data", "police_ouis.json")

IEEE_SOURCES = {
    "MA-L": ("oui.csv", "https://standards-oui.ieee.org/oui/oui.csv"),
    "MA-M": ("mam.csv", "https://standards-oui.ieee.org/oui28/mam.csv"),
    "MA-S": ("oui36.csv", "https://standards-oui.ieee.org/oui36/oui36.csv"),
}

# Vendors whose IEEE org name is specific enough to auto-discover new blocks safely.
# id -> (regex over IEEE org name, optional deny-regex). Vendors absent here are
# refreshed by explicit OUI only (e.g. Panasonic/Harris names are too broad).
DISCOVER = {
    "axon-enterprise":   (r"axon enterprise", None),
    "digital-ally":      (r"digital ally", None),
    "watchguard-video":  (r"watchguard video", None),
    "l3-mobile-vision":  (r"mobile-vision", None),
    "vievu":             (r"^vievu", None),
    "motorola-solutions":(r"motorola solutions", r"mobility|lenovo"),
    "sepura":            (r"^sepura", None),
    "tait":              (r"tait electronics", r"tait global"),
    "cradlepoint":       (r"cradlepoint", None),
    "sierra-wireless":   (r"sierra wireless", None),
    "peplink-pepwave":   (r"pep(link|wave)", None),
    "zepcam":            (r"^zepcam", None),
    "digital-barriers":  (r"digital barriers", None),
    "kymeta":            (r"^kymeta", None),
    "federal-signal":    (r"federal signal", None),
}

_HEX = re.compile(r"[0-9A-Fa-f]")


def hexonly(s: str) -> str:
    return "".join(_HEX.findall(s)).upper()


def canon_prefix(s: str) -> str:
    """Colon-group a hex prefix: '3873EA0' -> '38:73:EA:0'."""
    h = hexonly(s)
    return ":".join(h[i:i + 2] for i in range(0, len(h), 2))


# --------------------------------------------------------------------------- IEEE load
def fetch(url: str, dest: str) -> None:
    print(f"  downloading {url}", file=sys.stderr)
    req = urllib.request.Request(url, headers={"User-Agent": "end-0f-watch-builder/0.1"})
    with urllib.request.urlopen(req, timeout=120) as resp, open(dest, "wb") as fh:
        fh.write(resp.read())


def load_ieee(offline: bool, ieee_dir: Optional[str]) -> Dict[str, Tuple[str, str, str]]:
    """Return {prefix_hex: (registry, org, loc)} across MA-L/M/S."""
    cache_dir = ieee_dir or os.path.join(ROOT, "data")
    os.makedirs(cache_dir, exist_ok=True)
    table: Dict[str, Tuple[str, str, str]] = {}
    for registry, (fname, url) in IEEE_SOURCES.items():
        path = os.path.join(cache_dir, fname)
        if not offline:
            try:
                fetch(url, path)
            except Exception as exc:
                print(f"  warn: download failed for {registry} ({exc}); using cached {path}", file=sys.stderr)
        if not os.path.isfile(path):
            print(f"  error: missing IEEE file {path} (run without --offline once)", file=sys.stderr)
            continue
        with open(path, newline="", encoding="utf-8", errors="replace") as fh:
            reader = csv.reader(fh)
            header = next(reader, None)  # Registry,Assignment,Organization Name,Organization Address
            for row in reader:
                if len(row) < 3:
                    continue
                prefix = hexonly(row[1])
                org = row[2].strip().strip('"')
                loc = row[3].strip().strip('"') if len(row) > 3 else ""
                table[prefix] = (registry, org, loc)
    print(f"  loaded {len(table)} IEEE assignments", file=sys.stderr)
    return table


# --------------------------------------------------------------------------- build
def build(existing: dict, ieee: Dict[str, Tuple[str, str, str]]) -> Tuple[dict, List[str]]:
    report: List[str] = []
    exclusion_prefixes = {hexonly(e["prefix"]) for e in existing.get("exclusions", [])}
    out = json.loads(json.dumps(existing))  # deep copy; preserves exclusions/fingerprints/meta

    # Index IEEE by lower-cased org for discovery.
    by_org: List[Tuple[str, str, str, str]] = [
        (prefix, reg, org, loc) for prefix, (reg, org, loc) in ieee.items()
    ]

    for vendor in out.get("vendors", []):
        vid = vendor["id"]
        curated = {hexonly(o["prefix"]): o for o in vendor.get("ouis", [])}

        # (1) revalidate + refresh curated OUIs from IEEE (authoritative org/registry;
        #     preserve any hand-curated short `loc`, only backfilling it when empty)
        for phex, o in list(curated.items()):
            if phex in ieee:
                reg, org, loc = ieee[phex]
                o["registry"], o["org"] = reg, org
                if not o.get("loc"):
                    o["loc"] = loc
            else:
                report.append(f"REMOVED? {vid}: curated OUI {canon_prefix(phex)} no longer in IEEE registry")

        # (2) discovery for safelisted vendors
        rule = DISCOVER.get(vid)
        if rule:
            pat = re.compile(rule[0], re.IGNORECASE)
            deny = re.compile(rule[1], re.IGNORECASE) if rule[1] else None
            for prefix, reg, org, loc in by_org:
                if not pat.search(org):
                    continue
                if deny and deny.search(org):
                    continue
                if prefix in exclusion_prefixes or prefix in curated:
                    continue
                curated[prefix] = {"prefix": canon_prefix(prefix), "registry": reg, "org": org, "loc": loc}
                report.append(f"ADDED   {vid}: {canon_prefix(prefix)}  ({org})")

        vendor["ouis"] = [curated[p] for p in sorted(curated)]

    return out, report


# --------------------------------------------------------------------------- main
def main() -> int:
    ap = argparse.ArgumentParser(description="Refresh police_ouis.json from the IEEE registry")
    ap.add_argument("--out", default=DEFAULT_JSON, help="output JSON path")
    ap.add_argument("--in", dest="infile", default=DEFAULT_JSON, help="existing curated JSON to refresh")
    ap.add_argument("--offline", action="store_true", help="use cached IEEE CSVs, do not download")
    ap.add_argument("--ieee-dir", help="directory of oui.csv/mam.csv/oui36.csv (default: data/)")
    ap.add_argument("--check", action="store_true", help="report drift only; do not write")
    args = ap.parse_args()

    if not os.path.isfile(args.infile):
        print(f"error: curated seed JSON not found at {args.infile}", file=sys.stderr)
        return 1
    with open(args.infile, encoding="utf-8") as fh:
        existing = json.load(fh)

    print("[*] loading IEEE registry…", file=sys.stderr)
    ieee = load_ieee(args.offline, args.ieee_dir)
    if not ieee:
        print("error: no IEEE data loaded", file=sys.stderr)
        return 1

    print("[*] merging…", file=sys.stderr)
    out, report = build(existing, ieee)

    if report:
        print("\n[*] drift vs current DB:", file=sys.stderr)
        for line in report:
            print("    " + line, file=sys.stderr)
    else:
        print("[*] no drift — curated OUIs all current, no new blocks discovered.", file=sys.stderr)

    n_ouis = sum(len(v["ouis"]) for v in out["vendors"])
    if args.check:
        print(f"\n[check] {len(out['vendors'])} vendors / {n_ouis} OUIs (not written)", file=sys.stderr)
        return 0

    out.setdefault("meta", {})["generated_by"] = "build_oui_db.py"
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2, ensure_ascii=False)
        fh.write("\n")
    print(f"\n[*] wrote {args.out}: {len(out['vendors'])} vendors / {n_ouis} OUIs", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
