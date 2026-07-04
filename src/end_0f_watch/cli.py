"""end-0f-watch command-line interface."""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
import threading
from typing import List, Optional

from . import __version__
from .classifier import Classifier
from .db import OuiDatabase, default_db_path
from .engine import run_scan
from .models import Sighting
from .output import ConsoleSink, CsvSink, JsonlSink, SinkGroup
from .util import format_prefix, normalize_mac

DISCLAIMER = (
    "end-0f-watch — passive RF reconnaissance research tool\n"
    "  Receive-only: it never transmits, associates, injects, jams, or decodes traffic.\n"
    "  It matches PUBLICLY broadcast Wi-Fi/BLE source MAC prefixes against a curated\n"
    "  vendor OUI list. An OUI match identifies a likely VENDOR, not a device model,\n"
    "  and is never proof of active policing. Know and obey the radio-monitoring laws\n"
    "  in your jurisdiction. Do not use this to target, track, or harass any person.\n"
)


# --------------------------------------------------------------------------- helpers
def _load_db(args) -> OuiDatabase:
    return OuiDatabase.load(getattr(args, "db", None))


def _build_sink(args, console_quiet: bool = False) -> SinkGroup:
    sinks: List = []
    color = None
    if getattr(args, "no_color", False):
        color = False
    sinks.append(ConsoleSink(color=color, quiet=console_quiet or getattr(args, "quiet", False)))
    if getattr(args, "json", None):
        sinks.append(JsonlSink(args.json))
    if getattr(args, "csv", None):
        sinks.append(CsvSink(args.csv))
    return SinkGroup(sinks)


def _banner():
    print(DISCLAIMER, file=sys.stderr)


# --------------------------------------------------------------------------- scan
def cmd_scan(args) -> int:
    if not args.wifi and not args.ble:
        print("error: choose at least one of --wifi / --ble", file=sys.stderr)
        return 2

    backends = []
    if args.wifi:
        from .capture.wifi import WifiMonitorCapture
        if not args.iface:
            print("error: --wifi requires --iface (e.g. --iface wlan0mon)", file=sys.stderr)
            return 2
        channels = None
        if args.channels:
            channels = [int(c) for c in args.channels.split(",") if c.strip()]
        backends.append(
            WifiMonitorCapture(
                iface=args.iface, channels=channels,
                hop_interval=args.hop_interval, bpf=args.bpf,
            )
        )
    if args.ble:
        from .capture.ble import BleCapture
        backends.append(BleCapture(adapter=args.adapter))

    for b in backends:
        ok, reason = b.available()
        if not ok:
            print(f"error: {b.name} backend unavailable: {reason}", file=sys.stderr)
            return 1

    _banner()
    db = _load_db(args)
    clf = Classifier(db)
    sink = _build_sink(args)
    stop_evt = threading.Event()

    src = "+".join(b.name for b in backends)
    dur = f"{args.duration}s" if args.duration else "until Ctrl-C"
    print(f"[*] scanning ({src}); min-confidence={args.min_confidence}; {dur}", file=sys.stderr)

    try:
        seen, counts = run_scan(
            backends, clf, sink,
            min_confidence=args.min_confidence,
            duration=args.duration,
            stop_evt=stop_evt,
        )
    except KeyboardInterrupt:
        print("\n[*] stopping…", file=sys.stderr)
        stop_evt.set()
        seen, counts = {}, {}
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        sink.close()
        return 1

    for s in sink.sinks:
        if isinstance(s, ConsoleSink):
            s.summary(seen, counts)
    sink.close()
    return 0


# --------------------------------------------------------------------------- replay
def cmd_replay(args) -> int:
    if bool(args.pcap) == bool(args.macs):
        print("error: provide exactly one of a pcap path or --macs FILE", file=sys.stderr)
        return 2
    if args.pcap:
        from .capture.replay import PcapReplay
        backend = PcapReplay(args.pcap)
        ok, reason = backend.available()
        if not ok:
            print(f"error: {reason}", file=sys.stderr)
            return 1
    else:
        from .capture.replay import MacListReplay
        backend = MacListReplay(args.macs)

    db = _load_db(args)
    clf = Classifier(db)
    sink = _build_sink(args)
    seen, counts = run_scan([backend], clf, sink, min_confidence=args.min_confidence)
    for s in sink.sinks:
        if isinstance(s, ConsoleSink):
            s.summary(seen, counts)
    sink.close()
    return 0


# --------------------------------------------------------------------------- lookup
def cmd_lookup(args) -> int:
    db = _load_db(args)
    clf = Classifier(db)
    rc = 1
    for raw in args.macs:
        try:
            mac = normalize_mac(raw)
        except ValueError as exc:
            print(f"{raw}: {exc}")
            continue
        det = clf.classify(Sighting(mac=mac, source="lookup", ssid=args.ssid, ble_name=args.ble_name))
        if det.is_hit:
            rc = 0
            v = det.vendor
            print(f"{mac}  [{det.confidence.upper()}]  {det.category or '-'}  "
                  f"{v.name if v else '(fingerprint only)'}")
            for r in det.reasons:
                print(f"    - {r}")
            if v and v.note:
                print(f"    note: {v.note}")
            if v and v.false_positive_notes:
                print(f"    fp-note: {v.false_positive_notes}")
        else:
            print(f"{mac}  no police-vendor match", end="")
            excl = db.excluded_reason(mac)
            if excl:
                print(f"  (excluded trap: {excl})")
            elif det.randomized:
                print("  (randomized/locally-administered MAC)")
            else:
                print()
    return rc


# --------------------------------------------------------------------------- db
def cmd_db(args) -> int:
    db = _load_db(args)
    if args.modules:
        print("Real LE vendors with NO IEEE OUI (undetectable by brand prefix):")
        for mv in sorted(db.module_vendors, key=lambda m: (m.category, m.name)):
            print(f"  {mv.category:<13} {mv.name}")
            print(f"        {mv.reason}")
        return 0
    if args.list:
        for v in db.vendors_sorted():
            if args.category and v.category != args.category:
                continue
            prefixes = ", ".join(format_prefix(o.prefix_hex) for o in v.ouis)
            print(f"[{v.police_confidence.upper():<6}] {v.category:<13} {v.name}  (ota:{v.ota_emission})")
            print(f"          OUIs: {prefixes or '(none — module-OUI vendor)'}")
            if v.note:
                print(f"          {v.note}")
        return 0
    if args.validate:
        return _validate_db(db)
    # default: stats
    st = db.stats()
    print(f"database: {getattr(db, 'path', default_db_path())}")
    print(f"  vendors:      {st['vendors']}")
    print(f"  OUI prefixes: {st['ouis']}")
    print(f"  exclusions:   {st['exclusions']}")
    print(f"  fingerprints: {st['fingerprints']}")
    print(f"  module-only vendors (no OUI): {st['module_vendors']}   (see `db --modules`)")
    print("  by category:")
    for cat, n in st["by_category"].items():
        print(f"      {cat:<14} {n}")
    if st["meta"]:
        print(f"  source: {st['meta'].get('source', '')}")
        print(f"  version: {st['meta'].get('version', '')}  updated: {st['meta'].get('generated', '')}")
    return 0


def _validate_db(db: OuiDatabase) -> int:
    from .models import CATEGORIES, CONFIDENCE_LEVELS, OTA_EMISSION
    problems = 0
    for v in db.vendors.values():
        if v.category not in CATEGORIES:
            print(f"  WARN {v.id}: unknown category {v.category!r}")
            problems += 1
        if v.police_confidence not in CONFIDENCE_LEVELS:
            print(f"  WARN {v.id}: unknown confidence {v.police_confidence!r}")
            problems += 1
        if v.ota_emission not in OTA_EMISSION:
            print(f"  WARN {v.id}: unknown ota_emission {v.ota_emission!r}")
            problems += 1
        if not v.ouis and not any(fp.vendor_id == v.id for fp in db.fingerprints):
            print(f"  WARN {v.id}: no OUIs and no fingerprints (unmatchable)")
            problems += 1
    for fp in db.fingerprints:
        if fp.vendor_id and fp.vendor_id not in db.vendors:
            print(f"  WARN fingerprint references unknown vendor {fp.vendor_id!r}")
            problems += 1
    if problems == 0:
        print(f"OK — {len(db.vendors)} vendors, structure valid.")
        return 0
    print(f"{problems} problem(s) found.")
    return 1


# --------------------------------------------------------------------------- update-db
def cmd_update_db(args) -> int:
    script = os.path.normpath(
        os.path.join(os.path.dirname(__file__), "..", "..", "scripts", "build_oui_db.py")
    )
    if not os.path.isfile(script):
        print(f"error: builder not found at {script}", file=sys.stderr)
        return 1
    cmd = [sys.executable, script]
    if args.out:
        cmd += ["--out", args.out]
    if args.offline:
        cmd += ["--offline"]
    if args.ieee_dir:
        cmd += ["--ieee-dir", args.ieee_dir]
    if args.check:
        cmd += ["--check"]
    return subprocess.call(cmd)


# --------------------------------------------------------------------------- parser
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="end-0f-watch",
        description="Passive RF recon: detect police body-cam & cruiser device OUIs "
                    "from broadcast Wi-Fi/BLE MACs.",
    )
    p.add_argument("--version", action="version", version=f"end-0f-watch {__version__}")

    def add_common(sp):
        sp.add_argument("--db", help="path to police_ouis.json (default: packaged / $EOW_DB)")
        sp.add_argument("--min-confidence", choices=["high", "medium", "low"], default="low")
        sp.add_argument("--json", metavar="FILE", help="append detections as JSONL")
        sp.add_argument("--csv", metavar="FILE", help="append detections as CSV")
        sp.add_argument("--no-color", action="store_true")
        sp.add_argument("--quiet", action="store_true", help="console: show first sighting per MAC only")

    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("scan", help="live passive capture (Wi-Fi monitor and/or BLE)")
    add_common(sp)
    sp.add_argument("--wifi", action="store_true", help="enable 802.11 monitor-mode capture")
    sp.add_argument("--ble", action="store_true", help="enable BLE advertisement capture")
    sp.add_argument("--iface", help="monitor-mode interface (e.g. wlan0mon)")
    sp.add_argument("--channels", help="comma list to hop, e.g. 1,6,11 (default: no hop)")
    sp.add_argument("--hop-interval", type=float, default=0.5, help="seconds per channel (default 0.5)")
    sp.add_argument("--bpf", help="optional BPF filter for the Wi-Fi sniffer")
    sp.add_argument("--adapter", help="BLE adapter (e.g. hci0 on Linux)")
    sp.add_argument("--duration", type=float, help="stop after N seconds (default: until Ctrl-C)")
    sp.set_defaults(func=cmd_scan)

    sp = sub.add_parser("replay", help="analyze a recorded pcap or a MAC list file (no hardware)")
    add_common(sp)
    sp.add_argument("pcap", nargs="?", help="path to .pcap/.pcapng of 802.11 frames")
    sp.add_argument("--macs", metavar="FILE", help="text file: MAC[,ssid][,ble_name][,source] per line")
    sp.set_defaults(func=cmd_replay)

    sp = sub.add_parser("lookup", help="classify one or more MAC addresses")
    sp.add_argument("--db", help="path to police_ouis.json")
    sp.add_argument("macs", nargs="+", help="MAC address(es)")
    sp.add_argument("--ssid", help="optional SSID to test against fingerprints")
    sp.add_argument("--ble-name", help="optional BLE local name to test against fingerprints")
    sp.set_defaults(func=cmd_lookup)

    sp = sub.add_parser("db", help="inspect / validate the OUI database")
    sp.add_argument("--db", help="path to police_ouis.json")
    sp.add_argument("--list", action="store_true", help="list vendors and OUIs")
    sp.add_argument("--category", help="filter --list by category")
    sp.add_argument("--modules", action="store_true", help="list LE vendors that hold no IEEE OUI")
    sp.add_argument("--validate", action="store_true", help="structural validation")
    sp.set_defaults(func=cmd_db)

    sp = sub.add_parser("update-db", help="refresh the curated DB from the IEEE registry")
    sp.add_argument("--out", help="output path (default: data/police_ouis.json)")
    sp.add_argument("--offline", action="store_true", help="use local IEEE CSVs, do not download")
    sp.add_argument("--ieee-dir", help="directory holding oui.csv/mam.csv/oui36.csv")
    sp.add_argument("--check", action="store_true", help="report drift only; do not write")
    sp.set_defaults(func=cmd_update_db)

    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except BrokenPipeError:
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
