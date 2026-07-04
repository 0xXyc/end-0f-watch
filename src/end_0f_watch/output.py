"""Output sinks: live console, JSONL, CSV, plus a summary table."""
from __future__ import annotations

import csv
import json
import sys
from typing import Dict, List, Optional, TextIO

from .models import Detection
from .util import normalize_mac

_COLORS = {
    "high": "\033[1;31m",   # bold red
    "medium": "\033[33m",   # yellow
    "low": "\033[36m",      # cyan
    "dim": "\033[2m",
    "reset": "\033[0m",
    "bold": "\033[1m",
}


def _supports_color(stream: TextIO, force: Optional[bool]) -> bool:
    if force is not None:
        return force
    return bool(getattr(stream, "isatty", lambda: False)())


class Sink:
    def emit(self, det: Detection, first_seen: bool) -> None: ...
    def close(self) -> None: ...


class ConsoleSink(Sink):
    """Prints new hits prominently; repeat sightings of a known MAC are dimmed."""

    def __init__(self, stream: TextIO = sys.stdout, color: Optional[bool] = None, quiet: bool = False):
        self.stream = stream
        self.color = _supports_color(stream, color)
        self.quiet = quiet

    def _c(self, key: str, text: str) -> str:
        if not self.color:
            return text
        return f"{_COLORS.get(key, '')}{text}{_COLORS['reset']}"

    def emit(self, det: Detection, first_seen: bool) -> None:
        s = det.sighting
        if self.quiet and not first_seen:
            return
        try:
            mac = normalize_mac(s.mac)
        except ValueError:
            mac = s.mac
        vendor = det.vendor.name if det.vendor else (
            det.fingerprint_hits[0].vendor_id if det.fingerprint_hits else "?"
        )
        tag = f"[{det.confidence.upper()}]"
        bits = []
        bits.append(self._c(det.confidence, f"{tag:<8}"))
        bits.append(self._c("bold", f"{mac}"))
        bits.append(f"{s.source:<6}")
        bits.append(f"{det.category or '-':<13}")
        bits.append(vendor)
        meta = []
        if s.rssi is not None:
            meta.append(f"{s.rssi}dBm")
        if s.channel is not None:
            meta.append(f"ch{s.channel}")
        if s.ssid:
            meta.append(f"ssid={s.ssid!r}")
        if s.ble_name:
            meta.append(f"name={s.ble_name!r}")
        if meta:
            bits.append(self._c("dim", " ".join(meta)))
        line = "  ".join(bits)
        if not first_seen:
            line = self._c("dim", "  (repeat) ") + line
        print(line, file=self.stream, flush=True)

    def summary(self, detections: Dict[str, Detection], counts: Dict[str, int]) -> None:
        if not detections:
            print(self._c("dim", "\nNo police-associated devices detected."), file=self.stream)
            return
        print("\n" + self._c("bold", "=== Detection summary ==="), file=self.stream)
        rows = sorted(
            detections.values(),
            key=lambda d: ({"high": 0, "medium": 1, "low": 2}.get(d.confidence, 3),),
        )
        for det in rows:
            s = det.sighting
            try:
                mac = normalize_mac(s.mac)
            except ValueError:
                mac = s.mac
            vendor = det.vendor.name if det.vendor else "(fingerprint only)"
            n = counts.get(mac, 1)
            print(
                f"  {self._c(det.confidence, det.confidence.upper()):<7}  {mac}  "
                f"{det.category or '-':<13}  {vendor}  x{n}",
                file=self.stream,
            )
        print(f"\n{len(detections)} unique device(s) flagged.", file=self.stream)


class JsonlSink(Sink):
    def __init__(self, path: str):
        self.fh: TextIO = open(path, "a", encoding="utf-8")

    def emit(self, det: Detection, first_seen: bool) -> None:
        rec = det.to_dict()
        rec["first_seen"] = first_seen
        self.fh.write(json.dumps(rec) + "\n")
        self.fh.flush()

    def close(self) -> None:
        self.fh.close()


class CsvSink(Sink):
    _FIELDS = [
        "ts", "mac", "source", "confidence", "score", "category",
        "vendor", "vendor_id", "matched_oui", "rssi", "channel",
        "ssid", "ble_name", "randomized", "first_seen",
    ]

    def __init__(self, path: str):
        self.fh: TextIO = open(path, "a", newline="", encoding="utf-8")
        self.writer = csv.DictWriter(self.fh, fieldnames=self._FIELDS, extrasaction="ignore")
        if self.fh.tell() == 0:
            self.writer.writeheader()

    def emit(self, det: Detection, first_seen: bool) -> None:
        rec = det.to_dict()
        rec["first_seen"] = first_seen
        self.writer.writerow(rec)
        self.fh.flush()

    def close(self) -> None:
        self.fh.close()


class SinkGroup(Sink):
    def __init__(self, sinks: List[Sink]):
        self.sinks = sinks

    def emit(self, det: Detection, first_seen: bool) -> None:
        for s in self.sinks:
            s.emit(det, first_seen)

    def close(self) -> None:
        for s in self.sinks:
            s.close()
