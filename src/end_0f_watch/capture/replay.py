"""Offline capture backends for hardware-free analysis, demos and tests.

  PcapReplay    -> re-read a .pcap/.pcapng of 802.11 frames (needs scapy).
  MacListReplay -> read a simple text file of observations (no deps at all):
                     one record per line, comma-separated:
                         MAC[,ssid][,ble_name][,source]
                     blank lines and lines starting with '#' are ignored.
"""
from __future__ import annotations

from typing import Iterator

from ..models import Sighting
from .base import CaptureBackend


class PcapReplay(CaptureBackend):
    name = "replay:pcap"

    def __init__(self, path: str):
        self.path = path

    def available(self):
        try:
            import scapy  # noqa: F401
        except Exception:
            return False, "scapy is not installed (pip install '.[wifi]')"
        return True, ""

    def stream(self) -> Iterator[Sighting]:
        from scapy.utils import PcapReader
        from .wifi import parse_dot11

        with PcapReader(self.path) as reader:
            for pkt in reader:
                s = parse_dot11(pkt)
                if s is not None:
                    yield s


class MacListReplay(CaptureBackend):
    name = "replay:macs"

    def __init__(self, path: str):
        self.path = path

    def stream(self) -> Iterator[Sighting]:
        with open(self.path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = [p.strip() for p in line.split(",")]
                mac = parts[0]
                ssid = parts[1] if len(parts) > 1 and parts[1] else None
                ble_name = parts[2] if len(parts) > 2 and parts[2] else None
                source = parts[3] if len(parts) > 3 and parts[3] else "replay"
                yield Sighting(mac=mac, source=source, ssid=ssid, ble_name=ble_name)
