"""802.11 monitor-mode capture via scapy.

Passively reads management/data frames off a monitor-mode interface, extracts the
transmitter address (addr2) and any advertised SSID, and emits a Sighting. Also
provides `parse_dot11()`, reused by the pcap replay backend.

Requires a Linux monitor-capable adapter and root (or CAP_NET_RAW). Nothing is
transmitted — no association, probing, injection or deauth.
"""
from __future__ import annotations

import os
import queue
import subprocess
import threading
import time
from typing import Iterator, List, Optional, Tuple

from ..models import Sighting
from ..util import freq_to_channel
from .base import CaptureBackend

_STOP = object()
# ARPHRD type reported in /sys/class/net/<if>/type when an iface is in monitor mode.
_ARPHRD_IEEE80211_RADIOTAP = 803


def parse_dot11(pkt) -> Optional[Sighting]:
    """Convert a scapy 802.11 packet to a Sighting, or None if it carries no usable src."""
    from scapy.layers.dot11 import Dot11, Dot11Elt  # lazy

    if not pkt.haslayer(Dot11):
        return None
    dot11 = pkt.getlayer(Dot11)
    src = dot11.addr2  # transmitter address
    if not src or src == "ff:ff:ff:ff:ff:ff":
        return None

    rssi: Optional[int] = None
    channel: Optional[int] = None
    ssid: Optional[str] = None
    ts = float(getattr(pkt, "time", 0.0) or 0.0)

    # RadioTap metadata (present on real monitor-mode captures).
    try:
        from scapy.layers.dot11 import RadioTap
        if pkt.haslayer(RadioTap):
            rt = pkt.getlayer(RadioTap)
            sig = getattr(rt, "dBm_AntSignal", None)
            if sig is not None:
                rssi = int(sig)
            freq = getattr(rt, "ChannelFrequency", None)
            if freq:
                channel = freq_to_channel(freq)
    except Exception:
        pass

    # SSID element (ID 0), present in beacons, probe requests and probe responses.
    elt = pkt.getlayer(Dot11Elt)
    while elt is not None and isinstance(elt, Dot11Elt):
        if elt.ID == 0:
            raw = bytes(elt.info or b"")
            if raw:
                ssid = raw.decode("utf-8", "replace")
            break
        elt = elt.payload.getlayer(Dot11Elt)

    return Sighting(mac=src, source="wifi", ts=ts, rssi=rssi, channel=channel, ssid=ssid or None)


def set_channel(iface: str, channel: int) -> bool:
    """Best-effort `iw dev <iface> set channel N`. Returns True on success."""
    try:
        subprocess.run(
            ["iw", "dev", iface, "set", "channel", str(channel)],
            check=True, capture_output=True,
        )
        return True
    except Exception:
        return False


class WifiMonitorCapture(CaptureBackend):
    name = "wifi"

    def __init__(
        self,
        iface: str,
        channels: Optional[List[int]] = None,
        hop_interval: float = 0.5,
        bpf: Optional[str] = None,
    ):
        self.iface = iface
        self.channels = channels
        self.hop_interval = hop_interval
        self.bpf = bpf
        self._stop_evt = threading.Event()

    def available(self) -> Tuple[bool, str]:
        try:
            import scapy  # noqa: F401
        except Exception:
            return False, "scapy is not installed (pip install '.[wifi]')"
        sysfs = f"/sys/class/net/{self.iface}"
        if not os.path.isdir(sysfs):
            return False, f"interface {self.iface!r} not found"
        try:
            with open(os.path.join(sysfs, "type")) as fh:
                if int(fh.read().strip()) != _ARPHRD_IEEE80211_RADIOTAP:
                    return (
                        False,
                        f"{self.iface!r} is not in monitor mode. Enable it, e.g.:\n"
                        f"    sudo airmon-ng start {self.iface}\n"
                        f"  or: sudo ip link set {self.iface} down && "
                        f"sudo iw dev {self.iface} set type monitor && "
                        f"sudo ip link set {self.iface} up",
                    )
        except (OSError, ValueError):
            pass  # non-Linux or unreadable; let scapy surface the real error
        if hasattr(os, "geteuid") and os.geteuid() != 0:
            return False, "monitor-mode capture requires root (sudo) or CAP_NET_RAW"
        return True, ""

    def _hopper(self):
        if not self.channels:
            return
        i = 0
        while not self._stop_evt.is_set():
            set_channel(self.iface, self.channels[i % len(self.channels)])
            i += 1
            self._stop_evt.wait(self.hop_interval)

    def stream(self) -> Iterator[Sighting]:
        from scapy.sendrecv import AsyncSniffer  # lazy

        q: "queue.Queue" = queue.Queue(maxsize=10000)

        def _cb(pkt):
            s = parse_dot11(pkt)
            if s is not None:
                try:
                    q.put_nowait(s)
                except queue.Full:
                    pass  # drop under load rather than block the sniffer thread

        sniffer = AsyncSniffer(
            iface=self.iface, monitor=True, store=False, prn=_cb, filter=self.bpf
        )
        sniffer.start()
        hop = threading.Thread(target=self._hopper, daemon=True)
        hop.start()
        try:
            while True:
                try:
                    yield q.get(timeout=0.5)
                except queue.Empty:
                    if not sniffer.running:
                        break
        finally:
            self.close()
            try:
                sniffer.stop()
            except Exception:
                pass

    def close(self) -> None:
        self._stop_evt.set()
