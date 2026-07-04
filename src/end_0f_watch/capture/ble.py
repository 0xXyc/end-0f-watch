"""Bluetooth LE advertisement capture via bleak.

Passively listens for BLE advertising packets and emits a Sighting per device with
its address, RSSI, advertised local name, service UUIDs and manufacturer company
IDs. Purely observational — no connections are made.

Platform note: on Linux/BlueZ `device.address` is the real 48-bit BLE address (unless
the peripheral itself uses a random/resolvable-private address), so OUI matching
works. On macOS, CoreBluetooth hides the hardware address behind a per-host
peripheral UUID, so OUI attribution is unavailable there — only BLE-name/company-id
fingerprints apply (the classifier handles this gracefully).
"""
from __future__ import annotations

import asyncio
import queue
import sys
import threading
from typing import Iterator, Optional, Tuple

from ..models import Sighting
from .base import CaptureBackend

_STOP = object()


class BleCapture(CaptureBackend):
    name = "ble"

    def __init__(self, adapter: Optional[str] = None):
        self.adapter = adapter  # e.g. "hci0" on Linux; None = default
        self._stop_evt = threading.Event()

    def available(self) -> Tuple[bool, str]:
        try:
            import bleak  # noqa: F401
        except Exception:
            return False, "bleak is not installed (pip install '.[ble]')"
        return True, ""

    def stream(self) -> Iterator[Sighting]:
        from bleak import BleakScanner  # lazy

        q: "queue.Queue" = queue.Queue(maxsize=10000)

        def _detection(device, adv):
            company_ids = sorted((adv.manufacturer_data or {}).keys())
            s = Sighting(
                mac=device.address,
                source="ble",
                ts=0.0,
                rssi=getattr(adv, "rssi", None),
                ble_name=(adv.local_name or None),
                extra={
                    "company_ids": company_ids,
                    "service_uuids": list(adv.service_uuids or []),
                },
            )
            try:
                q.put_nowait(s)
            except queue.Full:
                pass

        async def _run():
            kwargs = {"detection_callback": _detection}
            if self.adapter:
                kwargs["adapter"] = self.adapter
            scanner = BleakScanner(**kwargs)
            try:
                await scanner.start()
            except Exception as exc:  # no adapter / bluetoothd down / DBus timeout
                self._error = exc
                return
            try:
                while not self._stop_evt.is_set():
                    await asyncio.sleep(0.25)
            finally:
                try:
                    await scanner.stop()
                except Exception:
                    pass

        def _thread_main():
            try:
                asyncio.run(_run())
            except Exception as exc:
                self._error = exc
            finally:
                q.put(_STOP)

        self._error = None
        t = threading.Thread(target=_thread_main, daemon=True)
        t.start()
        try:
            while True:
                item = q.get()
                if item is _STOP:
                    break
                yield item
        finally:
            self.close()

        # BLE failed to start: warn cleanly and yield nothing so a co-running
        # Wi-Fi scan keeps going instead of dumping a traceback.
        if self._error is not None:
            hint = ""
            if "bluez" in str(self._error).lower() or "org.bluez" in str(self._error):
                hint = (" — is a Bluetooth adapter present in this host and bluetoothd running? "
                        "try: sudo systemctl start bluetooth  (in a VM, pass through/enable Bluetooth)")
            print(f"[!] BLE scanning disabled: {self._error}{hint}", file=sys.stderr)

    def close(self) -> None:
        self._stop_evt.set()
