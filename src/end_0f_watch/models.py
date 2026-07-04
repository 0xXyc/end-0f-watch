"""Typed data models shared across the database, classifier, capture and output layers."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

# Device category taxonomy. Kept flat and stable so it can key colours/filters in the UI.
CATEGORIES = (
    "body_camera",
    "in_car_video",
    "lmr_radio",       # land-mobile / TETRA / P25 subscriber radios
    "mobile_router",   # cruiser cellular gateways
    "mdt_laptop",      # mobile data terminals / rugged laptops
    "satcom",
    "signaling",       # light bars, sirens, warning systems
    "surveillance",
)

CONFIDENCE_LEVELS = ("high", "medium", "low")

# How likely the vendor's *brand* OUI is to actually appear over-the-air. Many body
# cams / rugged MDTs emit their COTS radio-module maker's OUI instead, so a brand-OUI
# match is only meaningful for some classes. See data/police_ouis.json meta.
OTA_EMISSION = ("confirmed", "router_bssid", "unverified", "wired_only", "unknown")


@dataclass(frozen=True)
class Oui:
    """A single IEEE OUI assignment belonging to a vendor."""
    prefix_hex: str          # canonical uppercase nibbles, no separators (len 6/7/9)
    bits: int                # 24 / 28 / 36
    registry: str = ""       # MA-L / MA-M / MA-S
    org: str = ""            # IEEE-registered organization name
    loc: str = ""            # registered location (context only)


@dataclass
class Vendor:
    id: str
    name: str
    category: str
    police_confidence: str            # high | medium | low
    ota_emission: str = "unknown"     # see OTA_EMISSION
    note: str = ""
    aka: List[str] = field(default_factory=list)
    ouis: List[Oui] = field(default_factory=list)
    false_positive_notes: str = ""
    source: str = ""


@dataclass
class ModuleVendor:
    """A real LE vendor that holds NO IEEE OUI, so it cannot be matched by prefix.

    Documented so users understand the detection blind spot (their gear rides on a
    COTS Wi-Fi/BLE module maker's OUI, not a brand OUI).
    """
    id: str
    name: str
    category: str
    reason: str = ""


@dataclass(frozen=True)
class Fingerprint:
    """A secondary, non-OUI signal (SSID / BLE name / BLE company-id) that corroborates a vendor."""
    vendor_id: str
    kind: str                # wifi_ssid | ble_local_name | ble_company_id
    pattern: str             # regex, matched case-insensitively
    confidence: str = "low"
    caveat: str = ""
    source: str = ""


@dataclass
class Match:
    """Result of an OUI lookup: which vendor a MAC's prefix resolves to."""
    vendor: Vendor
    oui: Oui
    bits: int


@dataclass
class Sighting:
    """One raw observation emitted by a capture backend."""
    mac: str
    source: str                       # wifi | ble | replay
    ts: float = 0.0
    rssi: Optional[int] = None
    channel: Optional[int] = None
    ssid: Optional[str] = None
    ble_name: Optional[str] = None
    extra: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Detection:
    """A sighting enriched with classification (OUI match, fingerprints, score)."""
    sighting: Sighting
    match: Optional[Match]
    fingerprint_hits: List[Fingerprint]
    randomized: bool                  # locally-administered/randomized source MAC
    oui_capable: bool                 # False for opaque ids (e.g. macOS CoreBluetooth UUIDs)
    score: float
    confidence: str                   # high | medium | low
    category: Optional[str]
    reasons: List[str]

    @property
    def is_hit(self) -> bool:
        return self.match is not None or bool(self.fingerprint_hits)

    @property
    def vendor(self) -> Optional[Vendor]:
        if self.match is not None:
            return self.match.vendor
        return None

    def to_dict(self) -> Dict[str, Any]:
        s = self.sighting
        v = self.vendor
        return {
            "ts": s.ts,
            "mac": s.mac,
            "source": s.source,
            "rssi": s.rssi,
            "channel": s.channel,
            "ssid": s.ssid,
            "ble_name": s.ble_name,
            "vendor": v.name if v else None,
            "vendor_id": v.id if v else None,
            "category": self.category,
            "matched_oui": _fmt_oui(self.match),
            "match_bits": self.match.bits if self.match else None,
            "fingerprints": [
                {"vendor_id": fp.vendor_id, "kind": fp.kind, "pattern": fp.pattern}
                for fp in self.fingerprint_hits
            ],
            "randomized": self.randomized,
            "oui_capable": self.oui_capable,
            "score": round(self.score, 3),
            "confidence": self.confidence,
            "reasons": self.reasons,
        }


def _fmt_oui(match: Optional[Match]) -> Optional[str]:
    if match is None:
        return None
    from .util import format_prefix
    return format_prefix(match.oui.prefix_hex)
