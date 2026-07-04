"""Turn a raw Sighting into a scored Detection.

Scoring blends two independent signals:

  1. OUI match  -> base score from the vendor's `police_confidence`
                   (how exclusively that vendor's hardware means "police gear").
  2. Fingerprints (SSID / BLE local-name) -> corroboration that raises confidence,
                   or a standalone weak signal when the MAC is randomized and can't
                   be attributed by OUI.

The score is deliberately conservative. An OUI match is a *vendor* attribution,
never a device-model or a proof of active policing. The reasons[] list always
explains exactly why a detection fired so a researcher can audit it.
"""
from __future__ import annotations

from typing import Optional

from .db import OuiDatabase
from .models import Detection, Sighting
from .util import format_prefix, is_locally_administered, normalize_mac

# Base score contributed by an OUI match, keyed by the vendor's police_confidence.
_BASE = {"high": 0.85, "medium": 0.55, "low": 0.30}
# Each corroborating fingerprint adds this much on top of an OUI match (capped below).
_FP_BOOST = 0.20
# Standalone score when there is NO usable OUI, keyed by the fingerprint's own
# confidence (a name/SSID pattern is spoofable and weaker than a registered OUI).
_FP_STANDALONE = {"high": 0.60, "medium": 0.45, "low": 0.30}


def score_to_confidence(score: float) -> str:
    if score >= 0.70:
        return "high"
    if score >= 0.40:
        return "medium"
    return "low"


# Upper bound on score when the brand OUI is not expected to appear over-the-air.
_WIRED_ONLY_CAP = 0.30


class Classifier:
    def __init__(self, db: OuiDatabase):
        self.db = db

    @staticmethod
    def _apply_ota(ota: str, score: float, reasons: list) -> float:
        """Adjust/annotate score based on whether the brand OUI is emitted over-the-air."""
        if ota == "confirmed":
            reasons.append("brand OUI is confirmed on-air (Wi-Fi BSSID / non-randomized BLE)")
        elif ota == "router_bssid":
            reasons.append("router assigns this OUI to its Wi-Fi BSSID (emitted on-air)")
        elif ota == "unverified":
            reasons.append(
                "OTA emission of the brand OUI is UNVERIFIED for this device class "
                "(the radio may present a COTS module OUI instead)"
            )
        elif ota == "wired_only":
            if score > _WIRED_ONLY_CAP:
                score = _WIRED_ONLY_CAP
            reasons.append(
                "brand OUI appears on the WIRED NIC/dock only; over-the-air MAC is a COTS "
                "module OUI — a passive radio match on this prefix is unlikely (score capped)"
            )
        return score

    def classify(self, s: Sighting) -> Detection:
        reasons: list = []
        oui_capable = True
        randomized = False
        mac_norm: Optional[str] = None

        try:
            mac_norm = normalize_mac(s.mac)
        except ValueError:
            # Not a 48-bit MAC — e.g. a macOS CoreBluetooth peripheral UUID.
            oui_capable = False
            reasons.append(
                "identifier is not a 48-bit MAC (e.g. macOS CoreBluetooth UUID) — "
                "OUI attribution unavailable; using fingerprints only"
            )

        match = None
        score = 0.0
        category: Optional[str] = None

        if oui_capable and mac_norm is not None:
            randomized = is_locally_administered(mac_norm)
            if randomized:
                reasons.append(
                    "locally-administered / randomized source MAC — vendor OUI attribution not possible"
                )
            else:
                match = self.db.lookup(mac_norm)
                if match is not None:
                    score = _BASE.get(match.vendor.police_confidence, _BASE["low"])
                    category = match.vendor.category
                    reasons.append(
                        f"OUI {format_prefix(match.oui.prefix_hex)} -> {match.vendor.name} "
                        f"[{match.vendor.category}] ({match.vendor.police_confidence} police-confidence)"
                    )
                    score = self._apply_ota(match.vendor.ota_emission, score, reasons)
                else:
                    excluded = self.db.excluded_reason(mac_norm)
                    if excluded:
                        reasons.append(f"OUI is a known false-positive trap, ignored: {excluded}")

        # Fingerprints (SSID + BLE local name). These run even for randomized/UUID sources.
        fp_hits = []
        for kind, text in (("wifi_ssid", s.ssid), ("ble_local_name", s.ble_name)):
            if not text:
                continue
            for fp in self.db.match_fingerprints(kind, text):
                fp_hits.append(fp)
                vname = self.db.vendors.get(fp.vendor_id)
                reasons.append(
                    f"{kind} {text!r} matches /{fp.pattern}/ -> "
                    f"{vname.name if vname else fp.vendor_id}"
                    + (f" (caveat: {fp.caveat})" if fp.caveat else "")
                )

        if fp_hits:
            if match is not None:
                # Corroboration on top of an OUI match.
                score = min(0.99, score + min(_FP_BOOST * len(fp_hits), 0.40))
            else:
                # Standalone fingerprint evidence (no usable OUI). Score by the
                # strongest matching fingerprint's own confidence, with a small
                # bump for multiple independent hits; capped since names are spoofable.
                best = max(
                    (_FP_STANDALONE.get(fp.confidence, 0.30) for fp in fp_hits),
                    default=0.30,
                )
                score = min(0.75, best + 0.05 * (len(fp_hits) - 1))
                if category is None:
                    fv = self.db.vendors.get(fp_hits[0].vendor_id)
                    category = fv.category if fv else None

        return Detection(
            sighting=s,
            match=match,
            fingerprint_hits=fp_hits,
            randomized=randomized,
            oui_capable=oui_capable,
            score=score,
            confidence=score_to_confidence(score),
            category=category,
            reasons=reasons,
        )
