"""The OUI database: load the curated JSON, index it, and resolve MACs to vendors."""
from __future__ import annotations

import json
import os
import re
from typing import Dict, List, Optional, Tuple

from .models import Fingerprint, Match, ModuleVendor, Oui, Vendor
from .util import normalize_prefix, prefix_candidates

# Packaged default DB lives at <repo>/data/police_ouis.json relative to this file.
_DEFAULT_DB = os.path.normpath(
    os.path.join(os.path.dirname(__file__), "..", "..", "data", "police_ouis.json")
)


def default_db_path() -> str:
    env = os.environ.get("EOW_DB")
    return env if env else _DEFAULT_DB


class OuiDatabase:
    """Indexes curated vendor/OUI data for O(1) longest-prefix MAC lookup."""

    def __init__(self, data: dict):
        self.meta: dict = data.get("meta", {})
        self.vendors: Dict[str, Vendor] = {}
        # bits -> {prefix_hex: (Vendor, Oui)}
        self._by_bits: Dict[int, Dict[str, Tuple[Vendor, Oui]]] = {24: {}, 28: {}, 36: {}}
        # prefix_hex -> reason (documented false-positive traps, never matched)
        self.exclusions: Dict[str, str] = {}
        self.fingerprints: List[Fingerprint] = []
        self._compiled: List[Tuple[Fingerprint, "re.Pattern[str]"]] = []
        # Real LE vendors with no IEEE OUI (documented detection blind spots).
        self.module_vendors: List[ModuleVendor] = []
        self._load(data)

    # ---- construction -----------------------------------------------------
    @classmethod
    def load(cls, path: Optional[str] = None) -> "OuiDatabase":
        path = path or default_db_path()
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except FileNotFoundError as exc:
            raise FileNotFoundError(
                f"OUI database not found at {path!r}. "
                "Pass --db, set EOW_DB, or run `end-0f-watch update-db`."
            ) from exc
        db = cls(data)
        db.path = path  # type: ignore[attr-defined]
        return db

    def _load(self, data: dict) -> None:
        for vd in data.get("vendors", []):
            ouis: List[Oui] = []
            for od in vd.get("ouis", []):
                prefix_hex, bits = normalize_prefix(od["prefix"])
                ouis.append(
                    Oui(
                        prefix_hex=prefix_hex,
                        bits=bits,
                        registry=od.get("registry", ""),
                        org=od.get("org", ""),
                        loc=od.get("loc", ""),
                    )
                )
            vendor = Vendor(
                id=vd["id"],
                name=vd["name"],
                category=vd.get("category", ""),
                police_confidence=vd.get("police_confidence", "low"),
                ota_emission=vd.get("ota_emission", "unknown"),
                note=vd.get("note", ""),
                aka=list(vd.get("aka", [])),
                ouis=ouis,
                false_positive_notes=vd.get("false_positive_notes", ""),
                source=vd.get("source", ""),
            )
            self.vendors[vendor.id] = vendor
            for oui in ouis:
                table = self._by_bits.setdefault(oui.bits, {})
                if oui.prefix_hex in table:
                    other = table[oui.prefix_hex][0]
                    if other.id != vendor.id:
                        raise ValueError(
                            f"OUI {oui.prefix_hex} claimed by both {other.id!r} and {vendor.id!r}"
                        )
                table[oui.prefix_hex] = (vendor, oui)

        for ex in data.get("exclusions", []):
            prefix_hex, _bits = normalize_prefix(ex["prefix"])
            self.exclusions[prefix_hex] = ex.get("reason", "")

        for fp in data.get("fingerprints", []):
            f = Fingerprint(
                vendor_id=fp.get("vendor_id", ""),
                kind=fp["kind"],
                pattern=fp["pattern"],
                confidence=fp.get("confidence", "low"),
                caveat=fp.get("caveat", ""),
                source=fp.get("source", ""),
            )
            self.fingerprints.append(f)
            self._compiled.append((f, re.compile(f.pattern, re.IGNORECASE)))

        for mv in data.get("module_oui_vendors", []):
            self.module_vendors.append(
                ModuleVendor(
                    id=mv["id"],
                    name=mv["name"],
                    category=mv.get("category", ""),
                    reason=mv.get("reason", ""),
                )
            )

    # ---- queries ----------------------------------------------------------
    def lookup(self, mac: str) -> Optional[Match]:
        """Longest-prefix match a MAC to a vendor OUI, or None."""
        for prefix_hex, bits in prefix_candidates(mac):
            hit = self._by_bits.get(bits, {}).get(prefix_hex)
            if hit:
                vendor, oui = hit
                return Match(vendor=vendor, oui=oui, bits=bits)
        return None

    def excluded_reason(self, mac: str) -> Optional[str]:
        """If the MAC's prefix is a documented false-positive trap, return why."""
        for prefix_hex, _bits in prefix_candidates(mac):
            if prefix_hex in self.exclusions:
                return self.exclusions[prefix_hex]
        return None

    def match_fingerprints(self, kind: str, text: str) -> List[Fingerprint]:
        if not text:
            return []
        return [fp for fp, rx in self._compiled if fp.kind == kind and rx.search(text)]

    # ---- introspection ----------------------------------------------------
    def stats(self) -> dict:
        by_cat: Dict[str, int] = {}
        oui_total = 0
        for v in self.vendors.values():
            by_cat[v.category] = by_cat.get(v.category, 0) + 1
            oui_total += len(v.ouis)
        return {
            "vendors": len(self.vendors),
            "ouis": oui_total,
            "exclusions": len(self.exclusions),
            "fingerprints": len(self.fingerprints),
            "module_vendors": len(self.module_vendors),
            "by_category": dict(sorted(by_cat.items())),
            "meta": self.meta,
        }

    def vendors_sorted(self) -> List[Vendor]:
        order = {"high": 0, "medium": 1, "low": 2}
        return sorted(
            self.vendors.values(),
            key=lambda v: (order.get(v.police_confidence, 3), v.category, v.name),
        )
