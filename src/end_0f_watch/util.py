"""Low-level helpers: MAC normalization, OUI prefix extraction, IEEE parsing.

OUI assignments come in three IEEE registry sizes:
    MA-L  -> 24-bit prefix  (6 hex nibbles,  e.g. 0025DF)
    MA-M  -> 28-bit prefix  (7 hex nibbles,  e.g. 3873EA0)
    MA-S  -> 36-bit prefix  (9 hex nibbles,  e.g. 70B3D5FED)

We represent every prefix canonically as an uppercase run of hex nibbles with no
separators, plus its bit length. Lookup is longest-prefix-match: a MAC is tested
against its 36-, then 28-, then 24-bit leading nibbles so an MA-S/MA-M assignment
wins over the broader 24-bit block it lives inside.
"""
from __future__ import annotations

import re
from typing import Iterator, Tuple

_HEX_RE = re.compile(r"[0-9A-Fa-f]")

# Longest first so prefix_candidates() yields the most specific match opportunity first.
PREFIX_BITS: Tuple[int, ...] = (36, 28, 24)


def _hex_only(s: str) -> str:
    return "".join(_HEX_RE.findall(s)).upper()


def mac_hex(mac: str) -> str:
    """Return the 12 uppercase hex nibbles of a MAC, no separators. Raises ValueError."""
    h = _hex_only(mac)
    if len(h) != 12:
        raise ValueError(f"invalid MAC address: {mac!r}")
    return h


def normalize_mac(mac: str) -> str:
    """Canonicalize any MAC spelling to 'AA:BB:CC:DD:EE:FF' (uppercase)."""
    h = mac_hex(mac)
    return ":".join(h[i:i + 2] for i in range(0, 12, 2))


def first_octet(mac: str) -> int:
    return int(mac_hex(mac)[0:2], 16)


def is_locally_administered(mac: str) -> bool:
    """True if the U/L bit (bit 1 of the first octet) is set.

    A set U/L bit means the address is locally administered rather than a
    globally-unique burned-in address. In practice this flags MAC randomization
    (phones, and increasingly Wi-Fi/BLE gear when not associated/docked), which
    makes OUI-based vendor attribution impossible for that frame.
    """
    return bool(first_octet(mac) & 0x02)


def is_multicast(mac: str) -> bool:
    """True if the I/G bit (bit 0 of the first octet) is set (group/multicast)."""
    return bool(first_octet(mac) & 0x01)


def is_broadcast(mac: str) -> bool:
    return mac_hex(mac) == "FFFFFFFFFFFF"


def prefix_candidates(mac: str) -> Iterator[Tuple[str, int]]:
    """Yield (prefix_hex, bits) for 36/28/24-bit lookups, longest (most specific) first."""
    h = mac_hex(mac)
    for bits in PREFIX_BITS:
        yield h[: bits // 4], bits


def normalize_prefix(assignment: str) -> Tuple[str, int]:
    """Parse an IEEE assignment string to (prefix_hex, bits).

    Accepts any spelling ('00:25:DF', '0025DF', '38:73:EA:0', '70B3D5FED').
    Derives the bit length from the nibble count so callers cannot desync
    a stored `bits` field from the actual prefix.
    """
    h = _hex_only(assignment)
    bits = len(h) * 4
    if bits not in PREFIX_BITS:
        raise ValueError(
            f"unexpected OUI prefix length: {assignment!r} -> {len(h)} nibbles ({bits} bits); "
            "expected 6 (MA-L), 7 (MA-M), or 9 (MA-S)"
        )
    return h, bits


def format_prefix(prefix_hex: str) -> str:
    """Render a canonical prefix hex string as colon-grouped octets/nibble.

    '0025DF' -> '00:25:DF' ; '3873EA0' -> '38:73:EA:0' ; '70B3D5FED' -> '70:B3:D5:FE:D'
    """
    pairs = [prefix_hex[i:i + 2] for i in range(0, len(prefix_hex), 2)]
    return ":".join(pairs)


def freq_to_channel(freq_mhz: int):
    """Map a RadioTap channel frequency (MHz) to a Wi-Fi channel number, or None."""
    try:
        f = int(freq_mhz)
    except (TypeError, ValueError):
        return None
    if f == 2484:
        return 14
    if 2412 <= f <= 2472:
        return (f - 2407) // 5
    if 5000 <= f <= 5900:
        return (f - 5000) // 5
    if 5955 <= f <= 7115:  # 6 GHz (Wi-Fi 6E)
        return (f - 5950) // 5
    return None
