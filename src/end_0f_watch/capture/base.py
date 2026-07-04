"""Abstract capture backend contract."""
from __future__ import annotations

from typing import Iterator, Tuple

from ..models import Sighting


class CaptureBackend:
    """A source of `Sighting` events.

    Subclasses implement `stream()` as a generator. `available()` performs a cheap
    pre-flight check (deps installed, interface present, privileges) so the CLI can
    fail fast with an actionable message instead of deep inside a sniff loop.
    """

    name: str = "base"

    def available(self) -> Tuple[bool, str]:
        """Return (ok, reason). reason is a human-readable explanation when not ok."""
        return True, ""

    def stream(self) -> Iterator[Sighting]:
        raise NotImplementedError

    def close(self) -> None:
        pass
