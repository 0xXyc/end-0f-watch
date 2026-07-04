"""Capture backends. Each yields `Sighting` objects from a live or recorded source.

Backends import their heavy third-party deps (scapy, bleak) lazily so the package
and its DB tooling work even when those libraries are not installed.
"""
from .base import CaptureBackend

__all__ = ["CaptureBackend"]
