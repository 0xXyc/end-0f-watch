"""end-0f-watch — passive RF reconnaissance for police body-cam & cruiser device OUIs.

This package matches *publicly broadcast* Wi-Fi/BLE source MAC addresses against a
curated database of IEEE OUI assignments held by law-enforcement equipment vendors
(body cameras, in-car video, LMR radios, cruiser cellular routers, rugged MDTs).

It is a passive receive-only research tool. It never transmits, associates,
injects, jams, or decodes payload contents. See README.md for scope and caveats.
"""

__version__ = "0.2.0"

from .models import Vendor, Oui, Fingerprint, Match, Sighting, Detection  # noqa: E402
from .db import OuiDatabase  # noqa: E402
from .classifier import Classifier  # noqa: E402

__all__ = [
    "__version__",
    "Vendor",
    "Oui",
    "Fingerprint",
    "Match",
    "Sighting",
    "Detection",
    "OuiDatabase",
    "Classifier",
]
