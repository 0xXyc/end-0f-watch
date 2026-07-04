"""Scan engine: fan several capture backends into one classified, de-duplicated stream."""
from __future__ import annotations

import queue
import threading
import time
from typing import Callable, Dict, Iterator, List, Optional, Tuple

from .classifier import Classifier
from .models import Detection, Sighting
from .output import Sink
from .util import normalize_mac

_STOP = object()
_CONF_ORDER = {"high": 0, "medium": 1, "low": 2}


def merge_streams(backends: List, stop_evt: threading.Event) -> Iterator[Sighting]:
    """Run each backend.stream() in its own thread; yield sightings as they arrive."""
    q: "queue.Queue" = queue.Queue(maxsize=20000)
    live = {"n": len(backends)}
    lock = threading.Lock()

    def _pump(backend):
        try:
            for s in backend.stream():
                if stop_evt.is_set():
                    break
                try:
                    q.put(s, timeout=0.5)
                except queue.Full:
                    pass
        except Exception as exc:  # surface but don't kill sibling backends
            q.put(("__error__", backend.name, repr(exc)))
        finally:
            with lock:
                live["n"] -= 1
            q.put(_STOP)

    threads = []
    for b in backends:
        t = threading.Thread(target=_pump, args=(b,), daemon=True)
        t.start()
        threads.append(t)

    finished = 0
    total = len(backends)
    while finished < total:
        try:
            item = q.get(timeout=0.3)
        except queue.Empty:
            if stop_evt.is_set():
                break
            continue
        if item is _STOP:
            finished += 1
            continue
        if isinstance(item, tuple) and item and item[0] == "__error__":
            raise RuntimeError(f"capture backend {item[1]!r} failed: {item[2]}")
        yield item


def _key(sighting: Sighting) -> str:
    try:
        return normalize_mac(sighting.mac)
    except ValueError:
        return sighting.mac


def run_scan(
    backends: List,
    classifier: Classifier,
    sink: Sink,
    min_confidence: str = "low",
    duration: Optional[float] = None,
    stop_evt: Optional[threading.Event] = None,
) -> Tuple[Dict[str, Detection], Dict[str, int]]:
    """Consume backends until duration elapses, stop_evt is set, or KeyboardInterrupt.

    Returns (unique_detections_by_key, sighting_counts_by_key).
    """
    stop_evt = stop_evt or threading.Event()
    threshold = _CONF_ORDER.get(min_confidence, 2)
    seen: Dict[str, Detection] = {}
    counts: Dict[str, int] = {}
    start = time.monotonic()

    def _close():
        stop_evt.set()
        for b in backends:
            try:
                b.close()
            except Exception:
                pass

    try:
        for sighting in merge_streams(backends, stop_evt):
            if duration is not None and (time.monotonic() - start) >= duration:
                break
            if not sighting.ts:
                sighting.ts = time.time()
            det = classifier.classify(sighting)
            if not det.is_hit:
                continue
            if _CONF_ORDER.get(det.confidence, 2) > threshold:
                continue
            key = _key(sighting)
            first_seen = key not in seen
            counts[key] = counts.get(key, 0) + 1
            if first_seen:
                seen[key] = det
            sink.emit(det, first_seen)
    except KeyboardInterrupt:
        # Ctrl-C: stop cleanly and return whatever we accumulated so far.
        pass
    finally:
        _close()

    return seen, counts
