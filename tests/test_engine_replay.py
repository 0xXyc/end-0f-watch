import os

from end_0f_watch.capture.replay import MacListReplay
from end_0f_watch.classifier import Classifier
from end_0f_watch.db import OuiDatabase
from end_0f_watch.engine import run_scan
from end_0f_watch.output import Sink

FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "sample_macs.txt")


class CollectSink(Sink):
    def __init__(self):
        self.emitted = []

    def emit(self, det, first_seen):
        self.emitted.append((det, first_seen))

    def close(self):
        pass


def test_replay_end_to_end():
    clf = Classifier(OuiDatabase.load())
    sink = CollectSink()
    seen, counts = run_scan([MacListReplay(FIXTURE)], clf, sink, min_confidence="low")

    ids = {d.vendor.id for d in seen.values() if d.vendor}
    assert "axon-enterprise" in ids
    assert "sierra-wireless" in ids
    assert "l3-mobile-vision" in ids
    assert "watchguard-video" in ids

    # randomized / excluded / unrelated MACs must NOT be flagged
    macs = set(seen.keys())
    assert "02:11:22:33:44:55" not in macs
    assert "00:58:28:00:00:01" not in macs
    assert "DE:AD:BE:EF:00:01" not in macs


def test_min_confidence_filter_high_only():
    clf = Classifier(OuiDatabase.load())
    sink = CollectSink()
    seen, _ = run_scan([MacListReplay(FIXTURE)], clf, sink, min_confidence="high")
    for det in seen.values():
        assert det.confidence == "high"
    # Sierra (low) is filtered out at high threshold
    assert "64:CE:6E:AA:BB:CC" not in seen
