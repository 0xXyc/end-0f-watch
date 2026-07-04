from end_0f_watch.classifier import Classifier, score_to_confidence
from end_0f_watch.db import OuiDatabase
from end_0f_watch.models import Sighting


def real_db():
    return OuiDatabase.load()


def clf():
    return Classifier(real_db())


def test_high_confidence_axon():
    det = clf().classify(Sighting(mac="00:25:DF:12:34:56", source="wifi"))
    assert det.is_hit
    assert det.vendor.id == "axon-enterprise"
    assert det.category == "body_camera"
    assert det.confidence == "high"


def test_low_confidence_vendor():
    # Icom (00:90:C7) is a commercial-dominant LMR maker -> low police-confidence.
    det = clf().classify(Sighting(mac="00:90:C7:AA:BB:CC", source="wifi"))
    assert det.is_hit
    assert det.confidence == "low"


def test_sierra_is_medium_now():
    # FirstNet AirLink routers bumped Sierra low -> medium in v0.2.
    det = clf().classify(Sighting(mac="64:CE:6E:AA:BB:CC", source="wifi"))
    assert det.is_hit
    assert det.confidence == "medium"


def test_ota_wired_only_caps_score():
    # A high-confidence vendor whose brand OUI is wired-only must be capped low,
    # because the over-the-air MAC is a COTS module OUI, not this prefix.
    db = OuiDatabase({"vendors": [{
        "id": "toughbook-x", "name": "X", "category": "mdt_laptop",
        "police_confidence": "high", "ota_emission": "wired_only",
        "ouis": [{"prefix": "00:25:DF"}],
    }]})
    det = Classifier(db).classify(Sighting(mac="00:25:DF:00:00:01", source="wifi"))
    assert det.is_hit
    assert det.score <= 0.30
    assert det.confidence == "low"
    assert any("wired" in r.lower() for r in det.reasons)


def test_ota_confirmed_annotated():
    det = clf().classify(Sighting(mac="00:25:DF:12:34:56", source="wifi"))  # Axon: confirmed
    assert any("on-air" in r for r in det.reasons)


def test_randomized_mac_not_attributed():
    det = clf().classify(Sighting(mac="02:11:22:33:44:55", source="wifi"))
    assert det.randomized
    assert not det.is_hit
    assert any("randomized" in r for r in det.reasons)


def test_excluded_trap_not_a_hit():
    det = clf().classify(Sighting(mac="00:58:28:00:00:01", source="wifi"))
    assert not det.is_hit
    assert any("false-positive trap" in r for r in det.reasons)


def test_non_mac_identifier_is_graceful():
    # macOS CoreBluetooth UUID-style identifier
    det = clf().classify(Sighting(mac="A1B2C3D4-1234-5678-9ABC-DEF012345678", source="ble"))
    assert det.oui_capable is False
    assert not det.is_hit  # no fingerprints configured to match


# ---- fingerprint behaviour with a small synthetic DB -----------------------
def _fp_db():
    return OuiDatabase({
        "vendors": [{
            "id": "axon-enterprise", "name": "Axon", "category": "body_camera",
            "police_confidence": "high", "ouis": [{"prefix": "00:25:DF"}],
        }],
        "fingerprints": [{
            "vendor_id": "axon-enterprise", "kind": "wifi_ssid",
            "pattern": r"^AXON", "confidence": "medium",
        }],
    })


def test_standalone_fingerprint_on_randomized_mac():
    c = Classifier(_fp_db())
    det = c.classify(Sighting(mac="02:AA:BB:CC:DD:EE", source="wifi", ssid="AXON-1234"))
    assert det.is_hit
    assert det.match is None            # randomized -> no OUI attribution
    assert det.fingerprint_hits
    assert det.category == "body_camera"


def test_fingerprint_corroboration_boosts_score():
    c = Classifier(_fp_db())
    plain = c.classify(Sighting(mac="00:25:DF:00:00:01", source="wifi"))
    boosted = c.classify(Sighting(mac="00:25:DF:00:00:01", source="wifi", ssid="AXON-9"))
    assert boosted.score > plain.score


def test_standalone_fingerprint_tracks_fp_strength():
    # On a randomized MAC (no OUI), confidence should follow the fingerprint's own strength.
    c = clf()  # real DB
    weak = c.classify(Sighting(mac="02:11:22:33:44:55", source="wifi", ssid="IBR900-a1b"))
    assert weak.is_hit and weak.confidence == "low"        # Cradlepoint SSID fp = low
    axon = c.classify(Sighting(mac="02:11:22:33:44:55", source="wifi", ssid="AXON-X6032638M"))
    assert axon.is_hit and axon.confidence == "medium"     # Axon SoftAP fp = medium


def test_score_to_confidence_thresholds():
    assert score_to_confidence(0.85) == "high"
    assert score_to_confidence(0.55) == "medium"
    assert score_to_confidence(0.30) == "low"
