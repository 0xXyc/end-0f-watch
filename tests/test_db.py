from end_0f_watch.db import OuiDatabase


def db():
    return OuiDatabase.load()  # packaged data/police_ouis.json


def test_loads_and_has_core_vendors():
    d = db()
    assert "axon-enterprise" in d.vendors
    assert d.vendors["axon-enterprise"].police_confidence == "high"
    assert d.vendors["axon-enterprise"].ota_emission == "confirmed"
    assert d.stats()["vendors"] >= 25


def test_module_only_vendors_documented():
    d = db()
    # Real LE vendors with no IEEE OUI (detection blind spots) are documented.
    assert d.stats()["module_vendors"] >= 5
    ids = {m.id for m in d.module_vendors}
    assert {"getac", "coban-technologies", "bk-technologies"} <= ids


def test_ota_emission_values_valid():
    from end_0f_watch.models import OTA_EMISSION
    for v in db().vendors.values():
        assert v.ota_emission in OTA_EMISSION, v.id


def test_lookup_ma_l_24bit():
    m = db().lookup("00:25:DF:12:34:56")
    assert m is not None
    assert m.vendor.id == "axon-enterprise"
    assert m.bits == 24


def test_lookup_ma_m_28bit_matches_and_respects_boundary():
    d = db()
    # 38:73:EA:0x is L-3 Mobile-Vision (28-bit block 3873EA0)
    hit = d.lookup("38:73:EA:01:02:03")
    assert hit is not None and hit.vendor.id == "l3-mobile-vision" and hit.bits == 28
    # 38:73:EA:F0 shares only the 24-bit 3873EA prefix, which is NOT registered -> no match
    assert d.lookup("38:73:EA:F0:00:00") is None


def test_federal_signal_28bit():
    hit = db().lookup("08:3C:03:01:22:33")
    assert hit is not None and hit.vendor.id == "federal-signal"


def test_excluded_prefix_not_matched_but_explained():
    d = db()
    assert d.lookup("00:58:28:00:00:01") is None          # Axon Networks (defunct), excluded
    reason = d.excluded_reason("00:58:28:00:00:01")
    assert reason                                          # has an explanation
    assert "Axon Enterprise" in reason                     # explains the trap it's distinguished from


def test_no_conflicting_prefixes_across_vendors():
    # Constructor raises on conflicts; loading cleanly proves uniqueness.
    d = db()
    seen = set()
    for v in d.vendors.values():
        for o in v.ouis:
            assert (o.bits, o.prefix_hex) not in seen
            seen.add((o.bits, o.prefix_hex))


def test_all_categories_and_confidences_known():
    from end_0f_watch.models import CATEGORIES, CONFIDENCE_LEVELS
    d = db()
    for v in d.vendors.values():
        assert v.category in CATEGORIES, v.id
        assert v.police_confidence in CONFIDENCE_LEVELS, v.id
