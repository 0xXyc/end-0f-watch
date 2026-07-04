import pytest

from end_0f_watch.util import (
    format_prefix,
    freq_to_channel,
    is_broadcast,
    is_locally_administered,
    is_multicast,
    mac_hex,
    normalize_mac,
    normalize_prefix,
    prefix_candidates,
)


@pytest.mark.parametrize("raw,expected", [
    ("0025df123456", "00:25:DF:12:34:56"),
    ("00-25-DF-12-34-56", "00:25:DF:12:34:56"),
    ("00:25:df:12:34:56", "00:25:DF:12:34:56"),
    ("0025.df12.3456", "00:25:DF:12:34:56"),
])
def test_normalize_mac(raw, expected):
    assert normalize_mac(raw) == expected


@pytest.mark.parametrize("bad", ["", "00:25:DF", "zz:25:df:12:34:56", "0025df1234567"])
def test_normalize_mac_bad(bad):
    with pytest.raises(ValueError):
        normalize_mac(bad)


def test_prefix_candidates_order_and_values():
    cands = list(prefix_candidates("00:25:DF:12:34:56"))
    assert cands == [("0025DF123", 36), ("0025DF1", 28), ("0025DF", 24)]


def test_locally_administered_and_group_bits():
    assert is_locally_administered("02:00:00:00:00:00")   # bit 1 set
    assert not is_locally_administered("00:25:DF:00:00:00")
    assert is_multicast("01:00:5E:00:00:01")
    assert not is_multicast("00:25:DF:00:00:00")
    assert is_broadcast("ff:ff:ff:ff:ff:ff")


@pytest.mark.parametrize("assign,hexp,bits", [
    ("00:25:DF", "0025DF", 24),
    ("3873EA0", "3873EA0", 28),
    ("70B3D5FED", "70B3D5FED", 36),
])
def test_normalize_prefix(assign, hexp, bits):
    assert normalize_prefix(assign) == (hexp, bits)


def test_normalize_prefix_bad_length():
    with pytest.raises(ValueError):
        normalize_prefix("00:25")  # 4 nibbles -> 16 bits, unsupported


def test_format_prefix():
    assert format_prefix("0025DF") == "00:25:DF"
    assert format_prefix("3873EA0") == "38:73:EA:0"
    assert format_prefix("70B3D5FED") == "70:B3:D5:FE:D"


@pytest.mark.parametrize("freq,ch", [(2412, 1), (2437, 6), (2484, 14), (5180, 36), (5955, 1)])
def test_freq_to_channel(freq, ch):
    assert freq_to_channel(freq) == ch


def test_mac_hex_roundtrip():
    assert mac_hex("00:25:DF:12:34:56") == "0025DF123456"
