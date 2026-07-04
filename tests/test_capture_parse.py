"""Validate the 802.11 parse path with synthetic scapy frames (no radio needed).

Skipped automatically if scapy is not installed.
"""
import pytest

scapy_all = pytest.importorskip("scapy.all")

from scapy.all import RadioTap, Dot11, Dot11Beacon, Dot11ProbeReq, Dot11Elt  # noqa: E402

from end_0f_watch.capture.wifi import parse_dot11  # noqa: E402


def test_parse_beacon_extracts_mac_and_ssid():
    pkt = (
        RadioTap()
        / Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff",
                addr2="00:25:df:12:34:56", addr3="00:25:df:12:34:56")
        / Dot11Beacon()
        / Dot11Elt(ID=0, info=b"POLICE-AP")
    )
    s = parse_dot11(pkt)
    assert s is not None
    assert s.mac.lower() == "00:25:df:12:34:56"
    assert s.ssid == "POLICE-AP"
    assert s.source == "wifi"


def test_parse_probe_request_source_mac():
    pkt = (
        RadioTap()
        / Dot11(type=0, subtype=4, addr1="ff:ff:ff:ff:ff:ff",
                addr2="64:ce:6e:aa:bb:cc", addr3="ff:ff:ff:ff:ff:ff")
        / Dot11ProbeReq()
        / Dot11Elt(ID=0, info=b"")  # wildcard probe
    )
    s = parse_dot11(pkt)
    assert s is not None
    assert s.mac.lower() == "64:ce:6e:aa:bb:cc"


def test_parse_frame_without_dot11_is_ignored():
    assert parse_dot11(RadioTap()) is None


def test_parse_broadcast_source_is_dropped():
    pkt = RadioTap() / Dot11(type=0, subtype=8, addr2="ff:ff:ff:ff:ff:ff")
    assert parse_dot11(pkt) is None
