# end-0f-watch

Passive RF-reconnaissance CLI for **security/privacy research**. It listens for
*publicly broadcast* Wi-Fi (802.11) and Bluetooth-LE frames, extracts the source
**MAC address**, and matches the **OUI** (the vendor-assigned first 24–36 bits)
against a curated database of IEEE registrations held by law-enforcement equipment
makers — body cameras, in-car/dash video, LMR/TETRA radios, cruiser cellular
routers, and rugged mobile data terminals.

It is the same core mechanism as Wireshark's `manuf`, Kismet, and airodump-ng,
narrowed to a hand-verified police-equipment vendor set with honest confidence
scoring.

---

## ⚖️ Scope, ethics & legality — read first

- **Passive / receive-only.** The tool never transmits, associates, probes,
  injects, deauthenticates, jams, or decodes payload contents. It only *observes*
  frames that devices already broadcast into open air.
- **An OUI identifies a *vendor*, not a device model, and is never proof of active
  policing.** A `Sierra Wireless` OUI could be a police cruiser router or a vending
  machine. Confidence scoring reflects this; treat every hit as a lead, not a fact.
- **Know your local law.** Passively *receiving* RF is legal in many jurisdictions,
  but rules differ and some cover interception/decryption/logging. You are
  responsible for compliance where you operate.
- **Intended uses:** surveillance-transparency and privacy research, academic study
  of policing technology, protest-safety and journalist-safety research, RF/IoT
  device-fingerprinting research, and defensive awareness of what your own gear
  leaks.
- **Do not** use this to target, track, stalk, ambush, or harass any person, or to
  interfere with lawful activity. That is out of scope and not supported.

---

## How it works

```
 Wi-Fi monitor  ─┐
                 ├─►  Sighting (MAC, RSSI, channel, SSID / BLE name)
 BLE scanner    ─┘            │
                              ▼
                        Classifier ── OUI longest-prefix match (24/28/36-bit)
                              │        + SSID / BLE-name fingerprints
                              ▼
                         Detection (vendor, category, confidence, reasons[])
                              │
                         Console · JSONL · CSV
```

**Confidence** encodes *how exclusively* a vendor's hardware means "police gear":

| Level    | Meaning                                                                                  |
|----------|------------------------------------------------------------------------------------------|
| `high`   | Near-exclusive LE / first-responder vendor (e.g. Axon). A match is strong evidence.      |
| `medium` | Public-safety-heavy but also sells enterprise/consumer lines. Corroborate.               |
| `low`    | General-purpose device merely *common* in cruisers. Weak on its own.                     |

Fingerprints (advertised SSID / BLE local-name patterns) can **corroborate** an OUI
match (raising confidence) or stand alone as a weak signal when the MAC is randomized.

**`ota_emission`** — a second, subtler dimension. Holding an OUI is not the same as
*emitting* it over the air. Most body cams and rugged laptops put their COTS Wi-Fi/BLE
**module** maker's OUI (Intel, Qualcomm, Nordic…) on the air, and expose the *brand*
OUI only on a wired NIC or dock. So each vendor is tagged:

| `ota_emission` | Meaning | Effect on score |
|----------------|---------|-----------------|
| `confirmed`    | Brand OUI documented on-air (Wi-Fi BSSID / non-random BLE). **Only Axon.** | none |
| `router_bssid` | Router puts its brand OUI on its Wi-Fi BSSID (emitted). Cradlepoint/Sierra/Peplink. | none |
| `unverified`   | Unknown if the device radio emits the brand OUI (most cameras). | annotated |
| `wired_only`   | Brand OUI on wired NIC/dock only; OTA MAC is a module OUI. Toughbook/Dell. | **capped low** |
| `unknown`      | Not characterized (most LMR radios). | none |

---

## Install

```bash
git clone git@github.com:0xXyc/end-0f-watch.git && cd end-0f-watch
python3 -m venv .venv && . .venv/bin/activate

# DB / lookup / replay only (no capture deps):
pip install -e .

# With live capture backends:
pip install -e '.[capture]'   # scapy + bleak
pip install -e '.[wifi]'      # scapy only
pip install -e '.[ble]'       # bleak only
```

The `db`, `lookup`, and `replay --macs` commands work with **no** third-party
dependencies. `scapy`/`bleak` are imported lazily only when you actually capture.

Installs two console entry points for the same tool: **`end-0f-watch`** and the short
alias **`eow`** (used throughout the examples below). `python -m end_0f_watch` also works.

---

## Usage

```bash
# Classify one or more MACs (offline, instant)
eow lookup 00:25:DF:12:34:56 64:CE:6E:AA:BB:CC

# Inspect / validate the database
eow db                       # stats
eow db --list                # all vendors + OUIs, ranked by confidence
eow db --list --category body_camera
eow db --modules             # real LE vendors that hold NO OUI (blind spots)
eow db --validate

# Analyze a recorded capture or a plain MAC list — no radio needed
eow replay capture.pcap
eow replay --macs tests/fixtures/sample_macs.txt

# Live passive scan (Linux + monitor-mode adapter recommended)
sudo eow scan --wifi --iface wlan0mon --channels 1,6,11
sudo eow scan --ble
sudo eow scan --wifi --iface wlan0mon --ble --min-confidence medium \
        --json hits.jsonl --csv hits.csv --duration 300

# Refresh the curated DB from the live IEEE registry
eow update-db --check        # dry-run: show drift vs IEEE
eow update-db                 # write data/police_ouis.json
eow update-db --offline --ieee-dir data   # use cached CSVs
```

### Enabling Wi-Fi monitor mode (Linux)

```bash
sudo airmon-ng start wlan0                 # -> wlan0mon
# or, manually:
sudo ip link set wlan0 down
sudo iw dev wlan0 set type monitor
sudo ip link set wlan0 up
```

`eow scan --wifi` pre-flights the interface and prints these instructions if
it is not already in monitor mode. Live capture needs root (or `CAP_NET_RAW`).

---

## The database (`data/police_ouis.json`)

A single, hand-editable JSON file — **the source of truth for attribution**. Each
vendor carries its category, police-confidence, notes, and OUI prefixes; a separate
`exclusions[]` list documents name-collision traps that must *never* match.

```jsonc
{
  "vendors": [{
    "id": "axon-enterprise",
    "name": "Axon Enterprise, Inc.",
    "category": "body_camera",
    "police_confidence": "high",
    "ota_emission": "confirmed",
    "note": "…",
    "ouis": [{ "prefix": "00:25:DF", "registry": "MA-L", "org": "Axon Enterprise, Inc." }]
  }],
  "module_oui_vendors": [{ "id": "getac", "name": "Getac", "category": "body_camera", "reason": "no IEEE OUI — rides on Intel/Sierra module OUIs" }],
  "exclusions": [{ "prefix": "00:58:28", "org": "Axon Networks Inc.", "reason": "defunct Ethernet vendor, NOT Axon Enterprise" }],
  "fingerprints": [{ "vendor_id": "axon-enterprise", "kind": "wifi_ssid", "pattern": "^AXON-X[0-9A-Z]+", "confidence": "medium", "source": "WiGLE", "caveat": "crowdsourced SoftAP name" }]
}
```

Edit it directly for offline/custom use, **or** run `eow update-db` to
re-validate every OUI against the IEEE registry and auto-discover new blocks for
unambiguously-named vendors (see `scripts/build_oui_db.py`).

### Covered vendors (v0.2 — 30 vendors / 55 OUIs, adversarially verified)

| Category        | Vendors (confidence)                                                                                   |
|-----------------|--------------------------------------------------------------------------------------------------------|
| body_camera     | Axon (H), Digital Ally (H), VIEVU (H), Zepcam (M)                                                       |
| in_car_video    | WatchGuard Video (H), L-3 Mobile-Vision (H), Seon/Safe Fleet (L), Rosco (L)                             |
| lmr_radio       | Motorola Solutions (M), L3Harris (M), Sepura (M), Tait (M), EF Johnson (M), Airbus TETRA (M), + Kenwood / Hytera / Icom / Codan / Simoco / Thales / Selex / Vertex (L) |
| mobile_router   | Cradlepoint (M), Sierra Wireless (M), Peplink/Pepwave (L), Utility BodyWorn/Rocket (L)                  |
| mdt_laptop      | Panasonic Toughbook (L, wired-only)                                                                     |
| satcom          | Kymeta (L)                                                                                              |
| surveillance    | Digital Barriers (M)                                                                                    |
| signaling       | Federal Signal (L)                                                                                      |

Plus **8 documented "module-only" vendors** with no IEEE OUI (`db --modules`): Getac,
COBAN Technologies, i-PRO, BK Technologies, Wolfcom, Reveal Media, Edesix, Pinnacle
Response — undetectable by brand prefix, listed so you know *why*.

---

## Known limitations (important for honest research)

1. **MAC randomization.** Modern radios emit locally-administered (randomized)
   MACs when unassociated; those frames can't be attributed by OUI. Docked/uploading
   body cams and fixed cruiser routers more often expose their real burned-in MAC.
   The tool flags randomized MACs explicitly and never guesses.

2. **Module-OUI blind spot & OTA emission.** Two related realities, surfaced by
   adversarial verification of this dataset:
   - Several marquee vendors — **Getac, COBAN Technologies (Houston), i-PRO,
     BK Technologies, Wolfcom, Reveal Media, Edesix, Pinnacle Response** — hold *no
     IEEE block* at all; their gear rides on COTS Wi-Fi/BLE **module** OUIs (Intel,
     Qualcomm/Atheros, Nordic, Realtek, TI…) and cannot match by brand prefix.
   - Even vendors that *do* hold OUIs mostly emit the **module** OUI over the air.
     Public evidence of a *brand* OUI on-air exists only for **Axon** (00:25:DF on
     both Wi-Fi BSSID and non-randomized BLE) and for in-vehicle **routers**
     (Cradlepoint/Sierra/Peplink put their OUI on the router BSSID). For most body
     cams the brand-OUI-on-air is unverified, and for rugged laptops (Toughbook/Dell)
     the brand OUI appears only on the wired NIC/dock. The `ota_emission` field
     encodes this and the classifier caps `wired_only` matches to low confidence.
   Practically: an OUI match is most trustworthy when you already have a *factory/public*
   MAC (an associated Wi-Fi client, a router BSSID, or a BT-Classic public address).

3. **OUI ≠ device model ≠ active use.** See the ethics note above.

4. **Name-collision traps.** e.g. *Axon Networks* ≠ *Axon Enterprise*; *WatchGuard
   Technologies* (firewalls) ≠ *WatchGuard Video*; *COBAN SRL* (Italy) ≠ *Coban
   Technologies*. These are enumerated in `exclusions[]`.

---

## Project layout

```
src/end_0f_watch/
  cli.py            argparse CLI (scan / replay / lookup / db / update-db)
  db.py             load + index the curated JSON; longest-prefix lookup
  classifier.py     Sighting -> scored Detection
  engine.py         fan concurrent backends into one de-duplicated stream
  models.py         typed dataclasses + category/confidence taxonomy
  util.py           MAC / OUI parsing, U/L-bit, freq->channel
  output.py         console / JSONL / CSV sinks + summary
  capture/
    wifi.py         scapy 802.11 monitor-mode sniffer (+ shared Dot11 parser)
    ble.py          bleak BLE advertisement scanner
    replay.py       pcap + MAC-list offline backends
data/police_ouis.json     curated database (editable, offline)
scripts/build_oui_db.py   IEEE-registry refresh/validation builder
tests/                    pytest suite (no hardware required)
```

## Tests

```bash
pip install -e '.[dev]'
pytest -q
```

The suite exercises MAC/prefix math, 24/28/36-bit longest-prefix matching, the
false-positive exclusions, randomized-MAC handling, fingerprint corroboration, and
an end-to-end replay — all without capture hardware.

---

*Built for authorized research and education. Use responsibly and lawfully.*
