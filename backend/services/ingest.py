from __future__ import annotations
from pathlib import Path
from datetime import datetime
import json
import logging
import subprocess
import csv
from typing import Optional, Dict

log = logging.getLogger(__name__)

# ---------- Filename helper ----------

def safe_stem(name: str) -> str:
    stem = Path(name).stem
    return stem.split("_", 1)[0] if "_" in stem else stem


# ---------- GPS parsing ----------

def _parse_updated_datetime(updated: str) -> datetime:
    """
    Parse 'Updated' from GPS JSON.
    Expected example: "2025-08-29 21:05:52"
    """
    s = updated.strip()
    # ISO tolerant
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00")).replace(tzinfo=None)
    except Exception:
        pass
    # Fixed format
    try:
        return datetime.strptime(s, "%Y-%m-%d %H:%M:%S")
    except Exception as e:
        raise ValueError(f"Unrecognized Updated datetime format: {updated}") from e


def parse_gps_json(raw: bytes) -> dict:
    """
    Returns:
      {
        'datetime': datetime,
        'latitude': float,
        'longitude': float,
        'altitude': float|None,
        'accuracy': float|None
      }
    """
    try:
        data = json.loads(raw.decode("utf-8"))
    except Exception as e:
        raise ValueError(f"Invalid JSON: {e}")

    if "Updated" not in data or "Latitude" not in data or "Longitude" not in data:
        raise ValueError("Missing one of required keys: Updated, Latitude, Longitude")

    dt = _parse_updated_datetime(str(data["Updated"]))
    lat = float(data["Latitude"])
    lon = float(data["Longitude"])
    alt = round(float(data.get("Altitude")), 2) if data.get("Altitude") is not None else None
    acc = float(data.get("Accuracy")) if data.get("Accuracy") is not None else None

    return {
        "datetime": dt,
        "latitude": lat,
        "longitude": lon,
        "altitude": alt,
        "accuracy": acc,
    }


# ---------- Path builder ----------

def build_capture_paths(base_dir: Path, dt: datetime, ssid: str) -> dict:
    """
    Directory: base/YYYY-MM/DD/
    Filenames: ssid_HHMMSS.ext
    """
    y = f"{dt.year:04d}"
    m = f"{dt.month:02d}"
    d = f"{dt.day:02d}"
    hhmmss = f"{dt.hour:02d}{dt.minute:02d}{dt.second:02d}"

    dir_path = base_dir / f"{y}-{m}" / d
    base_name = f"{ssid}_{hhmmss}"

    return {
        "dir": dir_path,
        "pcap_path": dir_path / f"{base_name}.pcap",
        "gps_path": dir_path / f"{base_name}.gps.json",
        "hc22000_path": dir_path / f"{base_name}.22000",
    }


# ---------- 22000 conversion & parsing ----------

def _run(cmd: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False
    )

def _is_hex(s: str) -> bool:
    return len(s) % 2 == 0 and all(c in "0123456789abcdefABCDEF" for c in s)

def _decode_essid(essid_field: str) -> str:
    if _is_hex(essid_field):
        try:
            return bytes.fromhex(essid_field).decode("utf-8", errors="ignore")
        except Exception:
            return essid_field
    return essid_field

def _parse_22000_line(line: str) -> dict:
    s = line.strip()
    if not s.startswith("WPA*"):
        raise ValueError("Not a 22000 WPA hashline")

    parts = s.split("*")
    if len(parts) < 3:
        raise ValueError("Truncated 22000 line")

    kind_code = parts[1]

    if kind_code == "01":  # PMKID
        if len(parts) < 6:
            raise ValueError("Invalid PMKID 22000 line")
        return {
            "kind": "PMKID",
            "bssid": parts[3],
            "station": parts[4],
            "ssid": _decode_essid(parts[5]),
            "hash_type": "WPA",
            "variant": "PMKID",
        }

    if kind_code == "02":  # EAPOL
        if len(parts) < 6:
            raise ValueError("Invalid EAPOL 22000 line")
        return {
            "kind": "EAPOL",
            "bssid": parts[3],
            "station": parts[4],
            "ssid": _decode_essid(parts[5]),
            "hash_type": "WPA",
            "variant": "EAPOL",
        }

    raise ValueError(f"Unknown 22000 kind code: {kind_code}")

def _fmt_mac_colon(hex12: str) -> str:
    """'aabbccddeeff' -> 'AA:BB:CC:DD:EE:FF'"""
    h = "".join(c for c in hex12 if c in "0123456789abcdefABCDEF")
    if len(h) != 12:
        return ""
    return ":".join(h[i:i+2] for i in range(0, 12, 2)).upper()

def convert_pcap_to_hc22000_and_meta(pcap_path: Path, out_22000: Path) -> dict | None:
    if not pcap_path.exists():
        raise RuntimeError(f"pcap not found: {pcap_path}")

    cmd = ["hcxpcapngtool", "-o", str(out_22000), str(pcap_path)]
    proc = _run(cmd)

    if proc.returncode != 0:
        raise RuntimeError(
            f"hcxpcapngtool failed: {proc.stderr.strip() or proc.stdout.strip() or 'unknown error'}"
        )

    if not out_22000.exists():
        raise RuntimeError("Conversion produced no .22000 file")

    text = out_22000.read_text(encoding="utf-8", errors="ignore").strip()
    if not text:
        raise RuntimeError("No valid WPA* lines in .22000")

    first_line = next((ln for ln in text.splitlines() if ln.startswith("WPA*")), None)
    if not first_line:
        raise RuntimeError("No WPA* lines found in .22000")

    meta = _parse_22000_line(first_line)

    # Normalizza BSSID
    bssid_raw = (meta.get("bssid") or "").replace(":", "").replace("-", "")
    bssid_hex12 = bssid_raw.lower()
    if not (len(bssid_hex12) == 12 and all(c in "0123456789abcdef" for c in bssid_hex12)):
        bssid_hex12 = ""

    ssid = meta.get("ssid") or ""
    variant = meta.get("variant") or ("PMKID" if meta.get("kind") == "PMKID" else "EAPOL")

    return {
        "ssid": ssid or None,
        "bssid": (_fmt_mac_colon(bssid_hex12) if bssid_hex12 else None),
        "type": "WPA",
        "variant": variant,
    }


# ---------- Vendor OUI lookup ----------

class OUILookup:
    _loaded: bool = False
    _map_by_len: Dict[int, Dict[str, str]] = {6: {}, 7: {}, 9: {}}
    _csv_path: Path = Path("data/meta/vendor_oui.csv")

    @classmethod
    def _load(cls):
        if cls._loaded:
            return
        p = cls._csv_path
        if not p.exists():
            log.warning("OUI CSV not found at %s", p)
            cls._loaded = True
            return
        with p.open("r", encoding="utf-8", newline="") as f:
            reader = csv.reader(f)
            for row in reader:
                if not row or row[0].startswith("#"):
                    continue
                if len(row) < 2:
                    continue
                prefix = row[0].strip().upper()
                vendor = row[1].strip()
                L = len(prefix)
                if L in (6, 7, 9) and all(c in "0123456789ABCDEF" for c in prefix):
                    cls._map_by_len[L][prefix] = vendor
        cls._loaded = True
        log.info(
            "OUI loaded: %d (24b), %d (28b), %d (36b)",
            len(cls._map_by_len[6]),
            len(cls._map_by_len[7]),
            len(cls._map_by_len[9]),
        )

    @classmethod
    def vendor_for_bssid(cls, bssid_hex12: str) -> Optional[str]:
        cls._load()
        if not bssid_hex12:
            return None
        mac = "".join(c for c in bssid_hex12.upper() if c in "0123456789ABCDEF")
        if len(mac) < 9:
            return None
        for L in (9, 7, 6):
            pref = mac[:L]
            vendor = cls._map_by_len[L].get(pref)
            if vendor:
                return vendor
        return None


def lookup_vendor_from_csv(bssid: Optional[str]) -> Optional[str]:
    if not bssid:
        return None
    cleaned = bssid.replace(":", "").replace("-", "").strip().upper()
    if len(cleaned) != 12 or not all(c in "0123456789ABCDEF" for c in cleaned):
        return None
    return OUILookup.vendor_for_bssid(cleaned)
