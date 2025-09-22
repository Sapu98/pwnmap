from __future__ import annotations
import json
import re
import time
from typing import Iterable, Tuple, List, Dict, Optional

import requests
from requests import Response

from backend.core.settings import settings
from backend.db.queries import bulk_update_passwords

USER_AGENT = "PwnmapSync/1.0"

# Regex utili
_MAC_RE = re.compile(r"(?i)\b([0-9a-f]{2}(?::[0-9a-f]{2}){5})\b")

class WpaSecSyncError(RuntimeError):
    pass

# -----------------------------
# Parsing potfile
# -----------------------------
def _hex_to_mac(s: str) -> str:
    s = s.strip().upper()
    if len(s) == 12 and all(c in "0123456789ABCDEF" for c in s):
        return ":".join(s[i:i+2] for i in range(0, 12, 2))
    return ""


def parse_pot_line(line: str) -> Optional[Tuple[str, str]]:
    """Ritorna (bssid, password) se la riga è riconosciuta, altrimenti None.

    Accetta:
      - APMAC:STAMAC:SSID:PASS
      - MIC/PMKID:APMAC:STAMAC:SSID:PASS   (short form)
      - WPA*01*PMKID*AP*STA*...:PASS
      - WPA*02*AP*STA*...:PASS
      - ... AP=001122AABBCC ... :PASS   (fallback key=value)
    """
    try:
        s = line.rstrip("\r\n")
        if not s or s.startswith("#"):
            return None

        parts_colon = s.split(":")
        n = len(parts_colon)

        # 1) Short form: MIC/PMKID:APMAC:STAMAC:SSID:PASS
        if n >= 5:
            ap_hex = parts_colon[1]
            pwd = parts_colon[-1]
            bssid = _hex_to_mac(ap_hex)
            if bssid and pwd:
                return (bssid, pwd)

        # 2) Formato semplice: APMAC:STAMAC:SSID:PASS
        if n >= 4:
            ap_hex = parts_colon[0]
            pwd = parts_colon[-1]
            bssid = _hex_to_mac(ap_hex)
            if bssid and pwd:
                return (bssid, pwd)

        # 3) WPA*01/02*...:PASS
        if ":" in s:
            hashpart, pwd = s.split(":", 1)
            if pwd and hashpart.startswith("WPA*"):
                seg = hashpart.split("*")
                if len(seg) >= 3:
                    if seg[1] in {"01", "02"}:
                        # PMKID: WPA*01*PMKID*AP*STA*...
                        if len(seg) >= 5 and seg[2].upper() == "PMKID":
                            ap_hex = seg[3]
                            bssid = _hex_to_mac(ap_hex)
                            if bssid:
                                return (bssid, pwd)
                        # EAPOL: WPA*02*AP*STA*...
                        ap_hex = seg[2]
                        bssid = _hex_to_mac(ap_hex)
                        if bssid:
                            return (bssid, pwd)

        # 4) Fallback: AP=XXXXXXXXXXXX / BSSID=XXXXXXXXXXXX
        for key in ("AP=", "APMAC=", "BSSID=", "AP_MAC=", "BSSID_MAC="):
            m = re.search(rf"{re.escape(key)}([0-9A-Fa-f]{{12}})", s)
            if m:
                bssid = _hex_to_mac(m.group(1))
                if bssid:
                    pwd = s.split(":", 1)[1] if ":" in s else ""
                    if pwd:
                        return (bssid, pwd)
    except Exception:
        return None
    return None


def _is_valid_bssid(s: str) -> bool:
    return bool(_MAC_RE.fullmatch(s))


def _dedup_cracked(pairs: Iterable[Tuple[str, str]]) -> List[Tuple[str, str]]:
    """Deduplica per BSSID, preferendo password non vuote (mantiene la prima non vuota)."""
    best: Dict[str, str] = {}
    for bssid, pwd in pairs:
        if not _is_valid_bssid(bssid):
            continue
        bssid_u = bssid.upper()
        cur = best.get(bssid_u)
        if cur is None or (not cur and pwd):
            best[bssid_u] = pwd
    return [(b, p) for b, p in best.items()]


# -----------------------------
# Download potfile (con fallback cookie)
# -----------------------------
def _http_get_with_retry(url: str, *, timeout: int = 60, retries: int = 3, backoff: float = 1.5) -> Response:
    headers = {"User-Agent": USER_AGENT}
    last_exc: Exception | None = None
    for attempt in range(1, retries + 1):
        try:
            r = requests.get(url, headers=headers, timeout=timeout)
            r.raise_for_status()
            return r
        except Exception as e:
            last_exc = e
            if attempt == retries:
                break
            time.sleep(backoff ** attempt)
    raise WpaSecSyncError(f"HTTP GET failed for {url}: {last_exc}")


def download_cracked_potfile() -> List[Tuple[str, str]]:
    """
    Scarica il potfile e ritorna lista dedup di (bssid, password).
    Prima tenta query-string ?key=..., poi fallback con cookie=key se serve.
    """
    base = (getattr(settings, "wpasec_url", "") or "https://wpa-sec.stanev.org").rstrip("/")
    key = getattr(settings, "wpasec_key", "") or ""
    if not key:
        raise WpaSecSyncError("PWNMAP_WPASEC_KEY non configurata in settings.wpasec_key")

    def _parse_text(text: str) -> List[Tuple[str, str]]:
        raw_pairs: List[Tuple[str, str]] = []
        for line in text.splitlines():
            parsed = parse_pot_line(line)
            if parsed:
                raw_pairs.append(parsed)
        return _dedup_cracked(raw_pairs)

    # 1) Query string
    url_qs = f"{base}/?api&dl=1&key={key}"
    r = _http_get_with_retry(url_qs)
    pairs = _parse_text(r.text)

    # 2) Fallback cookie se vuoto o sembra HTML
    looks_html = "<html" in r.text.lower() or "</html>" in r.text.lower()
    if (not pairs) and (looks_html or len(r.text) < 10):
        headers = {"User-Agent": USER_AGENT}
        rc = requests.get(f"{base}/?api&dl=1", headers=headers, cookies={"key": key}, timeout=60)
        rc.raise_for_status()
        pairs = _parse_text(rc.text)

    return pairs


# -----------------------------
# Sync principale
# -----------------------------
def sync_now() -> dict:
    """
    Scarica il potfile, estrae coppie (BSSID, PSK), aggiorna il DB e ritorna:
      {
        "cracked_pairs_total": int,
        "rows_updated": int,
        "cracked_pairs": [{"bssid": "...", "password": "..."}, ...]
      }
    """
    cracked_pairs = download_cracked_potfile()

    # Aggiorna DB
    rows_updated = bulk_update_passwords(cracked_pairs)

    stats = {
        "cracked_pairs_total": len(cracked_pairs),
        "rows_updated": rows_updated,
        "cracked_pairs": [{"bssid": b, "password": p} for b, p in cracked_pairs],
    }

    # Log di servizio
    print("[WpaSec Sync] Stats:\n" + json.dumps(stats, indent=2))
    return stats
