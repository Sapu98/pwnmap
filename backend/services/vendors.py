
import csv
from functools import lru_cache
from backend.core.settings import settings

@lru_cache(maxsize=1)
def _load_vendors():
    mapping = {}
    try:
        with open(settings.vendor_oui_csv, newline="", encoding="utf-8") as f:
            reader = csv.reader(f)
            for row in reader:
                if not row or len(row) < 2: 
                    continue
                prefix = row[0].strip().upper().replace(":", "").replace("-", "")
                vendor = row[1].strip()
                mapping[prefix] = vendor
    except FileNotFoundError:
        pass
    ordered = sorted(mapping.keys(), key=len, reverse=True)
    return mapping, ordered

def vendor_from_bssid(bssid: str) -> str | None:
    mapping, ordered = _load_vendors()
    base = bssid.replace(":", "").replace("-", "").upper()
    for k in ordered:
        if base.startswith(k):
            return mapping[k]
    return None
