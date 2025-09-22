import sqlite3
from pathlib import Path
from contextlib import contextmanager
from backend.core.settings import settings

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS networks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    -- ordine richiesto
    ssid         TEXT,
    bssid        TEXT,
    vendor       TEXT,
    date         TEXT,   -- "YYYY-MM-DD"
    time         TEXT,   -- "HH:MM:SS"
    hash_type    TEXT,   -- es. "WPA"
    hash_variant TEXT,   -- es. "PMKID" | "EAPOL"

    lat          REAL,
    lon          REAL,
    alt          REAL,
    accuracy     REAL,

    password     TEXT,

    UNIQUE(bssid, date, time)
);

-- Useful indexes for filters
CREATE INDEX IF NOT EXISTS idx_networks_coords       ON networks(lat, lon);
CREATE INDEX IF NOT EXISTS idx_networks_bssid        ON networks(bssid);
CREATE INDEX IF NOT EXISTS idx_networks_date_time    ON networks(date, time);
CREATE INDEX IF NOT EXISTS idx_networks_ssid         ON networks(ssid);
CREATE INDEX IF NOT EXISTS idx_networks_password     ON networks(password);
"""

def init_db() -> None:
    Path("data").mkdir(parents=True, exist_ok=True)
    dbp: Path = settings.db_path
    dbp.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(dbp) as conn:
        conn.executescript(SCHEMA_SQL)
        conn.commit()

@contextmanager
def db_conn():
    conn = sqlite3.connect(
        settings.db_path,
        detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES,
    )
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()