from __future__ import annotations

import logging
import sqlite3
from typing import Optional, Iterable
from backend.core.settings import settings

log = logging.getLogger(__name__)

def insert_network_record(
    *,
    ssid: Optional[str],
    hash_type: Optional[str],
    hash_variant: Optional[str],
    bssid: Optional[str],
    vendor: Optional[str],
    date: Optional[str],
    time: Optional[str],
    lat: Optional[float],
    lon: Optional[float],
    alt: Optional[float],
    accuracy: Optional[float],
    password: Optional[str],
) -> int:
    """
    Inserisce una riga in 'networks'. Ritorna l'id inserito (o esistente se UNIQUE).
    UNIQUE su (bssid, date, time). Se bssid è NULL non scatta, è voluto.
    """

    try:
        with sqlite3.connect(settings.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()

            cur.execute(
                """
                INSERT OR IGNORE INTO networks (
                    ssid, bssid, vendor,
                    date, time,
                    hash_type, hash_variant,
                    lat, lon, alt, accuracy,
                    password
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    ssid,
                    bssid,
                    vendor,
                    date,
                    time,
                    hash_type,
                    hash_variant,
                    lat,
                    lon,
                    alt,
                    accuracy,
                    password,
                ),
            )
            new_id = cur.lastrowid

            if not new_id and bssid is not None:
                # significa che ha ignorato perché era un duplicato
                cur.execute(
                    "SELECT id FROM networks WHERE bssid = ? AND date = ? AND time = ?",
                    (bssid, date, time),
                )
                row = cur.fetchone()
                if row:
                    log.warning(
                        "Record duplicato ignorato per BSSID=%s @ %s %s (id esistente=%s)",
                        bssid, date, time, row["id"]
                    )
                    return int(row["id"])
                else:
                    log.warning(
                        "Insert fallito senza motivo apparente per BSSID=%s @ %s %s",
                        bssid, date, time
                    )
                    return -1

            conn.commit()
            return int(new_id)

    except sqlite3.Error as e:
        log.exception("Errore SQLite durante insert_network_record: %s", e)
        return -1

def bulk_update_passwords(items: Iterable[tuple[str, str]]) -> int:
    """Aggiorna solo reti già presenti con password NULL/vuota."""
    import sqlite3
    from backend.core.settings import settings

    if not items:
        return 0

    updated = 0
    with sqlite3.connect(settings.db_path) as conn:
        cur = conn.cursor()
        for bssid, pwd in items:
            if not bssid or not pwd:
                continue
            cur.execute(
                """
                UPDATE networks
                   SET password = ?
                 WHERE REPLACE(REPLACE(UPPER(TRIM(bssid)), ':',''), '-', '') =
                       REPLACE(REPLACE(UPPER(TRIM(?)),      ':',''), '-', '')
                   AND (password IS NULL OR TRIM(password) = '')
                """,
                (pwd, bssid),
            )
            updated += cur.rowcount
        conn.commit()
    return updated


def select_networks_geojson(
    *,
    bbox: Optional[tuple[float, float, float, float]] = None,  # (minLon,minLat,maxLon,maxLat)
    cracked: Optional[bool] = None,
    has_bssid: Optional[bool] = None,
    q: Optional[str] = None,
    limit: int = 5000,
) -> dict:
    parts = ["SELECT id, ssid, bssid, vendor, date, time, hash_type, hash_variant, lat, lon, alt, accuracy, password FROM networks"]
    where = []
    params: list = []

    if bbox is not None:
        (min_lon, min_lat, max_lon, max_lat) = bbox
        where.append("lat BETWEEN ? AND ? AND lon BETWEEN ? AND ?")
        params += [min_lat, max_lat, min_lon, max_lon]

    if cracked is True:
        where.append("password IS NOT NULL AND TRIM(password) != ''")
    elif cracked is False:
        where.append("(password IS NULL OR TRIM(password) = '')")

    if has_bssid is True:
        where.append("bssid IS NOT NULL AND TRIM(bssid) != ''")
    elif has_bssid is False:
        where.append("(bssid IS NULL OR TRIM(bssid) = '')")

    if q:
        where.append("(ssid LIKE ? OR vendor LIKE ? OR bssid LIKE ?)")
        like = f"%{q}%"
        params += [like, like, like]

    if where:
        parts.append("WHERE " + " AND ".join(where))

    parts.append("ORDER BY date DESC, time DESC")
    parts.append("LIMIT ?")
    params.append(int(limit))

    sql = "\n".join(parts)

    features = []
    with sqlite3.connect(settings.db_path) as conn:
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        for row in cur.execute(sql, params):
            lat = row["lat"]; lon = row["lon"]
            if lat is None or lon is None:
                continue
            props = {
                "id": row["id"],
                "ssid": row["ssid"],
                "bssid": row["bssid"],
                "vendor": row["vendor"],
                "date": row["date"],
                "time": row["time"],
                "hash_type": row["hash_type"],
                "hash_variant": row["hash_variant"],
                "alt": row["alt"],
                "accuracy": row["accuracy"],
                "password": row["password"],
            }
            features.append({
                "type": "Feature",
                "geometry": {"type": "Point", "coordinates": [lon, lat]},
                "properties": props,
            })

    return {"type": "FeatureCollection", "features": features}
