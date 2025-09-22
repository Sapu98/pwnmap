from __future__ import annotations
from fastapi import APIRouter, Query
from pydantic import BaseModel
from typing import Optional
from backend.db.queries import select_networks_geojson

router = APIRouter(prefix="/api/networks", tags=["networks"])

class Feature(BaseModel):
    type: str
    geometry: dict
    properties: dict

class FeatureCollection(BaseModel):
    type: str
    features: list[Feature]

@router.get("/geojson", response_model=FeatureCollection)
async def networks_geojson(
    bbox: Optional[str] = Query(None, description="minLon,minLat,maxLon,maxLat"),
    cracked: Optional[bool] = Query(None),
    has_bssid: Optional[bool] = Query(None),
    q: Optional[str] = Query(None),
    limit: int = Query(5000, ge=1, le=50000),
):
    bbox_t: Optional[tuple[float, float, float, float]] = None
    if bbox:
        parts = [float(x) for x in bbox.split(",")]
        if len(parts) == 4:
            bbox_t = (parts[0], parts[1], parts[2], parts[3])

    fc = select_networks_geojson(
        bbox=bbox_t,
        cracked=cracked,
        has_bssid=has_bssid,
        q=q,
        limit=limit,
    )
    for f in fc.get("features", []):
        props = f.get("properties", {}) or {}
        pwd = props.get("password")
        status = "cracked" if pwd else "unknown"
        props["status"] = status
        f["properties"] = props

    return fc


@router.get("/stats")
async def stats():
    from backend.db.database import db_conn
    sql = {
        "total": "SELECT COUNT(*) FROM networks",
        "with_coords": "SELECT COUNT(*) FROM networks WHERE lat IS NOT NULL AND lon IS NOT NULL",
        "cracked": "SELECT COUNT(*) FROM networks WHERE password IS NOT NULL AND TRIM(password) != ''",
        "uncracked": "SELECT COUNT(*) FROM networks WHERE password IS NULL OR TRIM(password) = ''",
        "empty_bssid": "SELECT COUNT(*) FROM networks WHERE bssid IS NULL OR TRIM(bssid) = ''",
    }
    out = {}
    with db_conn() as conn:
        cur = conn.cursor()
        for k, q in sql.items():
            cur.execute(q)
            (cnt,) = cur.fetchone()
            out[k] = cnt
    return out
