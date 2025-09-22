from fastapi import APIRouter, UploadFile, File, Depends, HTTPException
from starlette.requests import Request
import logging, re
from pathlib import Path
import aiofiles

from backend.core.security import require_admin
from backend.db.queries import insert_network_record
from backend.services.ingest import (
    safe_stem, parse_gps_json, build_capture_paths,
    convert_pcap_to_hc22000_and_meta, lookup_vendor_from_csv
)

router = APIRouter(prefix="/api", tags=["upload"])
log = logging.getLogger(__name__)

BSSID_RE = re.compile(r'^([0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}$')
def norm_bssid(x: str | None) -> str | None:
    if not x: return None
    x = x.strip().upper().replace('-', ':')
    return x if BSSID_RE.fullmatch(x) else None

@router.post("/upload", dependencies=[Depends(require_admin)])
async def upload_pair(request: Request, pcap: UploadFile = File(...), gps: UploadFile = File(...)):
    log.info("upload_pair: ct=%s ua=%s ip=%s", request.headers.get("content-type"),
             request.headers.get("user-agent"), request.client.host if request.client else "?")

    if not pcap.filename:
        log.warning("400: missing pcap filename")
        raise HTTPException(status_code=400, detail="pcap file missing filename")
    ssid_from_name = safe_stem(pcap.filename)

    gps_bytes = await gps.read()
    try:
        gps_info = parse_gps_json(gps_bytes)
    except ValueError as e:
        log.warning("400: invalid gps json: %s", e)
        raise HTTPException(status_code=400, detail=f"Invalid gps json: {e}")

    base_dir = Path("data/captures")
    paths = build_capture_paths(base_dir, gps_info["datetime"], ssid_from_name)
    paths["dir"].mkdir(parents=True, exist_ok=True)

    async with aiofiles.open(paths["pcap_path"], "wb") as f:
        while True:
            chunk = await pcap.read(1024 * 1024)
            if not chunk: break
            await f.write(chunk)
    async with aiofiles.open(paths["gps_path"], "wb") as f:
        await f.write(gps_bytes)

    hc_meta = None
    try:
        hc_meta = convert_pcap_to_hc22000_and_meta(paths["pcap_path"], paths["hc22000_path"])
    except RuntimeError as e:
        log.warning("22000 conversion failed: %s", e)

    meta_ssid   = (hc_meta.get("ssid")    if isinstance(hc_meta, dict) else None) or ssid_from_name
    hash_type   = (hc_meta.get("type")    if isinstance(hc_meta, dict) else None)
    hash_variant= (hc_meta.get("variant") if isinstance(hc_meta, dict) else None)
    raw_bssid   = (hc_meta.get("bssid")   if isinstance(hc_meta, dict) else None)
    bssid       = norm_bssid(raw_bssid)

    vendor = lookup_vendor_from_csv(bssid) if bssid else None

    log.info("insert: ssid=%s type=%s var=%s bssid=%s vendor=%s date=%s time=%s",
             meta_ssid, hash_type, hash_variant, bssid, vendor,
             gps_info["datetime"].strftime("%Y-%m-%d"),
             gps_info["datetime"].strftime("%H:%M:%S"))

    record_id = insert_network_record(
        ssid=meta_ssid, hash_type=hash_type, hash_variant=hash_variant,
        bssid=bssid, vendor=vendor,
        date=gps_info["datetime"].strftime("%Y-%m-%d"),
        time=gps_info["datetime"].strftime("%H:%M:%S"),
        lat=gps_info["latitude"], lon=gps_info["longitude"],
        alt=gps_info["altitude"], accuracy=gps_info["accuracy"],
        password=None,
    )

    resp = {"ok": True, "ssid": meta_ssid, "record_id": record_id}
    if hc_meta is None:
        resp["hash_meta_error"] = "no_22000"
    return resp
