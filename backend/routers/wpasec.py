from __future__ import annotations
from fastapi import APIRouter, Depends
from backend.services.wpasec_sync import sync_now

router = APIRouter(prefix="/api/wpasec", tags=["wpasec"])

@router.post("/sync")
async def wpasec_sync():
    return sync_now()