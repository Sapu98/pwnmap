from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.staticfiles import StaticFiles
from backend.db.database import init_db
from backend.routers.upload import router as upload_router
from backend.routers.networks import router as networks_router
from backend.routers.wpasec import router as wpasec_router

app = FastAPI(title="pwnmap", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(upload_router)
app.include_router(networks_router)
app.include_router(wpasec_router)

@app.on_event("startup")
async def _startup() -> None:
    init_db()

@app.get("/healthz")
async def healthz():
    return {"status": "ok"}

frontend_dir = "frontend"
app.mount("/", StaticFiles(directory=str(frontend_dir), html=True), name="frontend")