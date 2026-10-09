import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes.health import router as health_router
from app.api.routes.scans import router as scans_router
from app.api.routes.security import router as security_router
from app.config import settings
from app.database.database import init_db
from backend.api.datasets import router as datasets_router
from backend.api.records import router as records_router

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("ai_security_gateway")


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Initializing AI Security Gateway and Database Tables...")
    try:
        init_db()
        logger.info("Database and Security Tables successfully initialized.")
    except Exception as e:
        logger.error(f"Error initializing database: {e}")
    yield
    logger.info("Security Gateway shutting down.")


app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description=(
        "AI Security Gateway with modular Linux Cybersecurity Layer (YARA, ClamAV, tshark), "
        "Content Security, Output Firewall, and Dataset Collection Engine."
    ),
    lifespan=lifespan
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 1. Mount Security Gateway Routes
app.include_router(health_router)
app.include_router(security_router)
app.include_router(scans_router)

# 2. Mount Existing Dataset Platform Routes (Full Backward Compatibility)
app.include_router(datasets_router)
app.include_router(records_router)


from pathlib import Path
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

frontend_path = Path(__file__).resolve().parent.parent / "frontend"
if frontend_path.exists():
    assets_dir = frontend_path / "assets"
    if assets_dir.exists():
        app.mount("/assets", StaticFiles(directory=str(assets_dir)), name="assets")
    app.mount("/static", StaticFiles(directory=str(frontend_path)), name="static")


@app.get("/dashboard", include_in_schema=False)
@app.get("/", include_in_schema=False)
def serve_dashboard():
    index_file = frontend_path / "index.html"
    if index_file.exists():
        return FileResponse(index_file)
    return {"message": "Sentinel AI Gateway running"}


@app.get("/api", tags=["System"])
def api_index():
    return {
        "gateway": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "docs_url": "/docs",
        "health_url": "/health",
        "security_tools_url": "/api/v1/security/tools",
        "security_dashboard_url": "/api/v1/security/dashboard",
        "scans_url": "/api/v1/scans",
        "datasets_url": "/datasets",
        "records_url": "/records"
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
