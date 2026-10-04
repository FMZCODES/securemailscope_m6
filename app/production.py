"""Production entrypoint for the combined Render deployment."""

from pathlib import Path

from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.main import app


BASE_DIR = Path(__file__).resolve().parent.parent
FRONTEND_DIR = BASE_DIR / "frontend" / "dist"
ASSETS_DIR = FRONTEND_DIR / "assets"
INDEX_FILE = FRONTEND_DIR / "index.html"


if ASSETS_DIR.is_dir():
    app.mount(
        "/assets",
        StaticFiles(directory=ASSETS_DIR),
        name="frontend-assets",
    )


@app.get("/", include_in_schema=False)
def production_dashboard():
    """Serve the React dashboard at the Render service root."""
    if INDEX_FILE.is_file():
        return FileResponse(INDEX_FILE)

    return {
        "project": "SecureMailScope M6",
        "status": "running",
        "version": "0.3.0",
        "pipeline": "M2 -> M3 -> M4 -> M5",
        "dashboard": "frontend build not found",
    }


@app.get("/dashboard", include_in_schema=False)
def dashboard_alias():
    if INDEX_FILE.is_file():
        return FileResponse(INDEX_FILE)
    return production_dashboard()
