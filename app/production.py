"""Production entrypoint for Render.

Loads the existing FastAPI application, removes the duplicate legacy
root/health routes that were registered before the production routes,
and serves the Vite build assets.
"""

from pathlib import Path

from fastapi.routing import APIRoute
from fastapi.staticfiles import StaticFiles

from app.main import app


# Keep the later production versions of these endpoints.
for path in ("/", "/health"):
    matching = [
        route
        for route in app.router.routes
        if isinstance(route, APIRoute)
        and route.path == path
        and "GET" in route.methods
    ]
    while len(matching) > 1:
        app.router.routes.remove(matching.pop(0))


# Vite emits JS/CSS files under frontend/dist/assets.
assets_dir = Path(__file__).resolve().parent.parent / "frontend" / "dist" / "assets"
if assets_dir.is_dir():
    app.mount("/assets", StaticFiles(directory=assets_dir), name="frontend-assets")
