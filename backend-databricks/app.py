"""Databricks Apps entrypoint - the real app (rg.api:app), now that both the Lakebase control-plane
connection and the Databricks data-plane connection (both via this app's own service principal, no
stored credentials anywhere) are verified working. See RETENTIONGUARD_V4_STATUS.md for the full
verification trail.

Phase 7: Databricks Apps allows exactly one bound port with no customizable CORS on its reverse proxy
(confirmed via the databricks-apps skill), so the Angular production build (static/, built with
`npm run build` in angular-app/ and copied here - see RETENTIONGUARD_V4_STATUS.md for the exact step)
is served from this SAME FastAPI process alongside every /api/* route, rather than as a separate app.

The SPA fallback below is a 404 EXCEPTION HANDLER, not a catch-all route - a wildcard GET route
(`@app.get("/{full_path:path}")`) was tried first and broke every non-GET /api/* request with a 405:
Starlette's router matches routes by PATH PATTERN before checking the HTTP method, so a GET-only
wildcard that matches literally every path still counts as a "partial match" for a POST to /api/login,
and a partial match anywhere short-circuits the search for a later FULL match on the real POST route.
An exception handler only ever runs after FastAPI's own routing has already failed to find ANY match
(including a method-only mismatch, which raises its own 405 untouched), so it can never shadow a real
route - confirmed by the fix after a live 405 was reproduced on the deployed app."""
from __future__ import annotations

import os
from pathlib import Path

from fastapi.responses import FileResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from rg.api import app

STATIC_DIR = Path(__file__).resolve().parent / "static"


@app.exception_handler(404)
async def spa_fallback(request, exc: StarletteHTTPException):
    full_path = request.url.path.lstrip("/")
    candidate = STATIC_DIR / full_path
    if full_path and candidate.is_file():
        return FileResponse(candidate)
    return FileResponse(STATIC_DIR / "index.html")


if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("DATABRICKS_APP_PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
