"""Serves the console and tells it who the analyst is.

Alert text is attacker-controlled, and the console displays it. The page therefore ships with a
strict Content-Security-Policy (no inline script, no third-party origins) and renders every value
with textContent, never as HTML.
"""

from pathlib import Path
from typing import Annotated, Any

from fastapi import APIRouter, Header, HTTPException, status
from fastapi.responses import FileResponse

from core.auth import AnalystDirectory

STATIC = Path(__file__).parent / "static"

SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
        "connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}

_ASSETS = {"app.js": "text/javascript", "style.css": "text/css"}


def build_router(analysts: AnalystDirectory, demo_token: str | None = None) -> APIRouter:
    router = APIRouter(tags=["console"])

    @router.get("/console", include_in_schema=False)
    def page() -> FileResponse:
        return FileResponse(STATIC / "index.html", media_type="text/html", headers=SECURITY_HEADERS)

    @router.get("/console/{asset}", include_in_schema=False)
    def asset(asset: str) -> FileResponse:
        if asset not in _ASSETS:  # a fixed allowlist: no path ever comes from the request
            raise HTTPException(status.HTTP_404_NOT_FOUND)
        return FileResponse(STATIC / asset, media_type=_ASSETS[asset], headers=SECURITY_HEADERS)

    @router.get("/v1/me")
    def me(authorization: Annotated[str | None, Header()] = None) -> dict[str, Any]:
        found = analysts.authenticate(authorization)
        if found is None:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "analyst not authenticated")
        return {"id": found.id, "roles": sorted(found.roles)}

    @router.get("/v1/console/demo-session", include_in_schema=False)
    def demo_session() -> dict[str, str]:
        # Lab demos only (scripts/console_demo.py): hands the page a demo analyst token so it opens
        # signed in. Absent unless CLOUDSHIELD_CONSOLE_DEMO_TOKEN is set.
        if not demo_token:
            raise HTTPException(status.HTTP_404_NOT_FOUND)
        return {"token": demo_token}

    return router
