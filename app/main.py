"""Main FastAPI application entrypoint for IntentLock.

Integrates API routers, static dashboard assets, and the core health check.
"""

from pathlib import Path
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from app.routers import intents, store, agent, audit

# Initialize the main FastAPI application
app = FastAPI(
    title="IntentLock",
    description="Cryptographic human approval prototype for AI agents",
    version="0.1.0",
)

# Register API routers
app.include_router(intents.router)
app.include_router(store.router)
app.include_router(agent.router)
app.include_router(audit.router)


@app.get("/health", tags=["system"])
def health_check() -> dict[str, str]:
    """Basic health check endpoint returning system status."""
    return {"status": "ok"}


# Mount static assets at root ("/") after explicit API routes
# This allows "/" to serve index.html while /health and /api routes take precedence.
static_dir = Path(__file__).resolve().parent.parent / "static"
if static_dir.exists():
    app.mount("/", StaticFiles(directory=str(static_dir), html=True), name="static")
