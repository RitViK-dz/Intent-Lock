"""Router for intent proposal, listing, approval, and rejection endpoints."""

from fastapi import APIRouter

router = APIRouter(prefix="/api/intents", tags=["intents"])
