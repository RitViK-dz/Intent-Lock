"""Router for simulated agent attack runs and scenario demonstrations."""

from fastapi import APIRouter

router = APIRouter(prefix="/api/demo", tags=["demo"])
