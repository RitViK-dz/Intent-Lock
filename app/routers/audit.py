"""Router for retrieving immutable audit logs."""

from fastapi import APIRouter

router = APIRouter(prefix="/api/audit", tags=["audit"])
