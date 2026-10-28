"""Router for retrieving immutable audit logs."""

from fastapi import APIRouter, Query
from app.config import settings
from app.db import init_db, list_audit

router = APIRouter(prefix="/api/audit", tags=["audit"])


@router.get("", summary="Retrieve immutable audit logs")
def get_audit_logs(limit: int = Query(50, ge=1, le=500)):
    """Retrieve audit log entries in reverse-chronological order (newest first)."""
    init_db(settings.db_path)
    return list_audit(limit=limit, db_path=settings.db_path)

