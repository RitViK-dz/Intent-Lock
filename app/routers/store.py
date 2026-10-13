"""Router for store catalog, protected checkout, unprotected checkout, and orders."""

from fastapi import APIRouter

router = APIRouter(prefix="/store", tags=["store"])
