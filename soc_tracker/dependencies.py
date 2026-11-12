"""Shared FastAPI dependencies."""

from fastapi import Depends
from sqlalchemy.orm import Session


def get_db():
    """Database session dependency."""
    from .models import SessionLocal
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
