# backend/app/api/__init__.py
"""API package: REST route handlers and Pydantic schemas."""

from backend.app.api.routes import router

__all__ = ["router"]
