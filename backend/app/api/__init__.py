"""API package: REST route handlers and Pydantic schemas."""

def __getattr__(name: str):
    if name == "router":
        from backend.app.api.routes import router
        return router
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

__all__ = ["router"]

