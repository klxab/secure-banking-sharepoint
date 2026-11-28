from fastapi import Depends, FastAPI, HTTPException
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session
from src.api.routes.auth import router as auth_router
from src.api.routes.rbac import router as rbac_router

from src.database.session import get_database_session


app = FastAPI(
    title="Secure Banking Information System API",
    description=(
        "A secure banking information system featuring "
        "role-based access control, data tokenization, "
        "and access anomaly detection."
    ),
    version="0.1.0",
)

app.include_router(auth_router)
app.include_router(rbac_router)

@app.get("/health", tags=["System"])
def health_check() -> dict[str, str]:
    """Return the API service health status."""

    return {
        "status": "healthy",
        "service": "secure-banking-api",
    }


@app.get("/health/database", tags=["System"])
def database_health_check(
    db: Session = Depends(get_database_session),
) -> dict[str, str]:
    """Check database connectivity."""

    try:
        db.execute(text("SELECT 1"))

        return {
            "status": "healthy",
            "database": "connected",
        }

    except SQLAlchemyError:
        raise HTTPException(
            status_code=503,
            detail="Database connection unavailable.",
        )
