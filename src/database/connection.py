import os
from pathlib import Path

from dotenv import load_dotenv
from sqlalchemy import URL, create_engine
from sqlalchemy.engine import Engine


PROJECT_ROOT = Path(__file__).resolve().parents[2]
load_dotenv(PROJECT_ROOT / ".env")


_REQUIRED_APPLICATION_VARIABLES = (
    "POSTGRES_DB",
    "POSTGRES_USER",
    "POSTGRES_PASSWORD",
)


def _validate_required_variables(variable_names: tuple[str, ...]) -> None:
    missing = [
        name for name in variable_names
        if not os.getenv(name)
    ]

    if missing:
        raise RuntimeError(
            "Missing required environment variables: "
            + ", ".join(missing)
        )


_validate_required_variables(_REQUIRED_APPLICATION_VARIABLES)


def _create_database_url(username: str, password: str) -> URL:
    return URL.create(
        drivername="postgresql+psycopg",
        username=username,
        password=password,
        host=os.getenv("POSTGRES_HOST", "127.0.0.1"),
        port=int(os.getenv("POSTGRES_PORT", "5433")),
        database=os.environ["POSTGRES_DB"],
    )


# Application runtime connection.
DATABASE_URL = _create_database_url(
    username=os.environ["POSTGRES_USER"],
    password=os.environ["POSTGRES_PASSWORD"],
)


def create_database_engine() -> Engine:
    """Create the application runtime database engine."""
    return create_engine(
        DATABASE_URL,
        pool_pre_ping=True,
    )


def get_migration_database_url() -> URL:
    """Build the dedicated Alembic migration database URL."""
    _validate_required_variables(
        (
            "POSTGRES_MIGRATION_USER",
            "POSTGRES_MIGRATION_PASSWORD",
        )
    )

    return _create_database_url(
        username=os.environ["POSTGRES_MIGRATION_USER"],
        password=os.environ["POSTGRES_MIGRATION_PASSWORD"],
    )


def create_migration_database_engine() -> Engine:
    """Create the dedicated database engine used by Alembic."""
    return create_engine(
        get_migration_database_url(),
        pool_pre_ping=True,
    )
