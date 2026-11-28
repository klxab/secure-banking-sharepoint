from collections.abc import Generator

from sqlalchemy.orm import Session, sessionmaker

from src.database.connection import create_database_engine


engine = create_database_engine()

SessionLocal = sessionmaker(
    bind=engine,
    class_=Session,
    autoflush=False,
    expire_on_commit=False,
)


def get_database_session() -> Generator[Session, None, None]:
    """Provide a database session and always close it."""

    db = SessionLocal()

    try:
        yield db
    finally:
        db.close()
