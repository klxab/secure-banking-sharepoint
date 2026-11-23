import os

from sqlalchemy import text

from src.database.connection import create_database_engine


def test_database_connection():
    engine = create_database_engine()

    try:
        with engine.connect() as connection:
            result = connection.execute(
                text("SELECT current_database(), current_user")
            ).one()

            assert result[0] == os.getenv("POSTGRES_DB")
            assert result[1] == os.getenv("POSTGRES_USER")

    finally:
        engine.dispose()