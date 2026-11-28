import os

TEST_DATABASE_NAME = "banking_test"

# Force every test module to use the dedicated test database.
os.environ["POSTGRES_DB"] = TEST_DATABASE_NAME

from src.database.connection import DATABASE_URL

# Fail immediately if the test environment targets another database.
if DATABASE_URL.database != TEST_DATABASE_NAME:
    raise RuntimeError(
        f"Unsafe test database configuration: {DATABASE_URL.database}"
    )
