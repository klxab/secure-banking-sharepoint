from logging.config import fileConfig
from alembic import context
from src.database.base import Base
import src.models
from src.database.connection import DATABASE_URL, create_database_engine

# Alembic configuration
config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Metadata used by Alembic to detect database schema changes.
target_metadata = Base.metadata


def run_migrations_offline() -> None:
    """Generate migration SQL without connecting to the database."""

    # Remove credentials and host details from the offline configuration.
    safe_url = DATABASE_URL.set(
        username=None,
        password=None,
        host=None,
        port=None,
        database=None,
    )

    context.configure(
        url=safe_url.render_as_string(hide_password=True),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
        compare_server_default=True,
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations using the project's existing database connection."""

    engine = create_database_engine()

    try:
        with engine.connect() as connection:
            context.configure(
                connection=connection,
                target_metadata=target_metadata,
                compare_type=True,
                compare_server_default=True,
            )

            with context.begin_transaction():
                context.run_migrations()

    finally:
        engine.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()