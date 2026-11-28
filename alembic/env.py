from logging.config import fileConfig

from alembic import context

from src.database.base import Base
from src.database.connection import (
    create_migration_database_engine,
    get_migration_database_url,
)
import src.models


config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)


target_metadata = Base.metadata


def run_migrations_offline() -> None:
    """Generate migration SQL without connecting to the database."""

    migration_url = get_migration_database_url()

    safe_url = migration_url.set(
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
    """Run migrations using the dedicated migration account."""

    engine = create_migration_database_engine()

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
