"""Alembic environment. Driven programmatically by `cti db upgrade` (see cti.db.migrate)."""

from alembic import context
from sqlalchemy import text

from cti.db.models import Base
from cti.db.session import get_engine

target_metadata = Base.metadata

# Arbitrary constant: serializes concurrent migrations (worker + web starting together).
MIGRATION_LOCK_ID = 727_001


def run_migrations_online() -> None:
    url = context.config.get_main_option("sqlalchemy.url")
    engine = get_engine(url)
    with engine.connect() as connection:
        connection.execute(text("SELECT pg_advisory_lock(:id)"), {"id": MIGRATION_LOCK_ID})
        try:
            context.configure(connection=connection, target_metadata=target_metadata, compare_type=True)
            with context.begin_transaction():
                context.run_migrations()
            connection.commit()
        finally:
            connection.execute(text("SELECT pg_advisory_unlock(:id)"), {"id": MIGRATION_LOCK_ID})
            connection.commit()


run_migrations_online()
