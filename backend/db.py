from sqlmodel import SQLModel, create_engine, Session
import os
from pathlib import Path

# In production (e.g. Render with a mounted disk), store the DB on /data.
# Locally, store it in the project root.
_data_dir = Path(os.environ.get("DB_DIR", Path(__file__).parent.parent))
_db_path = _data_dir / "ai_protector.db"

engine = create_engine(f"sqlite:///{_db_path}", echo=False)


def init_db():
    SQLModel.metadata.create_all(engine)


def get_session():
    """Return a new SQLModel Session. Use as a context manager."""
    return Session(engine)
