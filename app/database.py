import os
from pathlib import Path
from dotenv import load_dotenv
from sqlmodel import SQLModel, create_engine, Session

load_dotenv()

DB_PATH = Path(os.getenv("DATABASE_PATH", "data/cyber_brief.db"))
DB_PATH.parent.mkdir(parents=True, exist_ok=True)

DATABASE_URL = f"sqlite:///{DB_PATH.as_posix()}"

engine = create_engine(
    DATABASE_URL,
    echo=False,
    connect_args={"check_same_thread": False},
)


def init_db() -> None:
    from app import models
    SQLModel.metadata.create_all(engine)


def get_session():
    with Session(engine) as session:
        yield session