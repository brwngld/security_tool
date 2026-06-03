from __future__ import annotations

from collections.abc import Iterator

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.web.config import WebConfig, load_web_config


class Base(DeclarativeBase):
    pass


def make_engine(config: WebConfig | None = None):
    active_config = config or load_web_config()
    connect_args = {"check_same_thread": False} if active_config.database_url.startswith("sqlite") else {}
    return create_engine(active_config.database_url, connect_args=connect_args, future=True)


def make_session_factory(config: WebConfig | None = None) -> sessionmaker[Session]:
    return sessionmaker(bind=make_engine(config), expire_on_commit=False, class_=Session)


def create_schema(config: WebConfig | None = None) -> None:
    from app.web import models  # noqa: F401

    engine = make_engine(config)
    Base.metadata.create_all(engine)


def session_scope(factory: sessionmaker[Session]) -> Iterator[Session]:
    session = factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
