import pytest

from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from fastapi.testclient import TestClient

from app.main import app
from app.api.deps import get_db
from app.database import engine, Base


@pytest.fixture(scope="function")
def test_engine(tmp_path):
    """Creates an isolated SQLite database for each test function."""
    test_db_path = tmp_path / "test_database.db"
    test_engine_url = f"sqlite:///{test_db_path.as_posix()}"

    test_engine = create_engine(
        test_engine_url,
        connect_args={"check_same_thread": False},
    )

    # Safety assertion: compare test DB path with production engine path using cross-platform path resolution
    test_db_abs = test_db_path.resolve()

    # Get production database path from SQLAlchemy URL
    prod_db_raw = engine.url.database

    # Handle in-memory databases explicitly
    if prod_db_raw is None or prod_db_raw == "":
        # In-memory database - cannot compare file paths, skip assertion
        pass
    else:
        # Resolve production path
        if Path(prod_db_raw).is_absolute():
            prod_db_resolved = Path(prod_db_raw).resolve()
        else:
            # Relative path: resolve against current working directory
            prod_db_resolved = (Path.cwd() / prod_db_raw).resolve()

        # Compare using pathlib equality (handles Windows case-insensitivity via normcase)
        if test_db_abs.name == prod_db_resolved.name and test_db_abs.parent == prod_db_resolved.parent:
            assert False, (
                "CRITICAL: Tests must use the isolated test database. "
                "Do not modify the development/production database."
            )

    # Create all tables in the isolated test database
    Base.metadata.create_all(bind=test_engine)

    yield test_engine

    # Cleanup: dispose the test engine
    test_engine.dispose()


@pytest.fixture
def test_session_factory(test_engine):
    """Binds sessionmaker exclusively to test_engine."""
    factory = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)
    return factory


@pytest.fixture
def db_session(test_session_factory):
    """Creates a session from test_session_factory."""
    session = test_session_factory()
    yield session
    session.close()


@pytest.fixture(autouse=True)
def override_app_dependencies(test_session_factory):
    """Saves existing app.dependency_overrides, registers the test override,
    and restores the previous overrides after each test."""
    previous_overrides = app.dependency_overrides.copy()

    def override_get_db():
        """Dependency override that provides test database sessions."""
        db = test_session_factory()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    yield

    app.dependency_overrides.clear()
    app.dependency_overrides.update(previous_overrides)


@pytest.fixture
def client():
    """Returns a TestClient instance for the FastAPI application."""
    return TestClient(app)