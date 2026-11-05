import sys
import os

# Ensure the backend package is importable when tests run from the tests/ folder
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.database import SessionLocal, engine, Base  # noqa: E402
from app.main import app  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402


def setup_function(function):
    Base.metadata.create_all(bind=engine)


def teardown_function(function):
    Base.metadata.drop_all(bind=engine)


def test_client():
    return TestClient(app)