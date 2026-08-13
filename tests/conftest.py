"""
Test configuration. Sets DB_PATH to a dedicated test database BEFORE any
application module is imported, since honeypot.config.get_config() is
cached for the lifetime of the process. Each test gets a clean database
via the test_db fixture, which deletes and re-initializes the file.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

TEST_DB_PATH = os.path.join(os.path.dirname(__file__), "test_honeypot.db")
os.environ["DB_PATH"] = TEST_DB_PATH

import pytest

from db.database import init_db


@pytest.fixture(scope="function")
def test_db():
    if os.path.exists(TEST_DB_PATH):
        os.remove(TEST_DB_PATH)
    init_db(TEST_DB_PATH)
    yield TEST_DB_PATH
    if os.path.exists(TEST_DB_PATH):
        os.remove(TEST_DB_PATH)
