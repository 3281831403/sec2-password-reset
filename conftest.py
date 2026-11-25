"""Shared fixtures for the public reset-token tests."""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import pytest

POLICY = {"min_length": 32, "max_age_seconds": 900}


@pytest.fixture
def policy():
    return dict(POLICY)


@pytest.fixture
def store():
    return {
        "tokens": {},
        "sessions": {},
        "logs": [],
        "seq": 0,
        "policy": dict(POLICY),
    }