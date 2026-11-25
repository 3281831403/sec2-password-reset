"""Shared fixtures for the public reset-token tests."""

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