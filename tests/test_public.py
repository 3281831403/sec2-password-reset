"""Public contract tests for the reset token module."""

from reset.token import check_binding, consume, issue, reset_batch


def test_issued_token_reaches_policy_length(store, policy):
    result = issue(store, "alice", 16, 1000, policy)
    assert result["ok"] is True
    assert isinstance(result["token"], str)
    assert len(result["token"]) >= policy["min_length"]


def test_binding_rejects_another_account(store, policy):
    token = issue(store, "alice", 16, 1000, policy)["token"]
    assert check_binding(token, "alice") is True
    assert check_binding(token, "bob") is False


def test_token_can_only_be_consumed_once(store, policy):
    token = issue(store, "alice", 16, 1000, policy)["token"]
    first = consume(store, token, "alice", 1000)
    second = consume(store, token, "alice", 1000)
    assert first["ok"] is True
    assert second["ok"] is False


def test_expired_token_is_rejected(store, policy):
    token = issue(store, "alice", 16, 1000, policy)["token"]
    later = 1000 + policy["max_age_seconds"] + 1
    assert consume(store, token, "alice", later)["ok"] is False


def test_batch_gives_each_request_its_own_token(policy):
    first_store = {
        "tokens": {},
        "sessions": {},
        "logs": [],
        "seq": 0,
        "policy": dict(policy),
    }
    second_store = {
        "tokens": {},
        "sessions": {},
        "logs": [],
        "seq": 0,
        "policy": dict(policy),
    }
    requests = [
        {"store": first_store, "account": "alice", "entropy": 16},
        {"store": second_store, "account": "bob", "entropy": 16},
    ]
    results = reset_batch(requests, policy, 1000)["results"]
    assert len(results) == 2
    assert results[0]["token"] != results[1]["token"]