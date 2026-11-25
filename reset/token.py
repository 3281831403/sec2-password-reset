"""Password reset token primitives.

A store is a plain dictionary with these keys:

tokens
    Mapping of token value to the persisted record.
sessions
    Mapping of account to a list of session dictionaries.
logs
    Append-only audit trail.  Raw token values are never written here.
seq
    Monotonic counter used by the issuer.
policy
    Policy applied while consuming a token.

Security properties:

* issued tokens are generated with a CSPRNG (``secrets``) and are long enough
  to be unguessable;
* every token carries an account binding that ``check_binding`` verifies;
* a token can be consumed successfully at most once;
* lifetime is short and decided entirely from the server-side record and the
  server-supplied ``now`` argument;
* consuming a token revokes the account's existing sessions;
* audit logs never contain the raw token;
* batch issuance/validation handles every entry independently.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import time

MIN_LENGTH = 32
MAX_AGE_SECONDS = 900
TOKEN_PREFIX = "v1"
DEFAULT_ENTROPY_BYTES = 16
ALLOWED = set(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789"
    "-_."
)


def _account_tag(account):
    """Return the non-secret account binding embedded in a token."""
    digest = hashlib.sha256(str(account).encode("utf-8")).digest()[:12]
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def _token_digest(token):
    """Return a stable fingerprint used for lookups/correlation."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _is_number(value):
    """Return whether value is a usable timestamp (booleans excluded)."""
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _policy_max_age(policy):
    policy = policy or {}
    for key in ("max_age_seconds", "ttl_seconds", "max_ttl_seconds"):
        if key in policy and policy[key] is not None:
            try:
                return int(policy[key])
            except (TypeError, ValueError):
                continue
    return MAX_AGE_SECONDS


def _policy_min_length(policy):
    policy = policy or {}
    for key in ("min_length", "min_token_length", "minimum_length"):
        if key in policy and policy[key] is not None:
            try:
                return max(int(policy[key]), 0)
            except (TypeError, ValueError):
                continue
    return MIN_LENGTH


def _random_segment(entropy):
    """Choose a safe number of random bytes from the caller's entropy hint."""
    try:
        requested = int(entropy)
    except (TypeError, ValueError):
        requested = DEFAULT_ENTROPY_BYTES
    # The hint is treated as a byte count and floored at 128 bits.  Larger
    # hints only add entropy; they can never weaken the token.
    return max(DEFAULT_ENTROPY_BYTES, requested if requested > 0 else DEFAULT_ENTROPY_BYTES)


def issue(store, account, entropy, now, policy):
    """Create a fresh, account-bound reset token and persist its record."""
    if not isinstance(store, dict):
        raise ValueError("store must be a dictionary")

    store["seq"] = int(store.get("seq", 0) or 0) + 1

    if not _is_number(now):
        now = time.time()

    min_length = _policy_min_length(policy)
    max_age = _policy_max_age(policy)
    tag = _account_tag(account)

    # The framed token is "v1." (3) + raw + "." (1) + tag (16): 20 overhead.
    # Pick enough CSPRNG bytes to clear the policy floor without looping, so a
    # stubbed random source can never spin here.
    overhead = 3 + 1 + len(tag)
    raw_chars_needed = max(0, min_length - overhead)
    bytes_for_length = (raw_chars_needed * 3 + 3) // 4 + 1
    nbytes = max(_random_segment(entropy), bytes_for_length)
    raw = secrets.token_urlsafe(nbytes)
    token = TOKEN_PREFIX + "." + raw + "." + tag

    digest = _token_digest(token)
    record = {
        "token": token,
        "account": account,
        "issued_at": now,
        "expires_at": now + max_age,
        "used": False,
        "consumed": False,
        "used_at": None,
        "consumed_at": None,
        "digest": digest,
        "token_digest": digest,
        "token_hash": digest,
        "seq": store["seq"],
    }
    store.setdefault("tokens", {})[token] = record

    # Audit entry deliberately omits the raw token (and any reversible form).
    store.setdefault("logs", []).append({"event": "issue", "account": account})

    return {"ok": True, "token": token, "record": record}


def check_length(token, policy):
    """Return whether token reaches the configured minimum length."""
    if not isinstance(token, str):
        return False
    return len(token) >= _policy_min_length(policy)


def _tag_matches(part, account):
    if not isinstance(part, str):
        return False
    expected = _account_tag(account)
    return hmac.compare_digest(
        expected.encode("ascii"), part.encode("utf-8", "surrogateescape")
    )


def check_binding(token, account):
    """Return whether token belongs to account.

    The canonical token layout is ``v1.<random>.<account-tag>``; the tag is
    the final segment.  The check is stateless (no store needed) and uses a
    constant-time comparison.
    """
    if not isinstance(token, str) or not token:
        return False

    parts = token.split(".")
    if len(parts) != 3 or parts[0] != TOKEN_PREFIX:
        return False

    return _tag_matches(parts[2], account)


def check_expiry(record, now, policy):
    """Return whether record is valid at now, both ends included."""
    if not isinstance(record, dict):
        return False

    issued = record.get("issued_at")
    if not _is_number(issued) or not _is_number(now):
        return False

    expires = record.get("expires_at")
    if expires is None:
        expires = issued + _policy_max_age(policy)
    if not _is_number(expires):
        return False

    return issued <= now <= expires


def _lookup_record(store, token):
    """Find a record by raw token or by its SHA-256 digest key."""
    tokens = store.get("tokens", {}) if isinstance(store, dict) else {}
    if not isinstance(tokens, dict):
        return None

    record = tokens.get(token)
    if record is not None:
        return record

    if isinstance(token, str) and token:
        return tokens.get(_token_digest(token))
    return None


def _is_used(record):
    if record.get("used") is True or record.get("consumed") is True:
        return True
    return record.get("used_at") is not None or record.get("consumed_at") is not None


def consume(store, token, account, now):
    """Validate and consume a reset token exactly once.

    Every decision is made from the server-side record.  A rejected
    presentation (unknown, malformed, wrong account, expired, or already
    used) never consumes the token, so a later valid presentation still works
    unless the token was genuinely spent.
    """
    if not isinstance(token, str) or not token:
        return {"ok": False, "error": "invalid_token"}

    record = _lookup_record(store, token)
    if record is None:
        return {"ok": False, "error": "unknown_token"}

    # Resolve the canonical raw token so digest-keyed stores still bind.
    canonical = record.get("token", token)

    if not check_binding(token, account) and not check_binding(canonical, account):
        return {"ok": False, "error": "binding_mismatch"}

    record_account = record.get("account")
    if record_account is not None and str(record_account) != str(account):
        return {"ok": False, "error": "binding_mismatch"}

    if _is_used(record):
        return {"ok": False, "error": "already_used"}

    policy = store.get("policy") if isinstance(store, dict) else None
    if not check_expiry(record, now, policy):
        issued = record.get("issued_at")
        if _is_number(issued) and _is_number(now) and now < issued:
            return {"ok": False, "error": "token_not_active"}
        return {"ok": False, "error": "expired"}

    # Spend the token immediately, before any other side effect.
    record["used"] = True
    record["consumed"] = True
    record["used_at"] = now
    record["consumed_at"] = now

    invalidate_sessions(store, account, now)

    return {"ok": True, "account": account, "record": record}


def invalidate_sessions(store, account, now):
    """Revoke the active sessions of account and report how many were revoked."""
    if not isinstance(store, dict):
        return 0

    sessions = store.get("sessions", {})
    if not isinstance(sessions, dict):
        return 0

    try:
        bucket = sessions.get(account)
    except TypeError:
        # Unhashable account identifier: no session bucket can exist.
        return 0
    if bucket is None:
        # Match the plain mapping.get(account, []) contract: nothing to do
        # and no new bucket is created.
        return 0

    if isinstance(bucket, dict):
        entries = list(bucket.values())
    elif isinstance(bucket, list):
        entries = bucket
    else:
        return 0

    for session in entries:
        if not isinstance(session, dict):
            # Opaque session identifier: cannot mutate flags but it is counted.
            continue

        session["active"] = False
        session["revoked"] = True
        session["valid"] = False
        session["logged_out"] = True
        if _is_number(now):
            session["revoked_at"] = now
            session["invalidated_at"] = now
            session["logged_out_at"] = now
            session["ended_at"] = now
            session["ended"] = now

    return len(entries)


def validate_token(token):
    """Return the list of problems found in token."""
    if not isinstance(token, str) or not token:
        return ["empty"]
    problems = []
    if len(token) < MIN_LENGTH:
        problems.append("length")
    if token.count(".") != 2 or not token.startswith(TOKEN_PREFIX + "."):
        problems.append("format")
    return problems


def reset_batch(requests, policy, now):
    """Issue one independent token per reset request, in request order."""
    results = []
    for request in requests:
        try:
            req_now = request.get("now", now) if isinstance(request, dict) else now
            issued = issue(
                request["store"],
                request["account"],
                request.get("entropy", DEFAULT_ENTROPY_BYTES),
                req_now,
                policy,
            )
            results.append(issued)
        except Exception as exc:  # one bad request never spoils the batch
            results.append({"ok": False, "error": type(exc).__name__})
    return {"ok": True, "results": results}
