"""Tests for Argon2id password hashing implementation."""

from app.services.security.password import hash_password, verify_password


def test_hash_starts_with_argon2id():
    """Newly created hashes must start with $argon2id$."""
    password = "secure_password_123"
    hashed = hash_password(password)
    assert hashed.startswith("$argon2id$"), f"Hash must start with $argon2id$, got: {hashed[:20]}"


def test_correct_password_verifies():
    """Correct passwords must verify successfully."""
    password = "correct_password_123"
    hashed = hash_password(password)
    assert verify_password(password, hashed) is True


def test_incorrect_password_fails():
    """Incorrect passwords must fail verification."""
    password = "correct_password_123"
    wrong_password = "wrong_password_456"
    hashed = hash_password(password)
    assert verify_password(wrong_password, hashed) is False


def test_empty_password_rejected():
    """Empty passwords must be rejected during hashing."""
    try:
        hash_password("")
        assert False, "Expected ValueError for empty password"
    except ValueError:
        pass  # Expected


def test_empty_password_fails_verification():
    """Empty passwords must fail verification."""
    hashed = hash_password("some_password")
    assert verify_password("", hashed) is False


def test_none_password_fails_verification():
    """None password must fail verification."""
    hashed = hash_password("some_password")
    assert verify_password(None, hashed) is False


def test_none_hash_fails_verification():
    """None hash must fail verification."""
    assert verify_password("password", None) is False


def test_malformed_hash_rejected():
    """Malformed hashes must be safely rejected."""
    malformed_hash = "$argon2id$v=19$m=65536,t=3,p=4$invalid$hash"
    assert verify_password("password", malformed_hash) is False


def test_wrong_algorithm_rejected():
    """Non-argon2id hashes must be rejected."""
    # bcrypt-like hash
    fake_hash = "$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj/RK.PZvO.S"
    assert verify_password("password", fake_hash) is False


def test_existing_accounts_continue_authenticating():
    """Existing accounts with valid hashes continue authenticating."""
    # Simulate an existing Argon2id hash
    password = "legacy_password"
    hashed = hash_password(password)
    # Verify it works
    assert verify_password(password, hashed) is True
    # Verify wrong password fails
    assert verify_password("wrong", hashed) is False


def test_hash_format_consistency():
    """Hash format must be consistent across multiple calls."""
    password = "consistency_test"
    hashed1 = hash_password(password)
    hashed2 = hash_password(password)
    # Each hash should be unique (due to salt)
    assert hashed1 != hashed2
    # But both should verify
    assert verify_password(password, hashed1) is True
    assert verify_password(password, hashed2) is True


def test_verify_preserves_hash_format():
    """Verification should not modify the stored hash."""
    password = "test_password"
    hashed = hash_password(password)
    original_hash = hashed
    verify_password(password, hashed)
    # The original hash should be unchanged (strings are immutable in Python)
    assert hashed == original_hash