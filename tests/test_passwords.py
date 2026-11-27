
import pytest

from src.security.passwords import (
    hash_password,
    verify_password,
    password_needs_rehash,
)


def test_password_hash_is_not_plaintext():
    password = "Strong-Test-Password-2026!"

    password_hash = hash_password(password)

    assert password_hash != password
    assert password_hash.startswith("$argon2id$")


def test_correct_password_is_verified():
    password = "Strong-Test-Password-2026!"

    password_hash = hash_password(password)

    assert verify_password(password, password_hash) is True


def test_incorrect_password_is_rejected():
    password_hash = hash_password("Correct-Password-2026!")

    assert verify_password("Wrong-Password-2026!", password_hash) is False


def test_same_password_produces_different_hashes():
    password = "Strong-Test-Password-2026!"

    first_hash = hash_password(password)
    second_hash = hash_password(password)

    assert first_hash != second_hash
    assert verify_password(password, first_hash)
    assert verify_password(password, second_hash)


def test_empty_password_is_rejected():
    with pytest.raises(ValueError):
        hash_password("")


def test_invalid_hash_is_rejected():
    assert verify_password("some-password", "not-a-valid-hash") is False


def test_current_hash_does_not_need_rehash():
    password_hash = hash_password("Strong-Test-Password-2026!")

    assert password_needs_rehash(password_hash) is False

def test_invalid_hash_needs_rehash():
    assert password_needs_rehash("invalid-hash") is True
    assert password_needs_rehash(None) is True


def test_password_at_maximum_byte_length_is_accepted():
    password = "a" * 1024

    password_hash = hash_password(password)

    assert verify_password(password, password_hash) is True


def test_password_over_maximum_byte_length_is_rejected():
    password = "a" * 1025

    with pytest.raises(ValueError):
        hash_password(password)


def test_oversized_password_is_rejected_during_verification():
    password_hash = hash_password("Valid-Password-2026!")
    oversized_password = "a" * 1025

    assert verify_password(oversized_password, password_hash) is False


def test_unicode_password_uses_utf8_byte_limit():
    password = "â‚¬" * 342  # 1,026 UTF-8 bytes

    with pytest.raises(ValueError):
        hash_password(password)
