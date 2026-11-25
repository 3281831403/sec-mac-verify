import hashlib
import hmac

from macv import (
    canonical_message,
    check_length,
    compute,
    derive_key,
    mac_batch,
    verify,
)

MASTER = b"demo-master-secret"
PURPOSE = "orders"


def _key() -> bytes:
    return derive_key(MASTER, PURPOSE)


def _message() -> bytes:
    return canonical_message([b"acct-42", b"pay", b"1250"])


def test_compute_matches_reference() -> None:
    key = _key()
    message = _message()
    expected = hmac.new(key, message, hashlib.sha256).hexdigest()
    assert compute(key, message) == expected


def test_complete_authentication_code_is_accepted() -> None:
    key = _key()
    message = _message()
    mac = compute(key, message)
    assert verify(key, message, mac) is True


def test_single_bit_change_is_rejected() -> None:
    key = _key()
    message = _message()
    mac = compute(key, message)
    assert verify(key, message, mac) is True

    replacement = "0" if mac[-1] != "0" else "1"
    altered = mac[:-1] + replacement
    assert verify(key, message, altered) is False


def test_short_authentication_code_is_rejected() -> None:
    key = _key()
    message = _message()
    mac = compute(key, message).lower()
    assert check_length(mac[:8], mac) is False
    assert verify(key, message, mac[:8]) is False


def test_batch_requests_are_independent() -> None:
    key = _key()
    config = {
        "master": MASTER,
        "purpose": PURPOSE,
        "allow_truncated": False,
    }
    first = b"first-request"
    second = b"second-request"
    requests = [
        {"message": first, "mac": compute(key, first)},
        {"message": second, "mac": compute(key, second)},
    ]

    assert mac_batch(requests, config) == {0: True, 1: True}