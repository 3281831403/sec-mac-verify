from __future__ import annotations

import hashlib
import hmac
import re
from collections.abc import Iterable, Mapping
from typing import Any

_HEX_RE = re.compile(r"\A[0-9a-fA-F]*\Z")
# Width of the fixed-width, big-endian length prefix used to frame segments.
_LENGTH_BYTES = 8
# Domain-separation label for purpose-specific derived keys.
_DERIVE_LABEL = b"macv:derive-key:v1"


def _as_bytes(value: bytes | bytearray | memoryview | str, field: str) -> bytes:
    if isinstance(value, str):
        return value.encode("utf-8")
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value)
    raise TypeError(f"{field} must be bytes or text")


def _framed(chunk: bytes) -> bytes:
    """Prefix a chunk with its fixed-width byte length.

    The framing is uniquely decodable, so different segmentations can never
    collapse into the same concatenated byte string.
    """
    return len(chunk).to_bytes(_LENGTH_BYTES, "big") + chunk


def derive_key(master: bytes | str, purpose: str) -> bytes:
    master_bytes = _as_bytes(master, "master")
    if not isinstance(purpose, str) or not purpose:
        raise ValueError("purpose must be non-empty text")
    purpose_bytes = purpose.encode("utf-8")
    info = _DERIVE_LABEL + _framed(purpose_bytes)
    return hmac.new(master_bytes, info, hashlib.sha256).digest()


def canonical_message(parts: Iterable[bytes | str]) -> bytes:
    return b"".join(_framed(_as_bytes(part, "part")) for part in parts)


def _mac_hex(key: bytes | str, message: bytes | str) -> str:
    key_bytes = _as_bytes(key, "key")
    message_bytes = _as_bytes(message, "message")
    return hmac.new(key_bytes, message_bytes, hashlib.sha256).hexdigest()


def compute(key: bytes | str, message: bytes | str) -> str:
    # Full-length, lower-case hexadecimal digest (64 chars for SHA-256).
    return _mac_hex(key, message)


def check_length(provided: str, expected: str) -> bool:
    # The authentication code must be present at its complete, exact length;
    # any truncation (or extension) is rejected.
    if not isinstance(provided, str) or not isinstance(expected, str):
        return False
    return len(provided) == len(expected)


def verify(
    key: bytes | str, message: bytes | str, provided: str
) -> bool:
    # Malformed presented codes are simply invalid: verification answers with
    # False rather than exposing distinct errors to a caller.
    if not isinstance(provided, str):
        return False
    if _HEX_RE.fullmatch(provided) is None:
        return False

    expected = _mac_hex(key, message)

    # Length must be checked before the content comparison. check_length only
    # admits the complete code, so no truncated prefix can ever be compared as
    # if it were sufficient.
    if not check_length(provided, expected):
        return False

    # Full-length, constant-time comparison. Hex is case-insensitive, so
    # normalize the presented code before comparing.
    return hmac.compare_digest(expected, provided.lower())


def check_purpose(key_purpose: str, expected: str) -> bool:
    return (
        isinstance(key_purpose, str)
        and isinstance(expected, str)
        and key_purpose == expected
    )


def validate_config(config: Mapping[str, Any]) -> list[str]:
    if not isinstance(config, Mapping):
        return ["config must be a mapping"]

    issues: list[str] = []
    master = config.get("master")
    if not master:
        issues.append("master key must not be empty")

    purpose = config.get("purpose")
    if not isinstance(purpose, str) or not purpose.strip():
        issues.append("a non-empty purpose is required for key separation")

    # Truncated authentication codes are never acceptable; a configuration
    # that asks to allow them is invalid.
    if config.get("allow_truncated"):
        issues.append(
            "allow_truncated must be false: truncated authentication codes "
            "are always rejected"
        )

    return issues


def mac_batch(
    requests: Iterable[Mapping[str, Any]], config: Mapping[str, Any]
) -> dict[int, bool]:
    try:
        request_list = list(requests)
    except TypeError:
        return {}

    issues = validate_config(config)
    if issues:
        return {index: False for index in range(len(request_list))}

    key = derive_key(config["master"], config["purpose"])
    expected_purpose = config["purpose"]
    results: dict[int, bool] = {}

    for index, request in enumerate(request_list):
        if not isinstance(request, Mapping):
            results[index] = False
            continue

        request_purpose = request.get("purpose", expected_purpose)
        if not check_purpose(request_purpose, expected_purpose):
            results[index] = False
            continue

        message = request.get("message", b"")
        # Every request is verified with its own authentication code; codes
        # from other requests are never carried over or reused.
        provided = request.get("mac", request.get("signature", ""))

        try:
            results[index] = verify(key, message, provided)
        except (TypeError, ValueError):
            results[index] = False

    return results
