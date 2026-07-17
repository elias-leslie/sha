from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import re
from secrets import token_urlsafe

ENROLLMENT_TOKEN_PATTERN = re.compile(
    r"^sha_enroll\.(et_[0-9a-f]{32})\.([A-Za-z0-9_-]{43,128})$"
)
DEVICE_CREDENTIAL_PATTERN = re.compile(
    r"^sha_device\.(dc_[A-Za-z0-9_-]{16,64})\.([A-Za-z0-9_-]{43,128})$"
)
CREDENTIAL_ID_PATTERN = re.compile(r"^dc_[A-Za-z0-9_-]{16,64}$")
INSTALLATION_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{15,127}$")

_ENROLLMENT_SECRET_DOMAIN = b"sha/enrollment-token/v1"
_DEVICE_SECRET_DOMAIN = b"sha/device-credential/v1"
_EXCHANGE_REQUEST_DOMAIN = b"sha/enrollment-exchange/v1"


def validate_hmac_key(key: bytes | None) -> bytes | None:
    if key is not None and len(key) < 32:
        raise ValueError("credential HMAC key must contain at least 32 bytes")
    return key


def generate_enrollment_token(token_id: str) -> tuple[str, str]:
    secret = token_urlsafe(32)
    return f"sha_enroll.{token_id}.{secret}", secret


def parse_enrollment_token(value: str) -> tuple[str, str] | None:
    match = ENROLLMENT_TOKEN_PATTERN.fullmatch(value)
    if match is None or not is_canonical_secret(match.group(2)):
        return None
    return match.group(1), match.group(2)


def parse_device_credential(value: str) -> tuple[str, str] | None:
    match = DEVICE_CREDENTIAL_PATTERN.fullmatch(value)
    if match is None or not is_canonical_secret(match.group(2)):
        return None
    return match.group(1), match.group(2)


def is_canonical_credential_id(value: str) -> bool:
    return CREDENTIAL_ID_PATTERN.fullmatch(value) is not None


def is_canonical_installation_id(value: str) -> bool:
    return INSTALLATION_ID_PATTERN.fullmatch(value) is not None


def is_canonical_secret(value: str) -> bool:
    if not 43 <= len(value) <= 128:
        return False
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, binascii.Error):
        return False
    if len(raw) < 32:
        return False
    canonical = base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
    return hmac.compare_digest(canonical, value)


def enrollment_secret_hash(key: bytes, token_id: str, secret: str) -> str:
    return _keyed_hash(key, _ENROLLMENT_SECRET_DOMAIN, token_id, secret)


def device_secret_hash(key: bytes, credential_id: str, secret: str) -> str:
    return _keyed_hash(key, _DEVICE_SECRET_DOMAIN, credential_id, secret)


def exchange_request_hash(key: bytes, token_id: str, values: dict[str, object]) -> str:
    canonical = json.dumps(values, separators=(",", ":"), sort_keys=True, ensure_ascii=False)
    return _keyed_hash(key, _EXCHANGE_REQUEST_DOMAIN, token_id, canonical)


def _keyed_hash(key: bytes, domain: bytes, public_id: str, secret: str) -> str:
    message = domain + b"\x00" + public_id.encode("utf-8") + b"\x00" + secret.encode("utf-8")
    return hmac.new(key, message, hashlib.sha256).hexdigest()
