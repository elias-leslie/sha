from __future__ import annotations

from base64 import urlsafe_b64decode, urlsafe_b64encode
from dataclasses import dataclass
from hashlib import sha256
import hmac
import logging
from secrets import token_bytes, token_urlsafe
from urllib.parse import urlsplit

from authlib.integrations.starlette_client import OAuth
from cryptography import x509
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.config import read_secure_public_file


SESSION_COOKIE_NAME = "__Host-sha_session"
OIDC_TRANSACTION_COOKIE_NAME = "__Host-sha_oidc_tx"
KEY_ID = "primary"


@dataclass(frozen=True)
class OidcClientConfig:
    issuer: str
    metadata_url: str
    client_id: str
    client_secret: str
    public_base_url: str
    ca_bundle_file: str | None = None

    @property
    def callback_uri(self) -> str:
        return f"{self.public_base_url.rstrip('/')}/api/auth/oidc/callback"


def _derived_key(master_key: bytes, purpose: str) -> bytes:
    return hmac.new(
        master_key,
        f"sha-browser-auth:{purpose}:v1".encode(),
        sha256,
    ).digest()


def keyed_hash(master_key: bytes, purpose: str, value: str) -> str:
    return hmac.new(
        _derived_key(master_key, purpose),
        value.encode("utf-8"),
        sha256,
    ).hexdigest()


def encrypt_code_verifier(master_key: bytes, transaction_id: str, verifier: str) -> str:
    nonce = token_bytes(12)
    ciphertext = AESGCM(_derived_key(master_key, "oidc-transaction-aead")).encrypt(
        nonce,
        verifier.encode("utf-8"),
        transaction_id.encode("utf-8"),
    )
    return urlsafe_b64encode(nonce + ciphertext).rstrip(b"=").decode("ascii")


def decrypt_code_verifier(master_key: bytes, transaction_id: str, encrypted: str) -> str:
    padding = "=" * (-len(encrypted) % 4)
    payload = urlsafe_b64decode(encrypted + padding)
    if len(payload) < 29:
        raise ValueError("invalid encrypted OIDC transaction")
    plaintext = AESGCM(_derived_key(master_key, "oidc-transaction-aead")).decrypt(
        payload[:12],
        payload[12:],
        transaction_id.encode("utf-8"),
    )
    return plaintext.decode("utf-8")


def generate_browser_secret() -> str:
    return token_urlsafe(32)


def csrf_token(master_key: bytes, session_secret: str) -> str:
    digest = hmac.new(
        _derived_key(master_key, "csrf-token"),
        session_secret.encode("utf-8"),
        sha256,
    ).digest()
    return urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def validate_return_to(value: str | None) -> str:
    if not value:
        return "/"
    if len(value) > 2048 or not value.startswith("/") or value.startswith("//"):
        raise ValueError("return_to must be a same-origin absolute path")
    if "\\" in value or any(ord(character) < 0x20 for character in value):
        raise ValueError("return_to must be a same-origin absolute path")
    parsed = urlsplit(value)
    if parsed.scheme or parsed.netloc:
        raise ValueError("return_to must be a same-origin absolute path")
    return value


def validate_oidc_config(config: OidcClientConfig) -> None:
    # Authlib's OAuth2 helper logs the PKCE verifier at DEBUG. Do not allow a
    # verbose application root logger to emit protocol secrets, including when
    # a configured client is injected by a runtime integration.
    logging.getLogger("authlib").setLevel(logging.INFO)
    logging.getLogger("httpx").setLevel(logging.INFO)
    logging.getLogger("httpcore").setLevel(logging.INFO)
    for label, value in (
        ("OIDC issuer", config.issuer),
        ("OIDC metadata URL", config.metadata_url),
        ("public base URL", config.public_base_url),
    ):
        parsed = urlsplit(value)
        if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password:
            raise ValueError(f"{label} must be an absolute HTTPS URL without user information")
        if parsed.fragment:
            raise ValueError(f"{label} must not contain a fragment")
    if urlsplit(config.issuer).query:
        raise ValueError("OIDC issuer must not contain a query")
    if urlsplit(config.public_base_url).query:
        raise ValueError("public base URL must not contain a query")
    if urlsplit(config.public_base_url).path not in {"", "/"}:
        raise ValueError("public base URL must not contain a path")
    if not config.client_id.strip():
        raise ValueError("OIDC client ID must not be empty")
    if not config.client_secret.strip():
        raise ValueError("OIDC client secret must not be empty")
    if config.ca_bundle_file:
        pem_data = read_secure_public_file(
            config.ca_bundle_file,
            label="OIDC CA bundle",
            maximum_bytes=4 * 1024 * 1024,
        )
        try:
            certificates = x509.load_pem_x509_certificates(pem_data)
        except ValueError as exc:
            raise ValueError("OIDC CA bundle must contain parseable PEM certificates") from exc
        if not certificates:
            raise ValueError("OIDC CA bundle must contain at least one certificate")


def build_oidc_client(config: OidcClientConfig):
    validate_oidc_config(config)
    client_kwargs: dict[str, object] = {
        "scope": "openid profile email",
        "code_challenge_method": "S256",
        "token_endpoint_auth_method": "client_secret_basic",
        "timeout": 10.0,
        "follow_redirects": False,
    }
    if config.ca_bundle_file:
        client_kwargs["verify"] = config.ca_bundle_file
    oauth = OAuth()
    return oauth.register(
        "sha_oidc",
        client_id=config.client_id,
        client_secret=config.client_secret,
        server_metadata_url=config.metadata_url,
        client_kwargs=client_kwargs,
    )
