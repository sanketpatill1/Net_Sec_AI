"""Strict validation and normalization for untrusted URL input."""

from ipaddress import ip_address
from urllib.parse import urlsplit, urlunsplit

MAX_URL_LENGTH = 2_048
ALLOWED_SCHEMES = {"http", "https"}


class URLValidationError(ValueError):
    """Raised when input is not a public HTTP(S) URL-shaped value."""


def normalize_url(value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise URLValidationError("A website URL is required.")
    if len(value) > MAX_URL_LENGTH:
        raise URLValidationError(f"URL must be at most {MAX_URL_LENGTH} characters.")
    if any(ord(char) < 32 for char in value):
        raise URLValidationError("URL contains unsupported control characters.")

    parsed = urlsplit(value.strip())
    if parsed.scheme.lower() not in ALLOWED_SCHEMES:
        raise URLValidationError("Only http:// and https:// URLs are supported.")
    if not parsed.hostname:
        raise URLValidationError("URL must include a hostname.")
    if parsed.username or parsed.password:
        raise URLValidationError("URLs containing credentials are not supported.")
    try:
        # Accessing .port raises ValueError for malformed ports.
        _ = parsed.port
    except ValueError as error:
        raise URLValidationError("URL contains an invalid port.") from error

    hostname = parsed.hostname.lower().rstrip(".")
    if not hostname:
        raise URLValidationError("URL must include a valid hostname.")
    try:
        hostname = ip_address(hostname).compressed
    except ValueError:
        # IDNA conversion produces a consistent hostname without doing DNS.
        try:
            hostname = hostname.encode("idna").decode("ascii")
        except UnicodeError as error:
            raise URLValidationError("URL hostname is invalid.") from error

    netloc = hostname if parsed.port is None else f"{hostname}:{parsed.port}"
    return urlunsplit((parsed.scheme.lower(), netloc, parsed.path or "", parsed.query, parsed.fragment))


def normalize_dataset_url(value: str) -> str:
    """Normalize a training row while accepting source URLs without a scheme.

    The public API intentionally remains stricter and calls normalize_url directly.
    """
    if not isinstance(value, str) or not value.strip():
        raise URLValidationError("Dataset URL is empty.")
    candidate = value.strip()
    if "://" not in candidate:
        candidate = f"http://{candidate}"
    return normalize_url(candidate)
