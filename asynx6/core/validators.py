"""Validators: URL/domain parsing, secret entropy, junk filter."""

from __future__ import annotations

import math
import re
from urllib.parse import urlparse

# Common JS-library noise tokens (verbs, framework primitives) that look like
# secrets but never are. Sourced from V1 utils.GLOBAL_BLACK_LIST.
JUNK_TOKENS: frozenset[str] = frozenset(
    {
        "init", "read", "write", "emit", "on", "off", "toString", "toJSON",
        "apply", "concat", "reset", "slice", "splice", "push", "pop", "shift",
        "unshift", "length", "prototype", "constructor", "render", "state",
        "props", "dispatch", "action", "effect", "mount", "unmount", "click",
        "hover", "touch", "scroll", "resize", "load", "error", "success",
        "translate", "changeLanguage", "getResource", "addResource", "exists",
        "resolve", "format", "reload", "save", "loadUrl", "create", "delete",
        "update", "patch", "get", "post", "put", "options", "head", "connect",
        "trace", "second", "minute", "hour", "day", "week", "month", "year",
        "unidentified", "unrecognized", "anonymous", "language", "namespaces",
        "interpolation", "plural", "suffix", "prefix", "fallback", "bundle",
        "resource", "definition", "handle", "callback", "listener", "event",
        "component", "element", "node", "fragment", "portal", "context",
        "provider", "consumer", "hook", "reducer", "store", "selector", "thunk",
        "saga",
    }
)

_VERB_PREFIXES = ("get", "set", "add", "remove", "has", "is", "on", "to", "from",
                  "create", "handle")

_INTERNAL_IP_RE = re.compile(
    r"^(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
    r"172\.(1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}|"
    r"192\.168\.\d{1,3}\.\d{1,3})$"
)


def normalize_url(target: str) -> str:
    """Ensure URL has a scheme; return as-is if it does."""
    if not target.startswith(("http://", "https://")):
        return "http://" + target
    return target


def extract_domain(url: str) -> str:
    """Extract domain (host[:port] -> host). Strips port for netloc-less scan."""
    parsed = urlparse(url if "://" in url else f"http://{url}")
    host = parsed.netloc or parsed.path
    if ":" in host:
        host = host.split(":")[0]
    return host.lower().strip("/")


def is_internal_ip(ip: str) -> bool:
    """True if the IP is RFC1918 private or loopback-ish."""
    return bool(_INTERNAL_IP_RE.match(ip))


def is_junk_secret(value: object) -> bool:
    """Return True if `value` looks like JS noise, not a real secret."""
    s = str(value).strip()
    if len(s) < 8:
        return True
    if any(c in s for c in "()[]{},;><="):
        return True
    if s.startswith((".", "_")):
        return True
    # camelCase verb prefix (e.g. getElementById) is almost never a secret
    if re.match(r"^[a-z]+[A-Z][a-z]+", s):
        lowered = s.lower()
        if lowered in JUNK_TOKENS:
            return True
        if any(lowered.startswith(v) for v in _VERB_PREFIXES):
            return True
    if s.lower() in JUNK_TOKENS:
        return True
    return False


def mask_secret(secret: str | None) -> str:
    """Mask a secret as `abcd****wxyz` for safe logging."""
    if not secret or len(secret) <= 8:
        return "*******"
    return f"{secret[:4]}****{secret[-4:]}"


def shannon_entropy(s: str) -> float:
    """Shannon entropy in bits/char. High entropy ≈ random ≈ secret-ish."""
    if not s:
        return 0.0
    length = len(s)
    counts = {c: s.count(c) for c in set(s)}
    return -sum((n / length) * math.log2(n / length) for n in counts.values())


def is_high_entropy_secret(value: str, threshold: float = 4.5) -> bool:
    """True if `value` looks high-entropy (random token, base64, hex).

    Threshold 4.5 captures typical API keys, JWT secrets, and base64-encoded
    payloads while filtering out human-readable identifiers.
    """
    return len(value) >= 20 and shannon_entropy(value) >= threshold


def safe_filename(name: str) -> str:
    """Convert any URL/path into a safe filesystem name.

    Replaces protocol separators (`://`), slashes, dots, and colons with
    underscores so the result is safe across filesystems.
    """
    if not name:
        return "index.html"
    cleaned = (name.replace("://", "___").replace("/", "_")
                   .replace(".", "_").replace(":", "_"))
    return cleaned or "index.html"
