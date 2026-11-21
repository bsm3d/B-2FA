"""One-time password maths (RFC 4226 HOTP, RFC 6238 TOTP, Steam Guard) and otpauth links.

Every number that comes from a file or a link goes through validate_params(), so a hostile
backup cannot make the maths crash, freeze or silently use another algorithm.
"""

import base64
import hashlib
import hmac
import struct
import time
from urllib.parse import parse_qs, unquote, urlparse

STEAM_ALPHABET = "23456789BCDFGHJKMNPQRTVWXY"
ALGORITHMS = {"SHA1": hashlib.sha1, "SHA256": hashlib.sha256, "SHA512": hashlib.sha512}
KINDS = ("TOTP", "HOTP", "STEAM")
MIN_DIGITS, MAX_DIGITS = 4, 10
MIN_PERIOD, MAX_PERIOD = 1, 3600
MAX_COUNTER = 2 ** 64 - 1
MAX_SECRET_CHARS = 256


class OtpError(ValueError):
    pass


def clean_secret(secret) -> str:
    """Normalise a base32 secret: no spaces or dashes, upper case, padded."""
    if not isinstance(secret, str):
        raise OtpError("The secret is missing")
    s = "".join(ch for ch in secret if ch not in " -\t\r\n").upper()
    s = s.rstrip("=")
    return s + "=" * (-len(s) % 8)


def _key(secret) -> bytes:
    cleaned = clean_secret(secret)
    if not cleaned.strip("="):
        raise OtpError("The secret is empty")
    if len(cleaned) > MAX_SECRET_CHARS:
        raise OtpError("The secret is too long")
    try:
        return base64.b32decode(cleaned)
    except Exception as exc:
        raise OtpError("Invalid secret (not base32)") from exc


def check_secret(secret) -> str:
    """Return the secret in its stored form (clean, no padding) or raise OtpError."""
    _key(secret)
    return clean_secret(secret).rstrip("=")


def validate_params(kind="TOTP", digits=6, period=30, algorithm="SHA1", counter=0) -> dict:
    """Check and normalise OTP settings. Raises OtpError on anything out of range."""
    kind = str(kind or "TOTP").upper()
    if kind not in KINDS:
        raise OtpError("Unknown token type: %s" % kind[:20])
    algorithm = str(algorithm or "SHA1").upper()
    if algorithm not in ALGORITHMS:
        raise OtpError("Unsupported algorithm: %s" % algorithm[:20])
    try:
        digits, period, counter = int(digits), int(period), int(counter or 0)
    except (TypeError, ValueError, OverflowError) as exc:
        raise OtpError("Digits, period and counter must be whole numbers") from exc
    if not MIN_DIGITS <= digits <= MAX_DIGITS:
        raise OtpError("Digits must be between %d and %d" % (MIN_DIGITS, MAX_DIGITS))
    if not MIN_PERIOD <= period <= MAX_PERIOD:
        raise OtpError("Period must be between %d and %d seconds" % (MIN_PERIOD, MAX_PERIOD))
    if not 0 <= counter <= MAX_COUNTER:
        raise OtpError("Counter out of range")
    return {"type": kind, "digits": digits, "period": period, "algorithm": algorithm,
            "counter": counter}


def hotp(secret, counter: int, digits: int = 6, algorithm: str = "SHA1") -> str:
    p = validate_params("HOTP", digits, 30, algorithm, counter)
    mac = hmac.new(_key(secret), struct.pack(">Q", p["counter"]), ALGORITHMS[p["algorithm"]]).digest()
    offset = mac[-1] & 0x0F
    number = struct.unpack(">I", mac[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(number % (10 ** p["digits"])).zfill(p["digits"])


def totp(secret, now: float | None = None, period: int = 30, digits: int = 6,
         algorithm: str = "SHA1") -> str:
    now = time.time() if now is None else now
    p = validate_params("TOTP", digits, period, algorithm)
    return hotp(secret, int(now // p["period"]), p["digits"], p["algorithm"])


def steam(secret, now: float | None = None, period: int = 30) -> str:
    now = time.time() if now is None else now
    period = validate_params("STEAM", 5, period)["period"]
    mac = hmac.new(_key(secret), struct.pack(">Q", int(now // period)), hashlib.sha1).digest()
    offset = mac[-1] & 0x0F
    number = struct.unpack(">I", mac[offset:offset + 4])[0] & 0x7FFFFFFF
    out = ""
    for _ in range(5):
        out += STEAM_ALPHABET[number % len(STEAM_ALPHABET)]
        number //= len(STEAM_ALPHABET)
    return out


def otp_params(service: dict) -> dict:
    """Read and validate the OTP settings of a 2FAS service dict (2FAS defaults apply).

    Raises OtpError if the entry is malformed.
    """
    otp = service.get("otp") if isinstance(service, dict) else None
    if not isinstance(otp, dict):
        otp = {}
    return validate_params(otp.get("tokenType") or "TOTP", otp.get("digits") or 6,
                           otp.get("period") or 30, otp.get("algorithm") or "SHA1",
                           otp.get("counter") or 0)


def current_code(service: dict, now: float | None = None) -> tuple[str, int, int]:
    """Return (code, seconds_left, period) for a service. HOTP has no countdown (0, 0).

    Only ever raises OtpError.
    """
    now = time.time() if now is None else now
    try:
        p = otp_params(service)
        secret = service.get("secret")
        if p["type"] == "HOTP":
            return hotp(secret, p["counter"], p["digits"], p["algorithm"]), 0, 0
        period = p["period"]
        left = int(period - now % period) or period
        if p["type"] == "STEAM":
            return steam(secret, now, period), left, period
        return totp(secret, now, period, p["digits"], p["algorithm"]), left, period
    except OtpError:
        raise
    except (ValueError, TypeError, OverflowError, struct.error, ZeroDivisionError, AttributeError) as exc:
        raise OtpError("Cannot compute a code for this account") from exc


def parse_otpauth(uri: str) -> dict:
    """Parse an otpauth:// link into a flat dict.

    Keys: type, name, issuer, account, secret, digits, period, algorithm, counter.
    """
    try:
        parsed = urlparse((uri or "").strip())
    except ValueError as exc:
        raise OtpError("Not a valid link") from exc
    if parsed.scheme != "otpauth":
        raise OtpError("Not an otpauth:// link")
    kind = parsed.netloc.upper()
    if kind not in ("TOTP", "HOTP"):
        raise OtpError("Unsupported otpauth type: " + parsed.netloc[:20])
    label = unquote(parsed.path.lstrip("/"))
    query = {k.lower(): v[0] for k, v in parse_qs(parsed.query).items()}
    issuer, account = "", label
    if ":" in label:
        issuer, account = [x.strip() for x in label.split(":", 1)]
    issuer = query.get("issuer", issuer)
    if not query.get("secret"):
        raise OtpError("The link has no secret")
    secret = check_secret(query["secret"])
    if issuer.lower() == "steam" or query.get("encoder", "").lower() == "steam":
        kind = "STEAM"
    p = validate_params(kind, query.get("digits", 6), query.get("period", 30),
                        query.get("algorithm", "SHA1"), query.get("counter", 0))
    return {
        "type": p["type"],
        "name": (issuer or account)[:256],
        "issuer": issuer[:256],
        "account": account[:256],
        "secret": secret,
        "digits": p["digits"],
        "period": p["period"],
        "algorithm": p["algorithm"],
        "counter": p["counter"],
    }


def group_digits(code: str) -> str:
    """'123456' -> '123 456', '12345678' -> '1234 5678'. Steam codes stay whole."""
    if len(code) in (6, 8) and code.isdigit():
        half = len(code) // 2
        return code[:half] + " " + code[half:]
    return code
