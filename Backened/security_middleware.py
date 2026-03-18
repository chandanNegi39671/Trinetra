"""
security_middleware.py — Production Security Layer
===================================================
Add to app.py:
    from security_middleware import apply_security
    apply_security(app)

Features:
  ✅ Security headers (XSS, clickjacking, MIME sniff protection)
  ✅ Input sanitization (URL + SMS)
  ✅ Request size limits
  ✅ Suspicious request detection
  ✅ IP-based abuse logging
  ✅ CORS locked to allowed origins
"""

import re, logging, os
from functools import wraps
from flask import request, jsonify
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# ── Config ────────────────────────────────────────────────────────────────────
MAX_URL_LEN    = 2048
MAX_SMS_LEN    = 1600
MAX_BODY_BYTES = 64 * 1024      # 64 KB max request body

ALLOWED_ORIGINS = os.environ.get(
    "ALLOWED_ORIGINS",
    "http://localhost:5000,http://127.0.0.1:5000,http://localhost:3000,http://127.0.0.1:5500"
)
ALLOWED_ORIGINS = [o.strip() for o in ALLOWED_ORIGINS.split(",") if o.strip()]

# Blocked patterns (prompt injection, script injection, SSRF)
BLOCKED_PATTERNS = [
    r"<script",
    r"javascript:",
    r"data:text/html",
    r"\beval\s*\(",
    r"127\.0\.0\.1",
    r"localhost",
    r"0\.0\.0\.0",
    r"169\.254\.",          # AWS metadata
    r"192\.168\.",          # internal LAN — remove if testing locally
    r"10\.\d+\.\d+\.\d+",  # private range
    r"\bfile://",
    r"\bftp://",
]

BLOCKED_RE = re.compile("|".join(BLOCKED_PATTERNS), re.IGNORECASE)

# Private / reserved IPs for SSRF protection
PRIVATE_IP_RE = re.compile(
    r'^(127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|169\.254\.|::1|0\.0\.0\.0)'
)


# ── Security Headers ──────────────────────────────────────────────────────────
def add_security_headers(response):
    response.headers.update({
        "X-Content-Type-Options":      "nosniff",
        "X-Frame-Options":             "DENY",
        "X-XSS-Protection":            "1; mode=block",
        "Strict-Transport-Security":   "max-age=31536000; includeSubDomains",
        "Referrer-Policy":             "strict-origin-when-cross-origin",
        "Content-Security-Policy":     "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
        "Permissions-Policy":          "geolocation=(), microphone=(), camera=()",
        "Cache-Control":               "no-store",
        "Server":                      "Trinetra",   # hide Flask version
    })
    return response


# ── Input Validators ──────────────────────────────────────────────────────────
def validate_url(url: str) -> tuple[bool, str]:
    """Returns (is_valid, error_message)"""
    if not url:
        return False, "URL is required"

    if len(url) > MAX_URL_LEN:
        return False, f"URL too long (max {MAX_URL_LEN} chars)"

    # Must look like a URL
    if not re.match(r'^https?://', url, re.IGNORECASE):
        if "." not in url:
            return False, "Invalid URL format"

    # SSRF protection — block internal IPs/hosts
    try:
        parsed = urlparse(url if url.startswith("http") else "http://"+url)
        host   = parsed.hostname or ""
        if PRIVATE_IP_RE.match(host):
            logger.warning(f"SSRF attempt blocked: {host}")
            return False, "Private/internal IP addresses not allowed"
    except Exception:
        return False, "Could not parse URL"

    # Injection patterns
    if BLOCKED_RE.search(url):
        logger.warning(f"Blocked pattern in URL: {url[:80]}")
        return False, "URL contains blocked patterns"

    return True, ""


def validate_sms(text: str) -> tuple[bool, str]:
    """Returns (is_valid, error_message)"""
    if not text:
        return False, "Text is required"

    if len(text) > MAX_SMS_LEN:
        return False, f"Message too long (max {MAX_SMS_LEN} chars)"

    # Script injection in SMS
    if re.search(r"<script|javascript:|on\w+\s*=", text, re.IGNORECASE):
        return False, "Invalid characters in text"

    return True, ""


# ── Decorators ────────────────────────────────────────────────────────────────
def require_json(f):
    """Reject non-JSON requests to API endpoints"""
    @wraps(f)
    def wrapper(*args, **kwargs):
        ct = request.content_type or ""
        if "application/json" not in ct and request.method in ("POST","PUT","PATCH"):
            return jsonify({"error": "Content-Type must be application/json"}), 415
        return f(*args, **kwargs)
    return wrapper


def validate_url_input(f):
    """Decorator for /analyze endpoint"""
    @wraps(f)
    def wrapper(*args, **kwargs):
        try:
            body = request.get_json(force=True) or {}
        except Exception:
            return jsonify({"error": "Invalid JSON body"}), 400

        url = (body.get("url") or "").strip()
        valid, err = validate_url(url)
        if not valid:
            return jsonify({"error": err}), 400

        return f(*args, **kwargs)
    return wrapper


def validate_sms_input(f):
    """Decorator for /analyze-sms endpoint"""
    @wraps(f)
    def wrapper(*args, **kwargs):
        try:
            body = request.get_json(force=True) or {}
        except Exception:
            return jsonify({"error": "Invalid JSON body"}), 400

        text = (body.get("text") or "").strip()
        valid, err = validate_sms(text)
        if not valid:
            return jsonify({"error": err}), 400

        return f(*args, **kwargs)
    return wrapper


# ── Request Size Limiter ──────────────────────────────────────────────────────
def check_request_size(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        length = request.content_length
        if length and length > MAX_BODY_BYTES:
            return jsonify({"error": f"Request too large (max {MAX_BODY_BYTES//1024}KB)"}), 413
        return f(*args, **kwargs)
    return wrapper


# ── Log suspicious requests ───────────────────────────────────────────────────
def log_suspicious(app):
    @app.before_request
    def detect_suspicious():
        ip  = request.remote_addr
        ua  = request.headers.get("User-Agent","")
        path = request.path

        # Common scanner UAs
        scanners = ["sqlmap","nikto","nmap","masscan","zgrab","dirbuster","hydra","burp"]
        if any(s in ua.lower() for s in scanners):
            logger.warning(f"SCANNER DETECTED: IP={ip} UA={ua[:60]}")

        # Path traversal
        if ".." in path or "/etc/passwd" in path:
            logger.warning(f"PATH TRAVERSAL: IP={ip} PATH={path}")

        # SQLi in query params
        raw_qs = request.query_string.decode("utf-8","ignore")
        if re.search(r"(union\s+select|drop\s+table|'--|\bor\b.+=.+)", raw_qs, re.IGNORECASE):
            logger.warning(f"SQLi ATTEMPT: IP={ip} QS={raw_qs[:80]}")


# ── Master apply function ─────────────────────────────────────────────────────
def apply_security(app):
    """
    Call this once in app.py after creating Flask app:
        from security_middleware import apply_security
        apply_security(app)
    """
    # Security headers on every response
    app.after_request(add_security_headers)

    # Log suspicious requests
    log_suspicious(app)

    logger.info("✅ Security middleware applied")
    return app


# ── CORS helper (tighter than flask-cors default) ─────────────────────────────
def configure_cors(app):
    """
    Call after apply_security if you want tight CORS (production).
    For hackathon demo, flask-cors with CORS(app) is fine.
    """
    from flask_cors import CORS
    CORS(app, origins=ALLOWED_ORIGINS, methods=["GET","POST","OPTIONS"],
         allow_headers=["Content-Type","Authorization"],
         max_age=600)
    logger.info(f"✅ CORS configured for: {ALLOWED_ORIGINS}")
