"""
ComplyScan Pro — Security Module
Security headers, rate limiting, input validation, CORS, CSRF protection
"""
import re
import time
import hashlib
from fastapi import Request, HTTPException, status
from fastapi.responses import Response
from starlette.middleware.base import BaseHTTPMiddleware
from typing import Callable
import os

# ─── Security Headers Middleware ───────────────────────────────────────────────

SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdn.jsdelivr.net; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data:; "
        "connect-src 'self' http://localhost:*; "
        "frame-ancestors 'none';"
    ),
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cross-Origin-Embedder-Policy": "require-corp",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
}

# HSTS only in production
if os.getenv("ENVIRONMENT", "development") == "production":
    SECURITY_HEADERS["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add security headers to all responses."""
    async def dispatch(self, request: Request, call_next: Callable):
        response = await call_next(request)
        for header, value in SECURITY_HEADERS.items():
            response.headers[header] = value
        # Remove Server header
        if "server" in response.headers:
            del response.headers["server"]
        return response


# ─── Rate Limiting ─────────────────────────────────────────────────────────────

class RateLimiter:
    """Simple in-memory rate limiter (IP-based)."""
    def __init__(self):
        self._requests = {}  # {ip: [timestamps]}
        self._cleanup_interval = 300  # Cleanup every 5 minutes
        self._last_cleanup = time.time()
    
    def _cleanup(self):
        now = time.time()
        if now - self._last_cleanup > self._cleanup_interval:
            cutoff = now - 60  # Keep last 60 seconds
            self._requests = {
                ip: [t for t in timestamps if t > cutoff]
                for ip, timestamps in self._requests.items()
            }
            self._last_cleanup = now
    
    def check(self, ip: str, max_requests: int = 30, window: int = 60) -> bool:
        """Returns True if request is allowed, False if rate limited."""
        self._cleanup()
        now = time.time()
        cutoff = now - window
        
        if ip not in self._requests:
            self._requests[ip] = []
        
        # Remove old entries
        self._requests[ip] = [t for t in self._requests[ip] if t > cutoff]
        
        if len(self._requests[ip]) >= max_requests:
            return False
        
        self._requests[ip].append(now)
        return True


rate_limiter = RateLimiter()


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Rate limiting middleware."""
    async def dispatch(self, request: Request, call_next: Callable):
        # Skip static files
        if request.url.path.startswith("/static/"):
            return await call_next(request)
        
        client_ip = request.client.host if request.client else "unknown"
        
        # Stricter limits for auth endpoints
        if "/auth/" in request.url.path:
            if not rate_limiter.check(client_ip, max_requests=10, window=60):
                raise HTTPException(status_code=429, detail="Too many login attempts. Try again later.")
        else:
            if not rate_limiter.check(client_ip, max_requests=60, window=60):
                raise HTTPException(status_code=429, detail="Too many requests. Slow down.")
        
        return await call_next(request)


# ─── Input Validation ─────────────────────────────────────────────────────────

URL_REGEX = re.compile(
    r'^https?://'
    r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,63}\.?'
    r'|localhost)'
    r'(?::\d{1,5})?'
    r'(?:/?|[/?]\S+)$',
    re.IGNORECASE
)

BLOCKED_DOMAINS = [
    "169.254.", "127.", "10.", "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
    "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
    "192.168.", "0.0.0.0", "localhost", "127.0.0.1",
    "metadata.google.internal", "169.254.169.254",
]


def validate_url(url: str) -> bool:
    """Validate URL for safety and block SSRF attacks."""
    if not url or len(url) > 2048:
        return False
    if not URL_REGEX.match(url):
        return False
    
    # Block internal/private IPs (SSRF protection)
    url_lower = url.lower()
    for blocked in BLOCKED_DOMAINS:
        if blocked in url_lower:
            return False
    
    return True


def sanitize_html(text: str) -> str:
    """Basic HTML sanitization to prevent XSS."""
    if not text:
        return ""
    text = text.replace("&", "&amp;")
    text = text.replace("<", "&lt;")
    text = text.replace(">", "&gt;")
    text = text.replace('"', "&quot;")
    text = text.replace("'", "&#x27;")
    return text


def validate_email(email: str) -> bool:
    """Simple email validation."""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email)) if email else False


# ─── CSRF Protection ──────────────────────────────────────────────────────────

def generate_csrf_token() -> str:
    """Generate a CSRF token."""
    random_bytes = os.urandom(32)
    return hashlib.sha256(random_bytes).hexdigest()


# ─── Cookie Security ──────────────────────────────────────────────────────────

def secure_cookie(response: Response, key: str, value: str, max_age: int = 86400):
    """Set a secure cookie with all security flags."""
    response.set_cookie(
        key=key,
        value=value,
        max_age=max_age,
        expires=max_age,
        httponly=True,
        secure=os.getenv("ENVIRONMENT", "development") == "production",
        samesite="lax",
    )