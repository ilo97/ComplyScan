"""
ComplyScan - Multi-Compliance Web Crawler (GDPR + SOC2 + CCPA)
===============================================================
Playwright tabanlı web crawler:
1. URL'den cookie'leri topla ve kategorize et
2. HTTP header'ları oku ve analiz et (GDPR + SOC2)
3. Privacy policy sayfasını bul ve raw text çek
4. Form'ları tara (consent checkbox, GDPR uyumu)
5. SOC2 kontrolleri: SSL/TLS, encryption header'ları, access control
6. CCPA kontrolleri: "Do Not Sell" linki, California privacy hakları
7. Tüm veriyi JSON formatında çıktı olarak ver

Kullanım:
    python crawler.py https://example.com
    python crawler.py --json '{"url": "https://example.com", "compliance": "all"}'
"""

import asyncio
import json
import os
import re
import sys
import time
import ssl
import socket
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup
from playwright.async_api import async_playwright

# Browser path
PLAYWRIGHT_BROWSERS_PATH = os.environ.get(
    "PLAYWRIGHT_BROWSERS_PATH",
    "/home/team/shared/playwright_browsers"
)
os.environ["PLAYWRIGHT_BROWSERS_PATH"] = PLAYWRIGHT_BROWSERS_PATH

# --- Compliance Types ---
COMPLIANCE_TYPES = ["gdpr", "soc2", "ccpa", "all"]

# ============================================================================
# COOKIE CATEGORIZATION
# ============================================================================

COOKIE_CATEGORIES = {
    "essential": [
        "session", "csrf", "xsrf", "__cfduid", "_cfduid", "laravel_session",
        "PHPSESSID", "JSESSIONID", "ASPSESSIONID", "ASP.NET_SessionId",
        "connect.sid", "auth", "token", "sid", "user_session",
    ],
    "analytics": [
        "_ga", "_gid", "_gat", "_ga_", "__utma", "__utmb", "__utmc",
        "__utmt", "__utmz", "__utmv", "_gcl_au", "amplitude", "mp_",
        "ajs_", "_hjSession", "_hjSessionUser", "collect", "hotjar",
        "gtm", "_clck", "_clsk", "clarity",
    ],
    "marketing": [
        "_fbp", "fr", "tr", "ads", "ad_", "IDE", "test_cookie",
        "MUID", "_pin_unauth", "_tt_enable", "_ttp", "bcookie",
        "bscookie", "lidc", "UserMatchHistory", "lang", "personalization",
        "criteo", "uid", "Tapad", "_gcl_aw", "_gcl_dc",
    ],
    "functional": [
        "language", "lang", "locale", "country", "currency",
        "font_size", "theme", "display", "preferences", "pref",
        "persistent", "user_settings", "settings", "consent",
        "cookieconsent", "cookies_accepted", "cookies-enabled",
    ],
}


def categorize_cookie(name: str) -> str:
    """Cookie adına göre kategori belirle."""
    name_lower = name.lower().strip()
    for category, keywords in COOKIE_CATEGORIES.items():
        for keyword in keywords:
            if keyword.lower() in name_lower:
                return category
    return "other"


def is_third_party_cookie(domain: str, cookie_domain: str) -> bool:
    """Cookie'nin 3rd-party olup olmadığını kontrol et."""
    if not cookie_domain:
        return False
    cookie_domain = cookie_domain.lstrip(".")
    domain = domain.lower()
    cookie_domain = cookie_domain.lower()
    return cookie_domain not in domain and domain not in cookie_domain


# ============================================================================
# HEADER ANALİZİ (GDPR + SOC2)
# ============================================================================

SECURITY_HEADERS = {
    # GDPR-relevant headers
    "X-Frame-Options": {
        "description": "Clickjacking koruması",
        "expected": ["DENY", "SAMEORIGIN"],
        "good_values": ["DENY", "SAMEORIGIN"],
        "compliance": ["gdpr", "soc2", "all"],
    },
    "Content-Security-Policy": {
        "description": "XSS ve veri sızıntısı koruması",
        "expected": [],
        "good_values": [],
        "compliance": ["gdpr", "soc2", "all"],
    },
    "Strict-Transport-Security": {
        "description": "SSL/TLS zorlaması (HSTS)",
        "expected": [],
        "good_values": ["max-age="],
        "compliance": ["gdpr", "soc2", "all"],
    },
    "X-Content-Type-Options": {
        "description": "MIME type sniffing koruması",
        "expected": ["nosniff"],
        "good_values": ["nosniff"],
        "compliance": ["gdpr", "soc2", "all"],
    },
    "Referrer-Policy": {
        "description": "Referrer bilgisi kontrolü",
        "expected": [],
        "good_values": ["strict-origin-when-cross-origin", "no-referrer", "same-origin"],
        "compliance": ["gdpr", "all"],
    },
    "Permissions-Policy": {
        "description": "API izinleri kontrolü (GDPR)",
        "expected": [],
        "good_values": [],
        "compliance": ["gdpr", "all"],
    },
    "Access-Control-Allow-Origin": {
        "description": "CORS politikası",
        "expected": [],
        "good_values": [],
        "compliance": ["gdpr", "soc2", "all"],
    },
    "Set-Cookie": {
        "description": "Cookie güvenlik ayarları (Secure, HttpOnly, SameSite)",
        "expected": [],
        "good_values": [],
        "compliance": ["gdpr", "all"],
    },
    # SOC2-specific headers
    "X-XSS-Protection": {
        "description": "XSS koruması (SOC2)",
        "expected": ["1; mode=block"],
        "good_values": ["1; mode=block", "1"],
        "compliance": ["soc2", "all"],
    },
    "Cache-Control": {
        "description": "Önbellek politikası - hassas veri koruması (SOC2)",
        "expected": [],
        "good_values": ["no-store", "no-cache", "must-revalidate"],
        "compliance": ["soc2", "all"],
    },
    "Pragma": {
        "description": "Önbellek politikası (SOC2)",
        "expected": [],
        "good_values": ["no-cache"],
        "compliance": ["soc2", "all"],
    },
    "Expires": {
        "description": "İçerik son kullanma tarihi (SOC2)",
        "expected": [],
        "good_values": ["0", "-1"],
        "compliance": ["soc2", "all"],
    },
}


def analyze_security_headers(headers: dict, compliance: str = "all") -> dict:
    """HTTP header'larını compliance tipine göre analiz et."""
    result = {}
    for header, info in SECURITY_HEADERS.items():
        # Compliance filtresi
        if compliance != "all" and compliance not in info.get("compliance", ["all"]):
            continue

        value = headers.get(header.lower(), headers.get(header, None))
        if value:
            is_good = any(good.lower() in value.lower() for good in info["good_values"]) if info["good_values"] else True
            result[header] = {
                "present": True,
                "value": value,
                "status": "ok" if is_good else "needs_review",
                "description": info["description"],
                "compliance": info.get("compliance", ["all"]),
            }
        else:
            result[header] = {
                "present": False,
                "value": None,
                "status": "missing",
                "description": info["description"],
                "compliance": info.get("compliance", ["all"]),
            }
    return result


# ============================================================================
# PRIVACY POLICY
# ============================================================================

PRIVACY_POLICY_KEYWORDS = [
    "privacy", "privacy-policy", "privacy_policy", "privacy policy",
    "gdpr", "data-privacy", "datenschutz", "confidentialité",
    "politique de confidentialité", "privacy notice",
    "cookie-policy", "cookie_policy", "cookie policy",
    "legal", "terms", "veri politikası", "gizlilik",
]

PRIVACY_POLICY_PATTERNS = [
    r"privacy[_-]?policy",
    r"privacy[_-]?notice",
    r"gdpr",
    r"cookie[_-]?policy",
    r"data[_-]?privacy",
    r"gizlilik",
    r"veri[_-]?politikası",
    r"datenschutz",
]


def find_privacy_policy_url(soup: BeautifulSoup, base_url: str) -> Optional[str]:
    """Sayfadaki tüm linkleri tara ve privacy policy URL'sini bul."""
    candidates = []
    for a_tag in soup.find_all("a", href=True):
        href = a_tag["href"]
        text = a_tag.get_text().strip().lower()
        full_url = urljoin(base_url, href)

        for pattern in PRIVACY_POLICY_PATTERNS:
            if re.search(pattern, text) or re.search(pattern, href.lower()):
                candidates.append((full_url, "link_text"))
                break

        for kw in PRIVACY_POLICY_KEYWORDS:
            if kw in href.lower():
                candidates.append((full_url, "href"))
                break

    if candidates:
        seen = set()
        unique = []
        for url, typ in candidates:
            if url not in seen:
                seen.add(url)
                unique.append((url, typ))
        unique.sort(key=lambda x: (0 if x[1] == "link_text" else 1))
        return unique[0][0]

    return None


def extract_privacy_policy_text(url: str) -> Optional[str]:
    """Privacy policy sayfasından raw text çek."""
    try:
        resp = requests.get(url, timeout=15, headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                          "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        })
        resp.raise_for_status()
        soup = BeautifulSoup(resp.text, "html.parser")
        for tag in soup(["script", "style", "nav", "footer", "header"]):
            tag.decompose()
        text = soup.get_text(separator="\n", strip=True)
        lines = [line.strip() for line in text.splitlines() if line.strip()]
        return "\n".join(lines[:500])
    except Exception as e:
        return f"[HATA] Privacy policy alınamadı: {str(e)}"


# ============================================================================
# FORM TARAYICI (GDPR)
# ============================================================================

GDPR_FORM_KEYWORDS = {
    "consent": ["consent", "onay", "kabul", "accept", "agree", "einwilligung"],
    "gdpr_checkbox": ["gdpr", "data processing", "veri işleme", "veri politikası"],
    "marketing": ["marketing", "pazarlama", "newsletter", "bülten", "ticari"],
    "analytics": ["analytics", "analiz", "tracking", "izleme", "cookies"],
}


def analyze_forms(soup: BeautifulSoup) -> list:
    """Sayfadaki form'ları tara ve GDPR uyumluluğunu analiz et."""
    forms = []
    for i, form in enumerate(soup.find_all("form")):
        form_data = {
            "form_index": i,
            "action": form.get("action", ""),
            "method": form.get("method", "get").upper(),
            "inputs": [],
            "has_consent_checkbox": False,
            "has_gdpr_checkbox": False,
            "has_submit_button": False,
            "gdpr_compliance_notes": [],
        }

        for input_tag in form.find_all(["input", "textarea", "select"]):
            input_type = input_tag.get("type", "text")
            input_name = input_tag.get("name", "")
            input_id = input_tag.get("id", "")
            input_placeholder = input_tag.get("placeholder", "")
            label_text = ""
            associated_label = soup.find("label", attrs={"for": input_id})
            if associated_label:
                label_text = associated_label.get_text(strip=True)

            combined_text = f"{input_name} {input_id} {input_placeholder} {label_text}".lower()

            is_checkbox = input_type == "checkbox"
            is_consent = any(kw in combined_text for kw in GDPR_FORM_KEYWORDS["consent"])
            is_gdpr = any(kw in combined_text for kw in GDPR_FORM_KEYWORDS["gdpr_checkbox"])
            is_marketing = any(kw in combined_text for kw in GDPR_FORM_KEYWORDS["marketing"])
            is_analytics = any(kw in combined_text for kw in GDPR_FORM_KEYWORDS["analytics"])

            input_info = {
                "type": input_type,
                "name": input_name,
                "id": input_id,
                "placeholder": input_placeholder,
                "label": label_text,
                "required": input_tag.get("required") is not None or "required" in str(input_tag),
            }

            if is_checkbox and is_consent:
                form_data["has_consent_checkbox"] = True
                input_info["purpose"] = "consent"
            elif is_checkbox and is_gdpr:
                form_data["has_gdpr_checkbox"] = True
                input_info["purpose"] = "gdpr"
            elif is_checkbox and (is_marketing or is_analytics):
                input_info["purpose"] = "marketing_or_analytics"
            elif input_type == "submit" or input_type == "button":
                form_data["has_submit_button"] = True
                input_info["purpose"] = "submit"

            form_data["inputs"].append(input_info)

        if form_data["has_consent_checkbox"]:
            form_data["gdpr_compliance_notes"].append("✅ Açık rıza checkbox'ı mevcut")
        else:
            form_data["gdpr_compliance_notes"].append("⚠️ Açık rıza checkbox'ı bulunamadı - GDPR Madde 7 ihlali olabilir")

        if form_data["has_gdpr_checkbox"]:
            form_data["gdpr_compliance_notes"].append("✅ GDPR veri işleme onayı mevcut")

        forms.append(form_data)

    return forms


# ============================================================================
# SOC2 KONTROLLERİ
# ============================================================================

def check_ssl_tls(url: str) -> dict:
    """SSL/TLS sertifika ve şifreleme kontrolü (SOC2)."""
    result = {
        "certificate_valid": False,
        "issuer": None,
        "expiry_date": None,
        "protocol_version": None,
        "cipher": None,
        "errors": [],
    }
    try:
        hostname = urlparse(url).hostname
        port = 443
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                result["certificate_valid"] = True
                result["issuer"] = dict(cert.get("issuer", []))
                result["expiry_date"] = cert.get("notAfter")
                try:
                    tls_ver = ssock.version()
                except Exception:
                    tls_ver = None
                result["protocol_version"] = tls_ver if tls_ver else "TLSv1.3"
                try:
                    cipher_info = ssock.cipher()
                    result["cipher"] = cipher_info
                    cipher_name = cipher_info[0] if cipher_info else ""
                except Exception:
                    result["cipher"] = None
                    cipher_name = ""
                result["tls_version_ok"] = result["protocol_version"] in ["TLSv1.2", "TLSv1.3", "TLS 1.2", "TLS 1.3"]
                result["cipher_strength_ok"] = "ECDHE" in cipher_name or "DHE" in cipher_name
    except Exception as e:
        result["errors"].append(f"SSL/TLS kontrol hatası: {str(e)}")

    return result


def check_encryption_headers(headers: dict) -> dict:
    """Encryption ile ilgili header'ları kontrol et (SOC2)."""
    encryption_headers = {
        "Content-Security-Policy": {
            "present": headers.get("content-security-policy") is not None,
            "value": headers.get("content-security-policy"),
        },
        "Strict-Transport-Security": {
            "present": headers.get("strict-transport-security") is not None,
            "value": headers.get("strict-transport-security"),
            "has_max_age": "max-age=" in (headers.get("strict-transport-security") or ""),
        },
    }

    # Check if HSTS has sufficient max-age (>= 6 months = 15768000)
    hsts = headers.get("strict-transport-security", "")
    max_age_match = re.search(r"max-age=(\d+)", hsts)
    encryption_headers["Strict-Transport-Security"]["max_age_seconds"] = int(max_age_match.group(1)) if max_age_match else 0
    encryption_headers["Strict-Transport-Security"]["max_age_sufficient"] = (
        int(max_age_match.group(1)) >= 15768000 if max_age_match else False
    )

    return encryption_headers


def check_access_control(headers: dict) -> dict:
    """Access control header'larını kontrol et (SOC2)."""
    return {
        "Access-Control-Allow-Origin": {
            "present": headers.get("access-control-allow-origin") is not None,
            "value": headers.get("access-control-allow-origin"),
            "is_restrictive": headers.get("access-control-allow-origin") not in ["*", "null"],
        },
        "Access-Control-Allow-Methods": {
            "present": headers.get("access-control-allow-methods") is not None,
            "value": headers.get("access-control-allow-methods"),
        },
        "Access-Control-Allow-Headers": {
            "present": headers.get("access-control-allow-headers") is not None,
            "value": headers.get("access-control-allow-headers"),
        },
    }


# ============================================================================
# CCPA KONTROLLERİ
# ============================================================================

CCPA_KEYWORDS = {
    "do_not_sell": [
        "do not sell", "do-not-sell", "don't sell", "dont sell",
        "satmayın", "satma", "do not sell my personal information",
        "do-not-sell-my-personal-information", "dsn", "dnsmpi",
    ],
    "california_privacy": [
        "california privacy", "california consumer privacy",
        "california rights", "ccpa", "california civil code",
        "california online privacy", "your california privacy",
        "kaliforniya gizlilik",
    ],
    "opt_out": [
        "opt out", "opt-out", "optout", "opt out of sale",
        "veri satışını durdur", "çıkış yap",
    ],
}

CCPA_LINK_PATTERNS = [
    r"do[-\s]?not[-\s]?sell",
    r"california[-\s]?privacy",
    r"ccpa",
    r"opt[-\s]?out",
    r"your[-\s]?privacy[-\s]?rights",
]


def check_ccpa_compliance(soup: BeautifulSoup, base_url: str) -> dict:
    """CCPA uyumluluk kontrolleri."""
    result = {
        "do_not_sell_link_found": False,
        "do_not_sell_link_url": None,
        "california_privacy_link_found": False,
        "california_privacy_url": None,
        "opt_out_mechanism_found": False,
        "ccpa_notes": [],
    }

    for a_tag in soup.find_all("a", href=True):
        href = a_tag["href"]
        text = a_tag.get_text().strip().lower()
        full_url = urljoin(base_url, href)

        # Do Not Sell linki kontrolü
        for keyword in CCPA_KEYWORDS["do_not_sell"]:
            if keyword in text or keyword in href.lower():
                if not result["do_not_sell_link_found"]:
                    result["do_not_sell_link_found"] = True
                    result["do_not_sell_link_url"] = full_url
                break

        # California privacy rights linki
        for keyword in CCPA_KEYWORDS["california_privacy"]:
            if keyword in text or keyword in href.lower():
                if not result["california_privacy_link_found"]:
                    result["california_privacy_link_found"] = True
                    result["california_privacy_url"] = full_url
                break

        # Opt-out mekanizması
        for keyword in CCPA_KEYWORDS["opt_out"]:
            if keyword in text or keyword in href.lower():
                result["opt_out_mechanism_found"] = True
                break

    # CCPA notları
    if result["do_not_sell_link_found"]:
        result["ccpa_notes"].append("✅ 'Do Not Sell My Personal Information' linki mevcut (CCPA uyumu)")
    else:
        result["ccpa_notes"].append("⚠️ 'Do Not Sell My Personal Information' linki bulunamadı - CCPA ihlali olabilir")

    if result["california_privacy_link_found"]:
        result["ccpa_notes"].append("✅ California gizlilik hakları sayfası mevcut")

    if result["opt_out_mechanism_found"]:
        result["ccpa_notes"].append("✅ Opt-out mekanizması mevcut")

    return result


# ============================================================================
# PERFORMANCE OPTIMIZATION
# ============================================================================

async def measure_page_load(page, target_url: str, timeout: int = 30000) -> dict:
    """Sayfa yüklenme performansını ölç."""
    perf = {
        "navigation_start": None,
        "dom_content_loaded": None,
        "load_complete": None,
        "total_load_time_ms": None,
        "status": "unknown",
    }
    try:
        start_time = time.time()
        await page.goto(target_url, wait_until="networkidle", timeout=timeout)
        load_time = (time.time() - start_time) * 1000

        perf["total_load_time_ms"] = round(load_time, 2)

        if load_time < 2000:
            perf["status"] = "fast"
        elif load_time < 5000:
            perf["status"] = "moderate"
        else:
            perf["status"] = "slow"

        # Try getting Performance API metrics (Chrome only)
        try:
            perf["navigation_start"] = await page.evaluate("performance.timing.navigationStart")
            perf["dom_content_loaded"] = await page.evaluate("performance.timing.domContentLoadedEventEnd") - await page.evaluate("performance.timing.navigationStart")
            perf["load_complete"] = await page.evaluate("performance.timing.loadEventEnd") - await page.evaluate("performance.timing.navigationStart")
        except Exception:
            pass

    except Exception as e:
        perf["status"] = "failed"
        perf["error"] = str(e)

    return perf


# ============================================================================
# ANA CRAWLER
# ============================================================================

async def crawl_url(target_url: str, compliance: str = "all") -> dict:
    """Tek bir URL'yi Playwright ile tara ve tüm verileri topla."""
    domain = urlparse(target_url).netloc
    timestamp = datetime.now(timezone.utc).isoformat()

    # Validate compliance type
    if compliance not in COMPLIANCE_TYPES:
        compliance = "all"

    result = {
        "scan_metadata": {
            "url": target_url,
            "domain": domain,
            "timestamp": timestamp,
            "compliance": compliance,
            "tool": "ComplyScan Crawler v2.0",
        },
        "cookies": [],
        "security_headers": {},
        "privacy_policy": {},
        "forms": [],
        "page_info": {},
        "security_audit": {},
        "ccpa_checks": {},
        "errors": [],
        "gdpr_notes": [],
    }

    async with async_playwright() as p:
        browser = await p.chromium.launch(
            headless=True,
            args=[
                "--no-sandbox",
                "--disable-setuid-sandbox",
                "--disable-dev-shm-usage",
                "--disable-gpu",
            ]
        )
        context = await browser.new_context(
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                       "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            viewport={"width": 1920, "height": 1080},
            ignore_https_errors=False,
        )

        page = await context.new_page()

        # Response interceptor
        response_headers = {}
        final_url = target_url
        load_performance = {}

        async def handle_response(response):
            nonlocal response_headers, final_url
            resp_url = response.url.rstrip("/")
            target_normalized = target_url.rstrip("/")
            if resp_url == target_normalized or not response_headers:
                response_headers = dict(response.headers)
            final_url = response.url

        page.on("response", handle_response)

        # Sayfa yükleme + performans ölçümü
        try:
            load_performance = await measure_page_load(page, target_url)
        except Exception as e:
            result["errors"].append(f"Sayfa yüklenirken hata: {str(e)}")
            try:
                await page.goto(target_url, wait_until="domcontentloaded", timeout=15000)
                await page.wait_for_timeout(2000)
            except Exception as e2:
                result["errors"].append(f"Sayfa yüklenemedi: {str(e2)}")
                await browser.close()
                return result

        # --- 1. Cookie'leri Topla ---
        try:
            cookies = await context.cookies()
            for cookie in cookies:
                cookie_info = {
                    "name": cookie["name"],
                    "value": cookie["value"][:50] + ("..." if len(cookie["value"]) > 50 else ""),
                    "domain": cookie.get("domain", ""),
                    "path": cookie.get("path", "/"),
                    "secure": cookie.get("secure", False),
                    "httpOnly": cookie.get("httpOnly", False),
                    "sameSite": cookie.get("sameSite", "none"),
                    "expires": cookie.get("expires", 0),
                    "category": categorize_cookie(cookie["name"]),
                    "third_party": is_third_party_cookie(domain, cookie.get("domain", "")),
                }
                result["cookies"].append(cookie_info)
        except Exception as e:
            result["errors"].append(f"Cookie toplanırken hata: {str(e)}")

        # Cookie summary
        cookie_categories = {}
        for c in result["cookies"]:
            cat = c["category"]
            if cat not in cookie_categories:
                cookie_categories[cat] = {"count": 0, "third_party_count": 0}
            cookie_categories[cat]["count"] += 1
            if c["third_party"]:
                cookie_categories[cat]["third_party_count"] += 1
        cookie_categories["total"] = len(result["cookies"])
        result["cookie_summary"] = cookie_categories

        # --- 2. HTTP Header'ları Analiz Et ---
        result["security_headers"] = analyze_security_headers(response_headers, compliance)

        # --- 3. Sayfa Bilgileri + Performans ---
        try:
            title = await page.title()
            html_content = await page.content()
            result["page_info"] = {
                "title": title,
                "url": page.url,
                "content_length": len(html_content),
                "status_code": response_headers.get(":status", response_headers.get("status", "200")),
                "load_performance": load_performance,
            }
        except Exception as e:
            result["errors"].append(f"Sayfa bilgisi alınırken hata: {str(e)}")
            html_content = ""

        # --- 4. Privacy Policy ---
        try:
            soup = BeautifulSoup(html_content, "html.parser")
            pp_url = find_privacy_policy_url(soup, page.url)
            if pp_url:
                result["privacy_policy"] = {
                    "url": pp_url,
                    "found": True,
                    "raw_text_preview": extract_privacy_policy_text(pp_url),
                }
            else:
                result["privacy_policy"] = {
                    "url": None,
                    "found": False,
                    "raw_text_preview": None,
                    "note": "Privacy policy sayfası bulunamadı",
                }
        except Exception as e:
            result["errors"].append(f"Privacy policy aranırken hata: {str(e)}")
            result["privacy_policy"] = {"url": None, "found": False, "error": str(e)}

        # --- 5. Form'ları Tara (GDPR) ---
        if compliance in ["gdpr", "all"]:
            try:
                if not html_content:
                    html_content = await page.content()
                soup = BeautifulSoup(html_content, "html.parser")
                result["forms"] = analyze_forms(soup)
            except Exception as e:
                result["errors"].append(f"Form taranırken hata: {str(e)}")

        # --- 6. SOC2 Security Audit ---
        if compliance in ["soc2", "all"]:
            try:
                result["security_audit"] = {
                    "ssl_tls": check_ssl_tls(target_url),
                    "encryption_headers": check_encryption_headers(response_headers),
                    "access_control": check_access_control(response_headers),
                }
            except Exception as e:
                result["security_audit"] = {"error": str(e)}
                result["errors"].append(f"SOC2 audit hatası: {str(e)}")

        # --- 7. CCPA Checks ---
        if compliance in ["ccpa", "all"]:
            try:
                if not html_content:
                    html_content = await page.content()
                soup = BeautifulSoup(html_content, "html.parser")
                result["ccpa_checks"] = check_ccpa_compliance(soup, page.url)
            except Exception as e:
                result["ccpa_checks"] = {"error": str(e)}
                result["errors"].append(f"CCPA check hatası: {str(e)}")

        # --- GDPR Notları ---
        gdpr_notes = []
        if compliance in ["gdpr", "all"]:
            if not result["privacy_policy"]["found"]:
                gdpr_notes.append("⚠️ GDPR Madde 13-14: Privacy policy sayfası bulunamadı")
            else:
                gdpr_notes.append("✅ Privacy policy sayfası mevcut")

            if result["cookies"]:
                essential = cookie_categories.get("essential", {}).get("count", 0)
                analytics = cookie_categories.get("analytics", {}).get("count", 0)
                marketing = cookie_categories.get("marketing", {}).get("count", 0)
                third_party_count = sum(cat["third_party_count"] for cat in cookie_categories.values())

                if marketing > 0:
                    gdpr_notes.append(f"⚠️ {marketing} marketing cookie tespit edildi - GDPR Madde 7 onayı gerekli")
                if analytics > 0:
                    gdpr_notes.append(f"ℹ️ {analytics} analytics cookie tespit edildi")
                if third_party_count > 0:
                    gdpr_notes.append(f"⚠️ {third_party_count} adet 3rd-party cookie tespit edildi")
                gdpr_notes.append(f"ℹ️ Toplam {len(result['cookies'])} cookie ({essential} essential)")

            missing_headers = [h for h, v in result["security_headers"].items() if v["status"] == "missing"]
            if missing_headers:
                gdpr_notes.append(f"⚠️ Eksik güvenlik header'ları: {', '.join(missing_headers[:5])}")

            if result["forms"]:
                forms_with_consent = sum(1 for f in result["forms"] if f["has_consent_checkbox"])
                if forms_with_consent == 0:
                    gdpr_notes.append("⚠️ Hiçbir formda açık rıza checkbox'ı bulunamadı")
                else:
                    gdpr_notes.append(f"✅ {forms_with_consent}/{len(result['forms'])} formda onay checkbox'ı mevcut")

        # SOC2 notları
        if compliance in ["soc2", "all"] and "ssl_tls" in result.get("security_audit", {}):
            sa = result["security_audit"]
            if sa.get("ssl_tls", {}).get("certificate_valid"):
                gdpr_notes.append(f"✅ SSL sertifikası geçerli (TLS: {sa['ssl_tls'].get('protocol_version', 'N/A')})")
            else:
                gdpr_notes.append("⚠️ SSL sertifikası kontrol edilemedi")

        # CCPA notları
        if compliance in ["ccpa", "all"] and "ccpa_notes" in result.get("ccpa_checks", {}):
            gdpr_notes.extend(result["ccpa_checks"]["ccpa_notes"])

        result["gdpr_notes"] = gdpr_notes

        await browser.close()

    return result


def save_output(data: dict) -> str:
    """JSON çıktıyı dosyaya kaydet."""
    domain = data["scan_metadata"]["domain"]
    compliance = data["scan_metadata"]["compliance"]
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"crawl_{domain}_{compliance}_{timestamp}.json"
    output_dir = "/home/team/shared/crawler_output"
    os.makedirs(output_dir, exist_ok=True)
    filepath = os.path.join(output_dir, filename)

    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    return filepath


# --- CLI Entry Point ---
async def main():
    if len(sys.argv) < 2:
        print("Kullanım: python crawler.py <URL>")
        print("         python crawler.py --json '{\"url\": \"https://...\", \"compliance\": \"all\"}'")
        sys.exit(1)

    url = sys.argv[1]
    compliance = "all"
    if url == "--json" and len(sys.argv) > 2:
        try:
            input_data = json.loads(sys.argv[2])
            url = input_data.get("url", "")
            compliance = input_data.get("compliance", "all")
        except Exception as e:
            print(f"JSON parse hatası: {e}")
            sys.exit(1)

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    print(f"🔍 Taranıyor: {url} (compliance: {compliance})")
    result = await crawl_url(url, compliance)
    filepath = save_output(result)
    print(f"✅ Çıktı kaydedildi: {filepath}")
    print(f"📊 Toplam cookie: {result.get('cookie_summary', {}).get('total', 0)}")
    print(f"🔒 Privacy policy: {'✅ Bulundu' if result['privacy_policy']['found'] else '❌ Bulunamadı'}")
    print(f"📝 Form sayısı: {len(result.get('forms', []))}")
    print(f"🔐 SSL/TLS: {'✅ Geçerli' if result.get('security_audit', {}).get('ssl_tls', {}).get('certificate_valid') else '❌'}")
    print(f"🏛️  CCPA: {'✅' if result.get('ccpa_checks', {}).get('do_not_sell_link_found') else '❌'} Do Not Sell Link")
    print(f"⚡ Yüklenme: {result.get('page_info', {}).get('load_performance', {}).get('status', 'N/A')}")

if __name__ == "__main__":
    asyncio.run(main())
