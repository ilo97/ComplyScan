"""
ComplyScan Crawler - FastAPI Server (v2.0 - Multi-Compliance)
===============================================================
Playwright tabanlı web crawler için REST API.
Desteklenen compliance tipleri: gdpr, soc2, ccpa, all

Çalıştırma:
    source /home/team/shared/crawler_venv/bin/activate
    PLAYWRIGHT_BROWSERS_PATH=/home/team/shared/playwright_browsers \
        uvicorn api:app --host 0.0.0.0 --port 8000

Endpoint'ler:
    POST /crawl
        Body: {"url": "https://example.com", "compliance": "all"}
        Response: JSON scan result

    GET /health
        Response: {"status": "ok", "version": "2.0"}
"""

import json
import os
import sys
import asyncio
import traceback
from datetime import datetime, timezone
from typing import Optional

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

# Crawler modülünü import et
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from crawler import crawl_url, save_output, COMPLIANCE_TYPES

app = FastAPI(
    title="ComplyScan Crawler API",
    description="Multi-Compliance Web Crawler - GDPR / SOC2 / CCPA - Cookie, Header, Privacy Policy, SSL, Form tarayıcı",
    version="2.0.0",
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class CrawlRequest(BaseModel):
    url: str
    compliance: str = Field(default="all", description="Compliance type: gdpr, soc2, ccpa, all")
    wait_time: Optional[int] = Field(default=2000, description="JS rendering için bekleme süresi (ms)")


class CrawlResponse(BaseModel):
    success: bool
    data: Optional[dict] = None
    filepath: Optional[str] = None
    error: Optional[str] = None


@app.get("/health")
async def health_check():
    return {
        "status": "ok",
        "version": "2.0.0",
        "compliance_types": COMPLIANCE_TYPES,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.post("/crawl", response_model=CrawlResponse)
async def crawl_endpoint(request: CrawlRequest):
    """
    Verilen URL'yi Playwright ile tara.
    
    compliance parametresi:
    - "gdpr" — GDPR odaklı tarama (cookie, header, privacy policy, form)
    - "soc2" — SOC2 odaklı tarama (SSL/TLS, encryption headers, access control)
    - "ccpa" — CCPA odaklı tarama (Do Not Sell linki, California privacy)
    - "all" — Tüm compliance kontrolleri (varsayılan)
    """
    url = request.url
    compliance = request.compliance.lower()

    # Validate compliance
    if compliance not in COMPLIANCE_TYPES:
        compliance = "all"

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        result = await crawl_url(url, compliance)
        filepath = save_output(result)
        return CrawlResponse(
            success=True,
            data=result,
            filepath=filepath,
        )
    except Exception as e:
        traceback.print_exc()
        return CrawlResponse(
            success=False,
            error=f"Crawl hatası: {str(e)}",
        )


@app.post("/crawl/batch")
async def crawl_batch(urls: list[str] = Query(..., description="Taranacak URL listesi"),
                       compliance: str = Query("all", description="Compliance type")):
    """
    Birden fazla URL'yi sırayla tara.
    """
    if compliance not in COMPLIANCE_TYPES:
        compliance = "all"

    results = []
    for url in urls:
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        try:
            result = await crawl_url(url, compliance)
            filepath = save_output(result)
            results.append({
                "url": url,
                "success": True,
                "filepath": filepath,
                "summary": {
                    "cookies": result.get("cookie_summary", {}).get("total", 0),
                    "privacy_policy": result["privacy_policy"].get("found", False),
                    "forms": len(result.get("forms", [])),
                    "ssl_valid": result.get("security_audit", {}).get("ssl_tls", {}).get("certificate_valid", False),
                    "ccpa_dns": result.get("ccpa_checks", {}).get("do_not_sell_link_found", False),
                }
            })
        except Exception as e:
            results.append({
                "url": url,
                "success": False,
                "error": str(e),
            })

    return {"results": results, "total": len(results), "successful": sum(1 for r in results if r["success"])}


@app.get("/")
async def root():
    return {
        "service": "ComplyScan Crawler API v2",
        "version": "2.0.0",
        "compliance_types": COMPLIANCE_TYPES,
        "endpoints": {
            "POST /crawl": "URL taraması yap (GDPR/SOC2/CCPA)",
            "POST /crawl/batch": "Toplu URL taraması",
            "GET /health": "Sağlık kontrolü",
        }
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)