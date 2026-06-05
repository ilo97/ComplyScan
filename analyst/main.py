from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel
from typing import List, Dict, Any, Optional, Union
import os

# Import modules from the same directory
try:
    from privacy_analyzer import PrivacyAnalyzer
    from scoring_engine import ScoringEngine
except ImportError:
    from .privacy_analyzer import PrivacyAnalyzer
    from .scoring_engine import ScoringEngine

app = FastAPI(title="ComplyScan AI Analyst API")

class ScanRequest(BaseModel):
    policy_text: str
    cookies: List[Dict[str, Any]]
    form_data: Dict[str, Any] = {}
    headers: Dict[str, Any] = {}
    compliance_type: str = "gdpr" # "gdpr", "soc2", "ccpa", "all"

class ScanResponse(BaseModel):
    privacy_analysis: Union[Dict[str, Any], Dict[str, Dict[str, Any]]]
    cookie_categorization: Dict[str, List[Dict[str, Any]]]
    overall_score: int
    detailed_scores: Optional[Dict[str, int]] = None

class CrawlerScanRequest(BaseModel):
    # This matches the structure seen in crawler_output JSON
    scan_metadata: Dict[str, Any]
    cookies: List[Dict[str, Any]]
    security_headers: Dict[str, Any]
    privacy_policy: Dict[str, Any]
    forms: List[Dict[str, Any]] = []
    compliance_type: str = "gdpr"

@app.get("/")
async def root():
    return {"message": "ComplyScan AI Analyst API is running"}

def perform_analysis(
    policy_text: str, 
    cookies: List[Dict[str, Any]], 
    headers: Dict[str, Any], 
    forms: List[Dict[str, Any]], 
    compliance_type: str
) -> ScanResponse:
    api_key = os.getenv("ANTHROPIC_API_KEY")
    analyzer = PrivacyAnalyzer(api_key=api_key)
    
    types_to_run = ["gdpr", "soc2", "ccpa"] if compliance_type == "all" else [compliance_type]
    
    all_analyses = {}
    all_scores = {}
    
    # Common components (Shared across compliance types for now)
    cookie_cats = ScoringEngine.categorize_cookies(cookies)
    unknown_count = len(cookie_cats.get("unknown", []))
    cookie_score = max(50, 100 - (unknown_count * 10))
    
    # Header scoring
    # If headers is a dict of crawler-style objects (with 'present' key)
    if headers and isinstance(list(headers.values())[0], dict) and "present" in list(headers.values())[0]:
        total_h = len(headers)
        present_h = sum(1 for h in headers.values() if h.get("present", False))
        header_score = int((present_h / total_h) * 100) if total_h > 0 else 100
    else:
        # Standard dict
        security_headers = ["content-security-policy", "strict-transport-security", "x-frame-options"]
        present_headers = [h for h in security_headers if h in {k.lower() for k in headers.keys()}]
        header_score = int((len(present_headers) / len(security_headers)) * 100) if security_headers else 100
        
    # Form scoring
    if isinstance(forms, list):
        form_score = 100 if len(forms) > 0 else 50
    else:
        # Backward compatibility for old form_data dict
        has_consent = forms.get("has_consent_checkbox", False)
        form_score = 100 if has_consent else 50

    for ctype in types_to_run:
        analysis = analyzer.analyze(policy_text, compliance_type=ctype)
        policy_score = analysis.get("overall_policy_score", 0) if "error" not in analysis else 0
        
        comp_score = ScoringEngine.calculate_compliance_score(
            cookie_score=cookie_score,
            policy_score=policy_score,
            form_score=form_score,
            header_score=header_score,
            compliance_type=ctype
        )
        
        all_analyses[ctype] = analysis
        all_scores[ctype] = comp_score
        
    final_score = ScoringEngine.calculate_final_aggregated_score(all_scores)
    
    return ScanResponse(
        privacy_analysis=all_analyses if compliance_type == "all" else all_analyses[compliance_type],
        cookie_categorization=cookie_cats,
        overall_score=final_score,
        detailed_scores=all_scores if compliance_type == "all" else None
    )

@app.post("/analyze", response_model=ScanResponse)
async def analyze_compliance(request: ScanRequest):
    return perform_analysis(
        policy_text=request.policy_text,
        cookies=request.cookies,
        headers=request.headers,
        forms=[request.form_data] if request.form_data else [],
        compliance_type=request.compliance_type
    )

@app.post("/analyze-crawler", response_model=ScanResponse)
async def analyze_crawler_output(request: CrawlerScanRequest):
    policy_text = request.privacy_policy.get("raw_text_preview") or ""
    if not policy_text and not request.privacy_policy.get("found", False):
        policy_text = "No privacy policy found on the website."
    
    return perform_analysis(
        policy_text=policy_text,
        cookies=request.cookies,
        headers=request.security_headers,
        forms=request.forms,
        compliance_type=request.compliance_type
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
