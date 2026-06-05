import os
import json
from typing import List, Dict, Any, Optional
from anthropic import Anthropic
from pydantic import BaseModel

class GDPRFinding(BaseModel):
    article: str
    status: str  # "compliant", "partially_compliant", "missing", "not_applicable"
    finding: str
    recommendation: str

class AnalysisResult(BaseModel):
    findings: List[Dict[str, Any]]
    overall_policy_score: int
    summary: str

COMPLIANCE_PROMPTS = {
    "gdpr": {
        "description": "Analyze for GDPR compliance.",
        "articles": [
            "Art. 5: Principles relating to processing of personal data",
            "Art. 7: Conditions for consent",
            "Art. 12-14: Transparency and information",
            "Art. 15-22: Rights of the data subject",
            "Art. 27: Representatives of controllers or processors not established in the Union",
            "Art. 28: Processor",
            "Art. 33-34: Communication of a personal data breach",
            "Art. 37: Designation of the data protection officer"
        ],
        "keys": ["article", "status", "finding", "recommendation"]
    },
    "soc2": {
        "description": "Analyze for SOC2 Type II compliance (Security, Availability, Processing Integrity, Confidentiality, Privacy).",
        "articles": [
            "Security: Protection against unauthorized access",
            "Availability: System accessibility for operation and use",
            "Processing Integrity: System processing is complete, valid, accurate, timely, and authorized",
            "Confidentiality: Data designated as confidential is protected",
            "Privacy: Personal information is collected, used, retained, disclosed, and disposed of properly",
            "Access Control: Logical and physical access controls",
            "Encryption: Data at rest and in transit",
            "Disaster Recovery: Business continuity and backup procedures"
        ],
        "keys": ["control", "status", "finding", "recommendation"]
    },
    "ccpa": {
        "description": "Analyze for CCPA (California Consumer Privacy Act) compliance.",
        "articles": [
            "Right to Know: Informing consumers about collection and use of personal information",
            "Right to Delete: Consumers can request deletion of personal information",
            "Right to Opt-Out: Ability to stop the sale of personal information",
            "Do Not Sell My Personal Information: Specific link/notice requirement",
            "Right to Non-Discrimination: No discrimination for exercising CCPA rights",
            "Verification Process: Process for verifying consumer requests",
            "Financial Incentives: Notice of financial incentive programs",
            "Service Provider Agreements: Contractual requirements for third-party processors"
        ],
        "keys": ["requirement", "status", "finding", "recommendation"]
    }
}

class PrivacyAnalyzer:
    def __init__(self, api_key: str = None):
        self.api_key = api_key or os.getenv("ANTHROPIC_API_KEY")
        self.client = Anthropic(api_key=self.api_key) if self.api_key else None

    def get_mock_data(self, compliance_type: str) -> Dict[str, Any]:
        if compliance_type == "gdpr":
            return {
                "findings": [
                    {"article": "Art. 5", "status": "compliant", "finding": "Basic principles are addressed.", "recommendation": "None."},
                    {"article": "Art. 15-22", "status": "partially_compliant", "finding": "Some rights mentioned.", "recommendation": "List all rights."}
                ],
                "overall_policy_score": 75,
                "summary": "Mock GDPR analysis completed."
            }
        elif compliance_type == "soc2":
            return {
                "findings": [
                    {"control": "Security", "status": "compliant", "finding": "Access controls are defined.", "recommendation": "None."},
                    {"control": "Encryption", "status": "missing", "finding": "No mention of encryption standards.", "recommendation": "Specify AES-256 for data at rest."}
                ],
                "overall_policy_score": 60,
                "summary": "Mock SOC2 analysis completed."
            }
        elif compliance_type == "ccpa":
            return {
                "findings": [
                    {"requirement": "Right to Know", "status": "compliant", "finding": "Information collection is disclosed.", "recommendation": "None."},
                    {"requirement": "Do Not Sell", "status": "missing", "finding": "No Do Not Sell link found.", "recommendation": "Add a Do Not Sell My Personal Information link."}
                ],
                "overall_policy_score": 50,
                "summary": "Mock CCPA analysis completed."
            }
        return {"error": f"Unknown compliance type: {compliance_type}"}

    def analyze(self, policy_text: str, compliance_type: str = "gdpr") -> Dict[str, Any]:
        if compliance_type not in COMPLIANCE_PROMPTS:
            return {"error": f"Unsupported compliance type: {compliance_type}"}
        
        if not self.client:
            return self.get_mock_data(compliance_type)

        config = COMPLIANCE_PROMPTS[compliance_type]
        articles_list = "\n".join([f"- {a}" for a in config["articles"]])
        
        prompt = f"""
        {config['description']}
        Focus on the following points:
        {articles_list}

        For each point, provide:
        1. Status: compliant, partially_compliant, missing, or not_applicable.
        2. Finding: A brief description of what was found or what is missing.
        3. Recommendation: How to improve compliance.

        Provide the output in structured JSON format with the following keys:
        - findings: A list of objects with keys {config['keys']}.
        - overall_policy_score: An integer from 0 to 100 based on the coverage of these points.
        - summary: A brief executive summary.

        Privacy Policy Text:
        {policy_text}
        """

        try:
            response = self.client.messages.create(
                model="claude-3-haiku-20240307",
                max_tokens=4000,
                messages=[
                    {"role": "user", "content": prompt}
                ]
            )
            
            content = response.content[0].text
            start = content.find('{')
            end = content.rfind('}') + 1
            if start != -1 and end != -1:
                json_str = content[start:end]
                return json.loads(json_str)
            else:
                return {"error": "Could not find JSON in response", "raw_content": content}
        except Exception as e:
            return {"error": f"API call failed: {str(e)}"}
