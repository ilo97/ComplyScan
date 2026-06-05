from typing import Dict, Any, List

class ScoringEngine:
    @staticmethod
    def calculate_compliance_score(
        cookie_score: int,      # 0-100
        policy_score: int,      # 0-100
        form_score: int,        # 0-100
        header_score: int,      # 0-100
        compliance_type: str = "gdpr"
    ) -> int:
        """
        Weights can vary by compliance type.
        Default (GDPR):
        Cookie Compliance: 30%
        Privacy Policy Coverage: 40%
        Form/Consent Mechanism: 20%
        HTTP Header Security: 10%
        """
        weights = {
            "gdpr": {"cookie": 0.30, "policy": 0.40, "form": 0.20, "header": 0.10},
            "soc2": {"cookie": 0.10, "policy": 0.40, "form": 0.10, "header": 0.40},
            "ccpa": {"cookie": 0.30, "policy": 0.40, "form": 0.20, "header": 0.10}
        }
        
        w = weights.get(compliance_type, weights["gdpr"])
        
        total_score = (
            (cookie_score * w["cookie"]) +
            (policy_score * w["policy"]) +
            (form_score * w["form"]) +
            (header_score * w["header"])
        )
        return int(round(total_score))

    @staticmethod
    def calculate_final_aggregated_score(scores: Dict[str, int]) -> int:
        """
        Calculates a weighted average of all compliance types.
        If a type is missing, it's not included in the average.
        """
        if not scores:
            return 0
            
        # Example weights for aggregate score
        agg_weights = {
            "gdpr": 0.4,
            "soc2": 0.3,
            "ccpa": 0.3
        }
        
        weighted_sum = 0
        total_weight = 0
        
        for ctype, score in scores.items():
            weight = agg_weights.get(ctype, 0.3)
            weighted_sum += score * weight
            total_weight += weight
            
        if total_weight == 0:
            return 0
            
        return int(round(weighted_sum / total_weight))

    @staticmethod
    def categorize_cookies(cookies: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """
        Categorizes cookies into: essential, analytics, marketing, functional.
        This is a heuristic-based categorizer.
        """
        categories = {
            "essential": [],
            "analytics": [],
            "marketing": [],
            "functional": [],
            "unknown": []
        }
        
        # Keywords for categorization
        keywords = {
            "essential": ["csrf", "xsrf", "consent", "cookie_policy", "sessionid", "token", "PHPSESSID"],
            "analytics": ["ga", "gid", "gat", "utma", "utmb", "utmc", "utmz", "_hj", "amplitude", "mixpanel", "hotjar", "pixel"],
            "marketing": ["ads", "track", "facebook", "fbp", "fbc", "doubleclick", "adform", "linkedin", "tr", "id", "_gcl"],
            "functional": ["lang", "pref", "settings", "theme", "session", "login", "auth"]
        }
        
        for cookie in cookies:
            name = cookie.get("name", "").lower()
            domain = cookie.get("domain", "").lower()
            categorized = False
            
            # Check keywords in name
            for cat, kws in keywords.items():
                if any(kw in name for kw in kws):
                    categories[cat].append(cookie)
                    categorized = True
                    break
            
            # Additional check for domain if not categorized
            if not categorized:
                if "google-analytics" in domain or "googletagmanager" in domain:
                    categories["analytics"].append(cookie)
                    categorized = True
                elif "doubleclick" in domain or "facebook" in domain:
                    categories["marketing"].append(cookie)
                    categorized = True
            
            if not categorized:
                categories["unknown"].append(cookie)
                
        return categories
