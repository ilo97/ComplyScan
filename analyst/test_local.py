from scoring_engine import ScoringEngine

cookies = [
    {"name": "_ga", "domain": ".example.com"},
    {"name": "sessionid", "domain": "example.com"},
    {"name": "fbp", "domain": "facebook.com"},
    {"name": "lang", "domain": "example.com"},
    {"name": "random_cookie", "domain": "example.com"}
]

cats = ScoringEngine.categorize_cookies(cookies)

print("Essential:", [c['name'] for c in cats['essential']])
print("Analytics:", [c['name'] for c in cats['analytics']])
print("Marketing:", [c['name'] for c in cats['marketing']])
print("Functional:", [c['name'] for c in cats['functional']])
print("Unknown:", [c['name'] for c in cats['unknown']])

score = ScoringEngine.calculate_overall_score(
    cookie_score=80,
    policy_score=90,
    form_score=100,
    header_score=70
)
print("Overall Score:", score)
