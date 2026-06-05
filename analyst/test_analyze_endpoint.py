import requests
import json

def test_analyze():
    url = "http://localhost:8001/analyze"
    data = {
        "policy_text": "We collect your email for marketing purposes. You have the right to access your data.",
        "cookies": [
            {"name": "_ga", "domain": ".example.com"},
            {"name": "sessionid", "domain": "example.com"}
        ],
        "form_data": {
            "has_consent_checkbox": True
        },
        "headers": {
            "Content-Security-Policy": "default-src 'self'",
            "Strict-Transport-Security": "max-age=31536000"
        }
    }
    
    try:
        response = requests.post(url, json=data)
        print(f"Status Code: {response.status_code}")
        if response.status_code == 200:
            print("Response JSON:")
            print(json.dumps(response.json(), indent=2))
        else:
            print(f"Error: {response.text}")
    except Exception as e:
        print(f"Failed to connect: {e}")

if __name__ == "__main__":
    test_analyze()
