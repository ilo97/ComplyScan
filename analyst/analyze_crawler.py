import json
import requests
import os
import sys

def analyze_crawler_json(file_path, api_url="http://localhost:8001/analyze-crawler"):
    if not os.path.exists(file_path):
        print(f"Error: File {file_path} not found.")
        return None
    
    with open(file_path, 'r') as f:
        data = json.load(f)
    
    try:
        response = requests.post(api_url, json=data)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.ConnectionError:
        print("Error: API server not running. Start main.py first.")
        return None
    except Exception as e:
        print(f"Error during analysis: {e}")
        if 'response' in locals():
            print(f"Response: {response.text}")
        return None

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python analyze_crawler.py <path_to_crawler_json>")
        sys.exit(1)
    
    json_path = sys.argv[1]
    result = analyze_crawler_json(json_path)
    
    if result:
        print(json.dumps(result, indent=2))
