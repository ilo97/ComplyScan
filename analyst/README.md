# ComplyScan AI Analyst

GDPR compliance analysis and scoring engine.

## Components

1. **Privacy Analyzer** (`privacy_analyzer.py`): Uses Claude AI to analyze privacy policy text for GDPR compliance (Articles 5, 7, 12-14, 15-22, 27, 28, 33-34, 37).
2. **Scoring Engine** (`scoring_engine.py`): 
    - Weights: Cookie (30%), Policy (40%), Forms (20%), Headers (10%).
    - Cookie Categorization: Heuristic-based categorization (essential, analytics, marketing, functional).
3. **API** (`main.py`): FastAPI interface for running analyses.
4. **Crawler Adapter** (`analyze_crawler.py`): Script to send crawler-generated JSON to the analysis API.

## Setup

1. Create a virtual environment:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```

2. Set your Anthropic API Key:
   ```bash
   export ANTHROPIC_API_KEY='your-key-here'
   ```

3. Run the API:
   ```bash
   uvicorn main:app --host 0.0.0.0 --port 8001
   ```

## API Usage

### POST `/analyze`
Standard analysis for custom data.

### POST `/analyze-crawler`
Specific endpoint for Crawler-generated JSON structure.

## Command Line Usage

Analyze a crawler JSON file:
```bash
python analyze_crawler.py /path/to/crawler_output.json
```
