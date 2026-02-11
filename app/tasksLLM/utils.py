import os
import json
import re
from datetime import datetime
from flask import current_app
from google.oauth2 import id_token
from google.oauth2.credentials import Credentials
import google.generativeai as genai
from google.auth.transport import requests as google_requests
from typing import Dict, Any, List


def load_scan_results_helper(scan_id: str) -> Dict[str, Any]:
    """
    Helper function to load scan results from the data directory.
    Assumes Flask app context is available for current_app.config.
    """
    data_dir = current_app.config['DATA_DIR']
    results_path = os.path.join(data_dir, 'scanned_results', f'{scan_id}.json')
    
    if not os.path.exists(results_path):
        raise FileNotFoundError(f"Scan results not found for ID: {scan_id}")
    
    with open(results_path, 'r', encoding='utf-8') as f:
        return json.load(f)

def generate_br_advice_with_gemini(scan_results: Dict[str, Any], user_token: str, model_name: str) -> Dict[str, Any]:
    """
    Helper function for Gemini enrichment (BRadvice).
    """
    prompt = f"""
    SECURITY SCAN DATA:
    {json.dumps(scan_results, indent=2)}

      
    You are a senior Principal Security Architect with hands-on experience in
application security, API security, and compliance-driven remediation
(OWASP Top 10, HIPAA, GDPR, SOC 2).

You are given the COMPLETE security scan output in JSON format.
This includes:
- Identified vulnerabilities
- Endpoint security analysis
- Risk severities and CVSS scores
- Authentication and authorization gaps
- Sensitive data exposure indicators
- Compliance impact analysis
- Metrics and severity distributions

Your task is to analyze the entire dataset holistically and produce a
FINAL ACTIONABLE SECURITY ROADMAP for the end user.

────────────────────────────
IMPORTANT OUTPUT RULES
────────────────────────────

1. Respond with ONLY valid JSON.
2. Do NOT include explanations outside JSON.
3. Do NOT repeat scan findings verbatim.
4. Be concise, practical, and execution-oriented.
5. Focus on WHAT TO DO NEXT, not what was already found.
6. Recommendations must be ordered by PRIORITY.
7. Each recommendation must be realistic and technically actionable.

────────────────────────────
WHAT YOUR RECOMMENDATION MUST COVER
────────────────────────────

Your recommendations must address, where applicable:

- Immediate risk reduction steps (high/critical issues)
- Authentication and authorization hardening
- API and endpoint exposure minimization
- Secure input validation and output handling
- Sensitive data protection improvements
- Logging, monitoring, and alerting gaps
- Compliance alignment (HIPAA, GDPR, etc.)
- Secure development lifecycle improvements
- Tooling or automation improvements if relevant

────────────────────────────
RESPONSE STRUCTURE (STRICT)
────────────────────────────

Return the response using EXACTLY the following JSON schema:

{{
  "BRadvice": {{
    "recommendation": [
      {{
        "priority": "Immediate | Short-Term | Mid-Term | Long-Term",
        "title": "Concise action title",
        "description": "Clear and direct explanation of the issue being addressed",
        "why_it_matters": "Security or compliance impact if not addressed",
        "recommended_actions": [
          "Concrete technical step 1",
          "Concrete technical step 2",
          "Concrete technical step 3"
        ],
        "expected_outcome": "Measurable or observable security improvement"
      }}
    ]
  }}
}}

────────────────────────────
QUALITY BAR
────────────────────────────

- Assume the reader is technical but needs clarity.
- Speak in vocabulary that is precise and directive, not vague or theoretical like that of Alex Hormozi.
- Avoid vague language like “consider” or “may improve”.
- Prefer directive language: “Enforce”, “Restrict”, “Implement”.
- Keep each recommendation short but meaningful.
- If no critical issues exist, focus on hardening and maturity improvements.

Analyze the provided JSON now and produce the final recommendations in the provide 'RESPONSE STRUCTURE'.

    """
    
    if not user_token:
        print("[generate_br_advice_with_gemini] No user token provided.")
        return {"error": "No user token provided for Gemini enrichment."}

    api_key_env = os.environ.pop('GOOGLE_API_KEY', None)
    gemini_key_env = os.environ.pop('GEMINI_API_KEY', None)

    try:
        user_credentials = Credentials(token=user_token)
        genai.configure(credentials=user_credentials)
        
        model = genai.GenerativeModel("gemini-2.5-flash-lite" if not model_name else model_name)
        response = model.generate_content(prompt)
        
        response_text = getattr(response, 'text', str(response))
        
        # More robust JSON extraction
        match = re.search(r'\{.*\}', response_text, re.DOTALL)
        if not match:
            print(f"[generate_br_advice_with_gemini] No JSON object found in Gemini response. Raw: {response_text[:500]}")
            raise json.JSONDecodeError("No JSON object found in response.", response_text, 0)
            
        json_string = match.group(0)
        return json.loads(json_string)

    except Exception as e:
        print(f"[generate_br_advice_with_gemini] Gemini generation with user token failed: {e}")
        # The raw response might be useful for debugging, so we can log part of it
        # Assuming `response` is available in this scope, otherwise pass it
        raw_response_snippet = ""
        if 'response' in locals():
            raw_response_snippet = getattr(response, 'text', '')[:500]
        return {"error": f"Gemini enrichment failed: {str(e)}", "raw_response_snippet": raw_response_snippet}
    finally:
        if api_key_env:
            os.environ['GOOGLE_API_KEY'] = api_key_env
        if gemini_key_env:
            os.environ['GEMINI_API_KEY'] = gemini_key_env