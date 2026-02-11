import ast
from asyncio.log import logger
import os
import json
from typing import Dict, List, Optional, Any
from dotenv import load_dotenv
# from flask import session
import google.generativeai as genai
from google.oauth2.credentials import Credentials
from openai import OpenAI
load_dotenv()  # Load environment variables from .env file
    
# =========================================================
# 1. Utilities
# =========================================================

HTTP_METHODS = {"GET", "POST", "PUT", "DELETE", "PATCH"}

AUTH_PATTERNS = [
    "login_required",
    "jwt",
    "JWT",
    "Depends",
    "Authorization",
    "request.headers",
    "current_user",
    "oauth"
]


def find_python_files(repo_path: str) -> List[str]:
    py_files = []
    for root, _, files in os.walk(repo_path):
        for f in files:
            if f.endswith(".py"):
                py_files.append(os.path.join(root, f))
    return py_files


def get_constant(node: ast.AST) -> Optional[str]:
    if isinstance(node, ast.Constant):
        return str(node.value)
    return None


# =========================================================
# 2. Flask Route Extraction
# =========================================================

def extract_flask_routes(tree: ast.AST, file_path: str) -> List[Dict]:
    routes = []

    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            for decorator in node.decorator_list:
                if isinstance(decorator, ast.Call):
                    func = decorator.func
                    if isinstance(func, ast.Attribute):
                        attr_name = func.attr.lower() # e.g. 'route', 'get', 'post'
                        
                        # CASE 1: Standard @app.route(...)
                        if attr_name == "route":
                            path = get_constant(decorator.args[0]) if decorator.args else "/"
                            methods = ["GET"] # Default for Flask

                            for kw in decorator.keywords:
                                if kw.arg == "methods":
                                    methods = [
                                        m.value.upper()
                                        for m in kw.value.elts
                                        if isinstance(m, ast.Constant) or isinstance(m, ast.Str)
                                    ]
                            
                            routes.append({
                                "path": path,
                                "methods": methods,
                                "view": node.name,
                                "source": file_path,
                                "line_number": node.lineno  # ### NEW: Capture view definition line
                            })

                        # CASE 2: Shorthand @app.get, @app.post, etc.
                        elif attr_name.upper() in HTTP_METHODS:
                            path = get_constant(decorator.args[0]) if decorator.args else "/"
                            routes.append({
                                "path": path,
                                "methods": [attr_name.upper()],
                                "view": node.name,
                                "source": file_path,
                                "line_number": node.lineno  # ### NEW: Capture view definition line
                            })
    return routes

# =========================================================
# 3. FastAPI Route Extraction
# =========================================================

def extract_fastapi_routes(tree: ast.AST, file_path: str) -> List[Dict]:
    routes = []

    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            for decorator in node.decorator_list:
                if isinstance(decorator, ast.Call):
                    func = decorator.func

                    # @app.get / @router.post etc
                    if isinstance(func, ast.Attribute):
                        method = func.attr.upper()
                        if method in HTTP_METHODS:
                            path = get_constant(decorator.args[0]) if decorator.args else "/"
                            routes.append({
                                "path": path,
                                "methods": [method],
                                "view": node.name,
                                "source": file_path,
                                "line_number": node.lineno  # ### NEW: Capture view definition line
                            })
    return routes


# =========================================================
# 4. View Analysis
# =========================================================

def analyze_handler(tree: ast.AST, handler_name: str) -> Dict[str, Any]:
    analysis = {
        "auth": {"required": False, "hints": [], "locations": []}, # ### NEW: Added locations
        "request": {"fields": []},
        "response": {"status_codes": []}
    }

    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == handler_name:

            # ---- Auth detection (Decorators) ----
            for deco in node.decorator_list:
                deco_str = ast.unparse(deco)
                for p in AUTH_PATTERNS:
                    if p.lower() in deco_str.lower():
                        analysis["auth"]["required"] = True
                        analysis["auth"]["hints"].append(p)
                        # ### NEW: Capture decorator line
                        analysis["auth"]["locations"].append({
                            "type": "decorator",
                            "pattern": p,
                            "line": deco.lineno
                        })

            # ---- Auth detection (Body) ----
            for n in ast.walk(node):
                try:
                    code = ast.unparse(n)
                    for p in AUTH_PATTERNS:
                        if p.lower() in code.lower():
                            analysis["auth"]["required"] = True
                            analysis["auth"]["hints"].append(p)
                            # ### NEW: Capture usage line
                            if hasattr(n, 'lineno'):
                                analysis["auth"]["locations"].append({
                                    "type": "code_usage",
                                    "pattern": p,
                                    "line": n.lineno
                                })
                except Exception:
                    pass

            # ---- Request body hints ----
            for n in ast.walk(node):
                if isinstance(n, ast.Attribute):
                    if n.attr in ("json", "form", "data"):
                        analysis["request"]["fields"].append("body")

                if isinstance(n, ast.Call):
                    name = ast.unparse(n.func)
                    if "Body" in name or "Request" in name:
                        analysis["request"]["fields"].append("body")

            # ---- Response hints ----
            for n in ast.walk(node):
                if isinstance(n, ast.Return):
                    try:
                        if isinstance(n.value, ast.Dict):
                            analysis["response"]["status_codes"].append(200)
                    except Exception:
                        pass

    return analysis


# =========================================================
# 5. Compact Context Builder
# =========================================================

def build_compact_context(extracted: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "framework": extracted.get("framework"),
        "endpoint_count": len(extracted.get("endpoints", [])),
        "endpoints": [
            {
                "path": ep["path"],
                "methods": ep["methods"],
                "view": ep["view"],
                "source": ep["source"],
                "line": ep.get("line_number"), # ### NEW: Include view line
                "auth_lines": [loc['line'] for loc in ep.get("auth", {}).get("locations", [])] # ### NEW: Include auth lines
            }
            for ep in extracted.get("endpoints", [])
        ]
    }


SECTOR_COMPLIANCE_MAP = {
    "Healthcare": ["HIPAA", "HITECH"],
    "Finance & Banking": ["GLBA", "SOX", "PCI DSS"],
    "Technology & SaaS": ["SOC 2", "ISO/IEC 27001", "CSA STAR"],
    "Retail & E-commerce": ["PCI DSS", "CCPA", "GDPR"],
    "Education": ["FERPA", "COPPA"],
    "Government & Defense": ["FISMA", "FedRAMP", "ITAR"],
    "Energy & Utilities": ["NERC CIP"],
    "Telecommunications": ["CALEA", "FCC Regulations"],
    "General Data Privacy": ["GDPR", "CCPA/CPRA", "LGPD", "PIPEDA"]
}


def build_llm_prompt(compact_json: Dict[str, Any], sector: str, framework: str = "django") -> str:
    compliances = SECTOR_COMPLIANCE_MAP.get(sector, [])

    prompt_template = f"""
You are a deterministic API security and compliance analysis engine.

You MUST return output in EXACTLY the JSON format described below.
You MUST NOT add extra keys.
You MUST NOT omit any required keys.
You MUST NOT explain anything.
You MUST NOT use markdown.

---------------------------------
OUTPUT JSON SCHEMA (STRICT)
---------------------------------

{{
  "metadata": {{
    "framework": "{framework}",
    "sector": "{sector}",
    "compliances": {json.dumps(compliances)}
  }},
  "endpoints": [
    {{
      "path": "string",
      "methods": ["GET","POST","PUT","DELETE","PATCH"],
      "source_info": {{
          "source_file": "string",
          "line_number": number
      }},
      "auth": {{
        "required": true | false,
        "type": "session | token | jwt | recommended | unknown",
        "detected_at_lines": [number]
      }},
      "request": {{
        "content_type": "application/json | form-data | unknown",
        "fields": [
          {{
            "name": "string",
            "type": "string | number | boolean | object | unknown",
            "sensitive": true | false
          }}
        ]
      }},
      "response": {{
        "content_type": "application/json | text | unknown",
        "status_codes": [200,201,400,401,403,500],
        "contains_sensitive_data": true | false
      }},
      "security_risks": [
        {{
          "id": "AUTH_MISSING | DATA_EXPOSURE | PRIV_ESCALATION | UNSAFE_METHOD",
          "severity": "low | medium | high",
          "description": "string",
          "Potential_attack_scenario": "string"
        }}
      ],
      "compliance_analysis": {{
        "<COMPLIANCE_NAME>": {{
          "applicable": true | false,
          "risk_level": "low | medium | high",
          "reason": "string"
        }}
      }},
        ""llm_notes": {{
       "severity": "critical",
      "severity_label": "Critical",
      "cvss": 10.0,
      "cvss_vector": "string",
      "references": [
        "string_url that user can visit for more info"
      ],
      }}
    }}
  ]
}}

---------------------------------
RULES
---------------------------------
- Only analyze compliances listed in metadata.compliances
- Mark sensitive=true if field may contain personal, financial, health, or identifying data
- If auth is missing on write/delete endpoints, add AUTH_MISSING risk
- If endpoint may expose personal data, mark GDPR/CCPA applicable
- Do not hallucinate fields that are not reasonably inferred
- If uncertain, use "unknown" type but still include the field
- Include line numbers in source_info and auth.detected_at_lines based on input data

---------------------------------
INPUT DATA
---------------------------------
"""
    return prompt_template + json.dumps(compact_json, indent=2)



# =========================================================
# 6. LLM Enrichment (same contract as Django)
# =========================================================

def enrich_with_llm(extracted: Dict[str, Any], framework: str, sector: str, user_token: Optional[str]) -> Dict[str, Any]:
    # Assuming django_info_service is available in the python path

    compact = build_compact_context(extracted)
    prompt = build_llm_prompt(compact, sector=sector, framework=framework)

    # if not user_token:
    #     try:
    #         user_token = session.get("google_access_token")
    #     except RuntimeError:
    #         user_token = None

    if not user_token:
        return {
            "error": "LLM enrichment skipped: No user token provided or available in session.",
            "raw_response": ""
        }

    raw_response = ""
    api_key_env = os.environ.pop('GOOGLE_API_KEY', None)
    gemini_key_env = os.environ.pop('GEMINI_API_KEY', None)


    try:
        user_credentials = Credentials(token=user_token)
        genai.configure(credentials=user_credentials)
        model = genai.GenerativeModel("gemini-2.5-flash-lite") # Corrected model name
        response = model.generate_content(prompt)
        raw_response = response.text.replace("```json", "").replace("```", "").strip()
        return json.loads(raw_response)
    except json.JSONDecodeError:
        return {
                    "error": "LLM returned invalid JSON",
                    "raw_response": raw_response
                }
    except Exception as e:
        logger.error({"error": f"Gemini API call failed: {str(e)}", "raw_response": raw_response})
        try:
            api_key1 = os.getenv("GROQ_API_KEY")
            if not api_key1:
                raise ValueError("GROQ_API_KEY not found in environment variables.")
            client = OpenAI(
                    api_key=api_key1,
                    base_url="https://api.groq.com/openai/v1"
                )
            response = client.chat.completions.create(
                messages=[
                            {
                                "role": "system",
                                "content": "You are a helpful assistant designed to output JSON.",
                            },
                            {
                                "role": "user",
                                "content": prompt,
                            }
                        ],
                        model="llama-3.3-70b-versatile",
                        response_format={"type": "json_object"},
                    )
            
            raw_response = response.choices[0].message.content
            return json.loads(raw_response)

        except Exception as fallback_e:
            logger.error(f" trying fallback ,1st iteration failed due to: {fallback_e}")
            try:
                api_key1 = os.getenv("OpenRouter_Key")
                if not api_key1:
                    raise ValueError("OpenRouter_Key not found in environment variables.")
                client = OpenAI(
                        api_key=api_key1,
                        base_url="https://openrouter.ai/api/v1"
                    )
                response = client.chat.completions.create(
                    messages=[
                                {
                                    "role": "system",
                                    "content": "You are a helpful assistant designed to output JSON.",
                                },
                                {
                                    "role": "user",
                                    "content": prompt,
                                }
                            ],
                            model="qwen/qwen3-coder:free",
                            response_format={"type": "json_object"},
                        )
                
                raw_response = response.choices[0].message.content
                return json.loads(raw_response)
                # Attempt 1: OpenRouter API Fallback
            except Exception as openrouter_e:
                logger.warning(f"OpenRouter API call failed: {openrouter_e}. Falling back to Gemini API.")
    finally:
        # Restore environment variables to avoid side effects
        if api_key_env:
            os.environ['GOOGLE_API_KEY'] = api_key_env
        if gemini_key_env:
            os.environ['GEMINI_API_KEY'] = gemini_key_env       
        

# =========================================================
# 7. Main Orchestrator
# =========================================================

def extract_flask_fastapi_endpoints(
    repo_path: str,
    sector: str = "General Data Privacy",
    user_token: Optional[str] = None
) -> Dict[str, Any]:

    output = {
        "framework": "flask/fastapi",
        "endpoints": [],
        "errors": []
    }

    try:
        for file_path in find_python_files(repo_path):
            try:
                tree = ast.parse(open(file_path, encoding="utf-8").read())
            except Exception:
                continue

            flask_routes = extract_flask_routes(tree, file_path)
            fastapi_routes = extract_fastapi_routes(tree, file_path)

            for ep in flask_routes + fastapi_routes:
                handler_analysis = analyze_handler(tree, ep["view"])
                ep.update(handler_analysis)
                output["endpoints"].append(ep)
        enriched = enrich_with_llm(output, "flask/fastapi", sector, user_token)
        output["llm_enriched"] = enriched

    except Exception as e:
        output["errors"].append(str(e))

    return output


# =========================================================
# 8. CLI Debug
# =========================================================
def store_enriched_output(repo_path: str, data: Dict[str, Any]) -> str:
    output_path = os.path.join(repo_path, "api_security_enriched.json")
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    return output_path

if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python flask_fastapi_info_service.py <repo_path> [access_token] [sector]")
        sys.exit(1)

    repo_arg = sys.argv[1]
    token_arg = sys.argv[2] if len(sys.argv) > 2 else None
    sector_arg = sys.argv[3] if len(sys.argv) > 3 else "General Data Privacy"

    print(f"Analyzing {repo_arg} for sector {sector_arg}...")
    if token_arg:
        print("Running with provided access token for LLM enrichment.")
    else:
        print("No access token provided. LLM enrichment will be skipped.")
    result = extract_flask_fastapi_endpoints(repo_arg, sector=sector_arg, user_token=token_arg)
    
    print(json.dumps(result, indent=2))
    output_file = store_enriched_output(repo_arg, result)
    print(f"Enriched output saved to: {output_file}")