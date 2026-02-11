import ast
import asyncio
import os
import json
from typing import Dict, List, Optional, Any
# from flask import session
import google.generativeai as genai
from google.oauth2.credentials import Credentials
from dotenv import load_dotenv
from openai import OpenAI
from asyncio.log import logger
# =========================================================
# 1. Utilities
# =========================================================
load_dotenv()  # Load environment variables from .env file
def find_files(repo_path: str, filename: str) -> List[str]:
    matches = []
    for root, _, files in os.walk(repo_path):
        if filename in files:
            matches.append(os.path.join(root, filename))
    return matches


def get_ast_string(node: ast.AST) -> str:
    if isinstance(node, ast.Constant):
        return str(node.value)
    if isinstance(node, ast.Str):
        return node.s
    return ""


def module_to_path(repo_path: str, module: str) -> Optional[str]:
    parts = module.split(".")
    candidate = os.path.join(repo_path, *parts) + ".py"
    if os.path.exists(candidate):
        return candidate
    return None


# =========================================================
# 2. Django Project Discovery
# =========================================================

def discover_settings_module(repo_path: str) -> Optional[str]:
    for manage_path in find_files(repo_path, "manage.py"):
        try:
            tree = ast.parse(open(manage_path, encoding="utf-8").read())
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and hasattr(node.func, "attr"):
                    if node.func.attr == "setdefault" and len(node.args) >= 2:
                        if get_ast_string(node.args[0]) == "DJANGO_SETTINGS_MODULE":
                            return get_ast_string(node.args[1])
        except Exception:
            continue
    return None


def extract_root_urlconf(settings_path: str) -> Optional[str]:
    try:
        tree = ast.parse(open(settings_path, encoding="utf-8").read())
        for node in tree.body:
            if isinstance(node, ast.Assign):
                for t in node.targets:
                    if isinstance(t, ast.Name) and t.id == "ROOT_URLCONF":
                        return get_ast_string(node.value)
    except Exception:
        pass
    return None


# =========================================================
# 3. URL Parsing (Recursive)
# =========================================================

def parse_urls_file(repo_path: str, urls_file: str, base: str = "") -> List[Dict]:
    endpoints = []
    try:
        tree = ast.parse(open(urls_file, encoding="utf-8").read())
    except Exception:
        return endpoints

    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and hasattr(node.func, "id"):
            if node.func.id in ("path", "re_path") and node.args:
                route = get_ast_string(node.args[0])
                full_path = (base + "/" + route).replace("//", "/")

                # Handle include()
                if len(node.args) > 1 and isinstance(node.args[1], ast.Call):
                    if getattr(node.args[1].func, "id", "") == "include":
                        mod = get_ast_string(node.args[1].args[0])
                        inc = module_to_path(repo_path, mod)
                        if inc:
                            endpoints.extend(parse_urls_file(repo_path, inc, full_path))
                        continue

                view_expr = ast.unparse(node.args[1]) if len(node.args) > 1 else "unknown"
                endpoints.append({
                    "path": full_path,
                    "view": view_expr,
                    "source": urls_file,
                    "line_number": node.lineno  # ### NEW: Capture line number of the path() call
                })

    return endpoints


# =========================================================
# 4. View Resolution
# =========================================================

def resolve_view_file(repo_path: str, view_expr: str) -> Optional[str]:
    parts = view_expr.split(".")
    if len(parts) < 2:
        return None
    return module_to_path(repo_path, ".".join(parts[:-1]))


# =========================================================
# 5. Dynamic Analysis Rules
# =========================================================

AUTH_PATTERNS = [
    "login_required",
    "permission_required",
    "IsAuthenticated",
    "JWT",
    "Token",
    "Authorization",
    "request.user",
    "is_authenticated"
]

HTTP_METHODS = {"GET", "POST", "PUT", "DELETE", "PATCH"}


# =========================================================
# 6. View Analysis
# =========================================================

def analyze_view(view_file: str, view_name: str) -> Dict[str, Any]:
    analysis = {
        "view_definition_line": None, # ### NEW
        "http_methods": [],
        "auth": {"required": False, "hints": [], "locations": []}, # ### NEW: Added locations list
        "request_schema": {"fields": []},
        "response_hints": []
    }

    try:
        tree = ast.parse(open(view_file, encoding="utf-8").read())
    except Exception:
        return analysis

    for node in ast.walk(tree):

        # -------- Function-based view --------
        if isinstance(node, ast.FunctionDef) and node.name == view_name:
            analysis["view_definition_line"] = node.lineno # ### NEW
            extract_http_methods(node, analysis)
            detect_auth(node, analysis)
            detect_request_schema(node, analysis)
            detect_response(node, analysis)

        # -------- Class-based view --------
        if isinstance(node, ast.ClassDef) and node.name == view_name:
            analysis["view_definition_line"] = node.lineno # ### NEW
            for item in node.body:
                if isinstance(item, ast.FunctionDef):
                    m = item.name.upper()
                    if m in HTTP_METHODS:
                        analysis["http_methods"].append(m)
                        detect_auth(item, analysis)
                        detect_request_schema(item, analysis)
                        detect_response(item, analysis)

    if not analysis["http_methods"]:
        analysis["http_methods"] = ["GET"]

    return analysis


def extract_http_methods(node: ast.AST, analysis: Dict):
    for n in ast.walk(node):
        if isinstance(n, ast.Compare):
            if isinstance(n.left, ast.Attribute) and n.left.attr == "method":
                for c in n.comparators:
                    if isinstance(c, ast.Constant):
                        analysis["http_methods"].append(c.value)


def detect_auth(node: ast.AST, analysis: Dict):
    # Check decorators
    if hasattr(node, "decorator_list"):
        for d in node.decorator_list:
            name = ast.unparse(d)
            for p in AUTH_PATTERNS:
                if p in name:
                    analysis["auth"]["required"] = True
                    analysis["auth"]["hints"].append(p)
                    # ### NEW: Store location of the auth decorator
                    analysis["auth"]["locations"].append({
                        "type": "decorator",
                        "pattern": p,
                        "line": d.lineno
                    })

    # Check body code (recursive)
    for n in ast.walk(node):
        try:
            # Avoid re-checking the decorators themselves (which ast.walk might hit if not careful, 
            # though usually it walks children. FunctionDef children includes body, args, etc.)
            
            # Simple check on names/attributes/strings in the code body
            code = ast.unparse(n)
            for p in AUTH_PATTERNS:
                # We need to be careful not to duplicate if multiple nodes construct the same line.
                # A simple check is usually sufficient for static analysis context.
                if p in code:
                    analysis["auth"]["required"] = True
                    analysis["auth"]["hints"].append(p)
                    # ### NEW: Store location of the auth usage (e.g., if request.user...)
                    # Since 'n' might not have lineno (some nodes don't), we check safely
                    if hasattr(n, 'lineno'):
                        analysis["auth"]["locations"].append({
                            "type": "code_usage",
                            "pattern": p,
                            "line": n.lineno
                        })
        except Exception:
            pass
            
    # Clean up duplicates in hints/locations if ast.walk hit multiple child nodes of same expression
    # (Optional refinement step you might want to add for cleaner JSON)


def detect_request_schema(node: ast.AST, analysis: Dict):
    for n in ast.walk(node):
        if isinstance(n, ast.Subscript):
            if isinstance(n.value, ast.Attribute) and n.value.attr in ("POST", "GET"):
                field = get_ast_string(n.slice)
                if field:
                    analysis["request_schema"]["fields"].append(field)

        if isinstance(n, ast.Call) and hasattr(n.func, "attr"):
            if n.func.attr == "loads":
                analysis["request_schema"]["fields"].append("raw_json_body")


def detect_response(node: ast.AST, analysis: Dict):
    for n in ast.walk(node):
        if isinstance(n, ast.Call):
            try:
                name = ast.unparse(n.func)
                if "JsonResponse" in name or "HttpResponse" in name:
                    analysis["response_hints"].append(name)
            except Exception:
                pass


def build_compact_context(extracted: Dict[str, Any]) -> Dict[str, Any]:
    """
    Reduce extracted data to LLM-friendly compact JSON.
    """
    compact_endpoints = []

    for ep in extracted.get("endpoints", []):
        compact_endpoints.append({
            "path": ep.get("path"),
            "view": ep.get("view"),
            "line": ep.get("line_number"), # ### NEW: Include in context for LLM
            "source": os.path.basename(ep.get("source", "")),
            "auth_lines": [loc['line'] for loc in ep.get("auth", {}).get("locations", [])] # ### NEW
        })

    return {
        "framework": extracted.get("framework"),
        "endpoint_count": len(compact_endpoints),
        "endpoints": compact_endpoints
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
        "type": "session | token | jwt | recommended | none",
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
      "cvss_vector": " ",
      "references": [
        "https://owasp.org/www-community/attacks/SQL_Injection"
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
# 7. Main Orchestrator (PUBLIC API)
# =========================================================

def extract_django_endpoints(repo_path: str, user_token: Optional[str] = None, sector: str = "General Data Privacy") -> Dict[str, Any]:
    output = {
        "framework": "django",
        "endpoints": [],
        "errors": []
    }

    try:
        settings_module = discover_settings_module(repo_path)
        if not settings_module:
            raise Exception("Django settings module not found")

        settings_file = module_to_path(repo_path, settings_module)
        if not settings_file:
            raise Exception("settings.py not found")

        root_urlconf = extract_root_urlconf(settings_file)
        if not root_urlconf:
            raise Exception("ROOT_URLCONF missing")

        urls_file = module_to_path(repo_path, root_urlconf)
        if not urls_file:
            raise Exception("urls.py not found")

        endpoints = parse_urls_file(repo_path, urls_file)
        output['endpoints'] = endpoints

        for ep in endpoints:
            view_expr = ep.get("view", "")
            view_file = resolve_view_file(repo_path, view_expr)
            if view_file:
                view_name = view_expr.split(".")[-1]
                ep.update(analyze_view(view_file, view_name))

        # Step 6: LLM enrichment
        try:
            enriched = enrich_with_llm(output, user_token=user_token, sector=sector)
            output["llm_enriched"] = enriched
        except Exception as llm_error:
            output["errors"].append(f"LLM enrichment failed: {str(llm_error)}")

    except Exception as e:
        output["errors"].append(str(e))

    return output


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python django_api_inspector.py <repo_path> [access_token] [sector]")
        sys.exit(1)

    repo_path_arg = sys.argv[1]
    token_arg = sys.argv[2] if len(sys.argv) > 2 else None
    sector_arg = sys.argv[3] if len(sys.argv) > 3 else "General Data Privacy"

    results = extract_django_endpoints(repo_path_arg, user_token=token_arg, sector=sector_arg)
    print(json.dumps(results, indent=2))