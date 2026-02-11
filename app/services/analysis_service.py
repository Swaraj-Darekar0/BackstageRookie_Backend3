import json
import logging
import os
import shutil
import stat
import uuid
from datetime import datetime
from typing import Any, Dict, List
from dotenv import load_dotenv
import google.generativeai as genai
from flask import current_app # Keep current_app for config access
from google.oauth2.credentials import Credentials
from openai import OpenAI

from analysis_engine.orchestrator import AnalysisOrchestrator
from app.services.repo_info_service import RepoInfoExtractor
load_dotenv()
logger = logging.getLogger(__name__)


class AnalysisService:
    """
    Thin service layer.
    Delegates all analysis to AnalysisOrchestrator.
    Transforms raw findings into a structured report if plan is 'full'.
    """

    def __init__(self, plan='basic'):
        self.data_dir = current_app.config['DATA_DIR']
        self.plan = plan
        self.repo_extractor = RepoInfoExtractor()
        # The orchestrator is always run in 'basic' mode to get raw findings
        self.orchestrator = AnalysisOrchestrator(plan='basic')
        logger.info(f"AnalysisService initialized (plan: {plan})")

    def analyze_codebase(self, repo_path, sector_hint, scan_id, user_token: str = None): # Added user_token here
        try:
            logger.info(f"🔍 Starting scan {scan_id} on path {repo_path}")

            # 1️⃣ Extract repository context
            repo_info = self.repo_extractor.extract(repo_path)
            
            # 2️⃣ Run analysis via orchestrator to get raw findings
            findings, metrics = self.orchestrator.run(
                repo_path=repo_path,
                repository_info=repo_info
            )
            
            # 3️⃣ Build final results
            logger.info("Plan is 'full'. Building structured JSON report with LLM...")
            structured_report = self._build_structured_report(
                    repo_path,
                    findings,
                    repo_info,
                    sector_hint,
                    user_token # Pass user_token to _build_structured_report
                )
                
            final_results = structured_report or {}

            # Ensure total_findings reflects the number of vulnerabilities in the final report.
            total = 0
            try:
                vuln_list = final_results.get('executive_summary', {}).get('vulnerability_list')
                if isinstance(vuln_list, list):
                    total = len(vuln_list)
                else:
                    # fallback to 'findings' section if vulnerability_list is missing
                    findings_list = final_results.get('findings')
                    if isinstance(findings_list, list):
                        total = len(findings_list)
                    else:
                        # final fallback to raw findings returned by orchestrator
                        total = len(findings) if isinstance(findings, list) else 0
            except Exception:
                total = len(findings) if isinstance(findings, list) else 0

            final_results['total_findings'] = total

            # Add metadata to the final report
            final_results['scan_id'] = scan_id
            final_results['timestamp'] = datetime.now().isoformat()

            

            # 4️⃣ Persist final results
            self._save_scan_results(scan_id, final_results)

            logger.info(f"✅ Scan complete for plan '{self.plan}'.")
            return final_results

        except Exception as e:
            logger.error(f"❌ Analysis failed for scan {scan_id}: {e}", exc_info=True)
            raise

    def _build_structured_report(self, repo_path: str, findings: List[Dict], repo_info: Dict, sector_hint: str, user_token: str = None) -> Dict[str, Any]: # Accept user_token
        """Orchestrates the LLM call to build the final JSON report."""
        prompt = self._build_report_prompt(repo_path, findings, sector_hint)
        raw_json_string = self._generate_with_llm(prompt, user_token) # Pass user_token to _generate_with_llm

        try:
            clean_json_string = raw_json_string.strip().replace('```json', '').replace('```', '').strip()
            if not clean_json_string:
                raise json.JSONDecodeError("LLM returned an empty response.", "", 0)
            return json.loads(clean_json_string)
        except json.JSONDecodeError as e:
            logger.error(f"Failed to decode JSON from LLM report generator: {e}")
            return {"error": f"Failed to parse the structured report from the LLM: {e}", "raw_output": raw_json_string}

    def _generate_with_llm(self, prompt: str, user_token: str = None) -> str: # Added user_token parameter
        """
        Handles the API call to a configured LLM endpoint.
        Tries Groq API first, then falls back to Gemini with user's token.
        """
        # Attempt 1: Groq API
        try:
            
            api_key = os.getenv("GROQ_API_KEY")
  
            if not api_key:
                raise ValueError("GROQ_API_KEY environment variable not set.")

            logger.info("Attempting to generate report with Groq API.")
            client = OpenAI(
                api_key=api_key,
                base_url="https://api.groq.com/openai/v1",
            )
            
            chat_completion = client.chat.completions.create(
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
            
            response_content = chat_completion.choices[0].message.content
            if response_content:
                logger.info("Groq API call successful.")
                return response_content
            
            logger.warning("Groq API returned an empty response.")
            raise ConnectionError("Groq API returned an empty response.")

        except Exception as e:
            logger.warning(f"Groq API call failed: {e}. Falling back to Gemini API.")
            
            try:
                api_key = os.getenv("OPENROUTER_API_KEY")
                if not api_key:
                    raise ValueError("OPENROUTER_API_KEY environment variable not set.")

                logger.info("Attempting to generate report with OpenRouter API.")
                client = OpenAI(
                    api_key=api_key,
                    base_url="https://openrouter.ai/api/v1",
                )
                
                chat_completion = client.chat.completions.create(
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
                
                response_content = chat_completion.choices[0].message.content
                if response_content:
                    logger.info("OpenRouter fallback  API call successful.")
                    return response_content
                
                logger.warning("OpenRouter fallback API returned an empty response.")
                raise ConnectionError("OpenRouter fallback API returned an empty response.")

            except Exception as another_e:
                logger.warning(f"openRouter API call failed: {another_e}. Falling back to Gemini API.")
                try:
                        # user_token = session.get('google_access_token') # REMOVED: Get user_token from argument
                        if not user_token:
                            logger.error("Gemini fallback failed: No user token provided to _generate_with_llm.")
                            return '{"error": "Primary LLM service failed and no fallback user token is available."}'

                        logger.info("Attempting to generate report with Gemini API.")
                        
                        # Temporarily manage environment variables to prevent conflicts
                        api_key_env = os.environ.pop('GOOGLE_API_KEY', None)
                        gemini_key_env = os.environ.pop('GEMINI_API_KEY', None)

                        try:
                            user_credentials = Credentials(token=user_token)
                            genai.configure(credentials=user_credentials)
                            
                            model = genai.GenerativeModel('gemini-2.5-flash')
                            response = model.generate_content(prompt)
                            
                            response_text = getattr(response, 'text', str(response))
                            if response_text:
                                logger.info("Gemini API call successful.")
                                return response_text
                            
                            logger.warning("Gemini API returned an empty response.")
                            return '{"error": "Gemini API returned an empty response."}'

                        finally:
                            # Restore environment variables
                            if api_key_env:
                                os.environ['GOOGLE_API_KEY'] = api_key_env
                            if gemini_key_env:
                                os.environ['GEMINI_API_KEY'] = gemini_key_env
                    
                except Exception as gemini_e:
                        logger.error(f"Gemini API fallback also failed: {gemini_e}", exc_info=True)
                        return f'{{"error": "Both primary and fallback LLM services failed. Gemini error: {gemini_e}"}}'


    def _build_report_prompt(self, repo_path: str, findings: List[Dict], sector: str) -> str:
        """Builds the detailed prompt for the final report generation."""
        for finding in findings:
            try:
                file_path = os.path.join(repo_path, finding['file_path'])
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    lines = f.readlines()
                start = max(0, finding['line_number'] - 10)
                end = min(len(lines), finding['line_number'] + 10)
                context_lines = lines[start:end]
                finding['code_context_with_line_numbers'] = "".join([f"{i+1}: {line}" for i, line in enumerate(context_lines, start)])
            except Exception:
                finding['code_context_with_line_numbers'] = "Could not read file context."
        
        findings_json_str = json.dumps(findings, indent=2)
        
        output_schema = """
{
  "Repository_name": "Name of the repository analyzed",  ,
  "executive_summary": {
    "overview": "High-level narrative generated by LLM based on verified findings.",
    "vulnerability_overview_text": "<X> Critical, <Y> High, ... vulnerabilities identified.",
    "vulnerability_list": [
      {
        "id": "C1",
        "title": "SQL Injection",
        "cvss": 10.0,
        "page": "app.py:9"
      }
    ],
    "severity_distribution": {
      "CRITICAL": 0,
      "HIGH": 0,
      "MEDIUM": 0,
      "LOW": 0
    }
  },
  "methodology": {
    "introduction": "This report details the results of a security assessment conducted on the specified repository. The analysis involved a multi-layered approach, combining automated static analysis tools with advanced, AI-driven verification and enrichment to identify potential security vulnerabilities.",
    "objective": "The primary objective of this assessment was to identify security weaknesses, assess their potential impact, and provide actionable recommendations for remediation to improve the overall security posture of the application.",
    "scope_text": "The assessment was performed on the source code of the repository cloned at the time of the scan. The analysis focused on common web application vulnerabilities, insecure coding practices, and dependency risks.",
    "systems": [],
    "user_accounts_description": "As this was a static source code analysis, no user accounts were provisioned or tested.",
    "accounts": []
  },
  "findings": [
    {
      "id": "C1",
      "title": "SQL Injection (SQLi)",
      "severity": "critical",
      "severity_label": "Critical",
      "cvss": 10.0,
      "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
      "target": "The application's database layer",
      "references": [
        "https://owasp.org/www-community/attacks/SQL_Injection"
      ],
      "overview": "A narrative overview of the specific vulnerability.",
      "details": "A technical deep-dive into the vulnerability, explaining the root cause.",
      "evidence": [
        {
          "name": "app/services/user_service.py:58",
          "description": string
        }
      ],
      "recommendation": "- Use parameterized queries (prepared statements) for all database interactions.\n- Implement input validation on all user-supplied data.\n- Utilize an Object-Relational Mapping (ORM) library that automatically handles SQL injection prevention.",
      "prompts_to_solve_the_vulnerability": "In App services/user_service.py, there is a potential SQL injection vulnerability at line 58 where user input is directly concatenated into a SQL query. To remediate this issue, you should refactor the code to use parameterized queries or prepared statements. For example, if you are using a library like psycopg2 for PostgreSQL, you can change the code from something like `cursor.execute(f\"SELECT * FROM users WHERE username = '{username}'\")` to `cursor.execute(\"SELECT * FROM users WHERE username = %s\", (username,))`. This change will ensure that user input is properly escaped and will prevent attackers from injecting malicious SQL code through the username parameter."
    }
  ]
}
"""
        prompt = f"""
You are a world-class security researcher and report generator. Your task is to analyze a set of preliminary findings from static analysis tools and produce a final, comprehensive, and professional security assessment report in JSON format.

**Input Data:**

1.  **Preliminary Findings:** A list of potential vulnerabilities found by basic tools. For each finding, I have included the code context.
    ```json
    {findings_json_str}
    ```

2.  **Repository Context:**
    - Sector: {sector}

**Your Task:**

1.  **Verify and Enrich Findings:** For each preliminary finding, use its `code_context_with_line_numbers` to analyze the code.
    *   Determine if the finding is a true positive. **You MUST discard any false positives.**
    *   For each true positive, create a finding object in the final report. Enrich it with a clear `title`, `cvss` score, `vector` string, `overview`, `details`, and an actionable `recommendation`.
    *   **The recommendation must be a single string with points separated by '\\n-'.**
    *   Assign a finding `id` (e.g., C1, H1, M1) based on severity.

2.  **Generate Executive Summary:** Based ONLY on the verified findings, create an `executive_summary`.
    *   Write a high-level `overview`.
    *   Accurately summarize the counts of vulnerabilities by severity.

3.  **Produce Final JSON:** Combine all parts into a single JSON object that STRICTLY conforms to the schema provided below. Do not include any extra text, markdown, or explanations outside of the JSON structure.

**Output JSON Schema (Strict):**
{output_schema}

**IMPORTANT INSTRUCTIONS:**
- Your entire response MUST be a single, valid JSON object.
- Generate realistic but illustrative CVSS scores and vectors.
- The Prompt to Solve the Vulnerability should be a clear, concise explanation of how to fix the issue in the code, referencing the file path and line number from the code context.
- Do not add your own comments.

Now, produce the final JSON report.
"""
        return prompt

    def _save_scan_results(self, scan_id, results):
        results_dir = os.path.join(self.data_dir, "scanned_results")
        os.makedirs(results_dir, exist_ok=True)
        path = os.path.join(results_dir, f"{scan_id}.json")
        with open(path, "w") as f:
            json.dump(results, f, indent=2)
        logger.info(f"💾 Results saved: {path}")

    @staticmethod
    def _remove_readonly_onerror(func, path, _):
        os.chmod(path, stat.S_IWRITE)
        func(path)
