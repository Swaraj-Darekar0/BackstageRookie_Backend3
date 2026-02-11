import os
import json
import logging
from typing import Any, List, Dict
import re
import subprocess

import google.generativeai as genai
from google.oauth2.credentials import Credentials
from flask import session

logger = logging.getLogger(__name__)

class LLMAnalyzer:
    """
    Advanced LLM Analyzer using the Gemini API via the user's session credentials.
    Performs context-aware "vulnerability hunting" and risk summarization.
    """

    def __init__(self, config: Dict = None, model_dir: str = None, adapter_dir: str = None):
        """
        Initializes the Gemini-based analyzer. The local model parameters are ignored
        but kept for compatibility with the orchestrator's instantiation call.
        """
        default_llm_config = {
            'max_hunts': 3, 
            'enable_risk_summary': True, 
            'model_name': 'gemini-2.5-flash-lite'
        }
        self.config = default_llm_config
        if isinstance(config, dict):
            self.config.update(config)
        logger.info("LLMAnalyzer (Gemini version) initialized.")

    def analyze(self, repo_path: str, seed_findings: List[Dict], full_findings_summary: Dict) -> Dict[str, Any]:
        """
        Main entry point for LLM analysis.
        Orchestrates different LLM tasks based on config.
        """
        # Check for token at the beginning of the analysis.
        user_token = session.get('google_access_token')
        if not user_token:
            logger.warning("LLM analysis skipped: No user token found in session.")
            return {"linked_findings": [], "risk_summary": "Skipped: No user token provided."}

        results = {}
        results["linked_findings"] = self._task_hunt_for_linked_vulnerabilities(repo_path, seed_findings)
        
        if self.config.get('enable_risk_summary'):
            combined_summary = self._combine_summaries(full_findings_summary, results["linked_findings"])
            results["risk_summary"] = self._task_summarize_risk(combined_summary)
        
        return results

    def _generate(self, prompt: str) -> str:
        """
        Calls the Gemini API to generate content using the user's token from the Flask session.
        """
        user_token = session.get('google_access_token')
        if not user_token:
            logger.error("LLMAnalyzer._generate called without a user token in session.")
            return "Error: Could not find user token in session for Gemini API call."

        # Temporarily manage environment variables to prevent conflicts
        api_key_env = os.environ.pop('GOOGLE_API_KEY', None)
        gemini_key_env = os.environ.pop('GEMINI_API_KEY', None)

        try:
            user_credentials = Credentials(token=user_token)
            genai.configure(credentials=user_credentials)
            
            model = genai.GenerativeModel(self.config.get('model_name'))
            response = model.generate_content(prompt)
            
            return getattr(response, 'text', str(response))
        except Exception as e:
            logger.error(f"Gemini API call failed in LLMAnalyzer: {e}", exc_info=True)
            return f"Error during generation: {e}"
        finally:
            if api_key_env:
                os.environ['GOOGLE_API_KEY'] = api_key_env
            if gemini_key_env:
                os.environ['GEMINI_API_KEY'] = gemini_key_env

    def _task_hunt_for_linked_vulnerabilities(self, repo_path: str, seed_findings: List[Dict]) -> List[Dict]:
        all_new_findings = []
        hunts_performed = 0
        for seed in seed_findings:
            if hunts_performed >= self.config.get('max_hunts', 3):
                logger.info("Reached max number of LLM hunts.")
                break
            
            logger.info(f"--- Starting LLM Hunt based on seed: {seed.get('shortform_keyword')} in {seed.get('file_path')} ---")
            try:
                seed_file_path = os.path.join(repo_path, seed['file_path'])
                if not os.path.exists(seed_file_path):
                    logger.warning(f"Seed file not found: {seed_file_path}")
                    continue
                
                with open(seed_file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    seed_file_content = f.read()

                target_entity = self._extract_target_entity(seed.get('context_snippet', ''))
                
                cross_references = "Not available."
                if target_entity:
                    try:
                        result = subprocess.run(['rg', '-l', target_entity, repo_path], capture_output=True, text=True, check=False)
                        if result.stdout:
                            cross_references = "The vulnerable entity is also mentioned in:\n" + result.stdout
                    except FileNotFoundError:
                        logger.warning("`rg` (ripgrep) not found. Cannot perform cross-reference search.")
                    except Exception as e:
                        logger.warning(f"Cross-reference search failed: {e}")

                prompt = self._build_hunt_prompt(seed, seed_file_content, cross_references)
                raw_output = self._generate(prompt)
                
                new_findings = self._parse_finding_blocks(raw_output)
                if new_findings:
                    logger.info(f"LLM Hunt successful: Found {len(new_findings)} new linked vulnerabilities.")
                    all_new_findings.extend(new_findings)
                else:
                    logger.info("LLM Hunt did not yield any new findings from output.")
                hunts_performed += 1
            except Exception as e:
                logger.error(f"Error during LLM hunt for seed {seed.get('shortform_keyword')}: {e}", exc_info=True)

        return all_new_findings

    def _task_summarize_risk(self, findings_summary: Any) -> str:
        prompt = f"""
Provide a brief, executive-level summary of the project's security posture based on these findings.
Do not list the vulnerabilities; instead, describe the overall risk profile and key areas of concern.

Context:
{json.dumps(findings_summary, indent=2)}
""".strip()
        try:
            return self._generate(prompt)
        except Exception as e:
            logger.error(f"LLM task 'summarize_risk' failed: {e}")
            return "Risk summary could not be generated due to an error."
    
    def _extract_target_entity(self, snippet: str) -> str:
        match = re.search(r'(?:function|class)\s+([a-zA-Z0-9_]+)', snippet)
        return match.group(1) if match else ""

    def _build_hunt_prompt(self, seed_finding: Dict, seed_file_content: str, cross_references: str) -> str:
        return f"""
As a security researcher, you have found a "seed" vulnerability. Your task is to investigate the codebase to find other, new vulnerabilities that could be linked to it, forming an attack chain.

**Seed Vulnerability Details:**
- Type: {seed_finding.get('shortform_keyword')}
- File: {seed_finding.get('file_path')}
- Line: {seed_finding.get('line_number')}
- Description: {seed_finding.get('context_snippet')}

**Full source code of the vulnerable file (`{seed_finding.get('file_path')}`):**
```
{seed_file_content[:8000]}
```

**Cross-references (where the vulnerable code might be used elsewhere):**
```
{cross_references[:2000]}
```

**Your Mission:**
Based on all the context above, find **NEW, PREVIOUSLY UNDETECTED** vulnerabilities in the codebase that either:
1. Allow an attacker to control the input to the seed vulnerability (e.g., an unsanitized API endpoint).
2. Exploit the output or state change caused by the seed vulnerability.

Report **ONLY THE NEW VULNERABILITIES** you discover. Do not report the seed vulnerability itself. If you find no new linked vulnerabilities, respond with "NONE".

For EACH new vulnerability found, respond in EXACTLY this format:
VULNERABILITY: <type_of_new_vulnerability>
FILE: <file_path_of_new_vulnerability>
LINE: <line_number>
DESCRIPTION: <how_this_new_vulnerability_links_to_the_seed>
CONFIDENCE: <HIGH|MEDIUM|LOW>
---
""".strip()

    def _parse_finding_blocks(self, text: str) -> List[Dict]:
        findings = []
        for block_text in text.split('---'):
            if not block_text.strip() or block_text.strip().upper() == "NONE": continue
            finding = {"source": "llm-hunter-gemini", "confidence": "MEDIUM"} # Mark source as Gemini
            for line in block_text.strip().splitlines():
                if ":" not in line: continue
                key, value = line.split(":", 1)
                key = key.strip().lower()
                value = value.strip()
                if key == "vulnerability": finding["shortform_keyword"] = value
                elif key == "file": finding["file_path"] = value
                elif key == "line": finding["line_number"] = int(value) if value.isdigit() else -1
                elif key == "description": finding["context_snippet"] = value
                elif key == "confidence": finding["confidence"] = value.upper()
            if "shortform_keyword" in finding and "file_path" in finding:
                finding["severity"] = self._map_confidence_to_severity(finding["confidence"])
                findings.append(finding)
        return findings

    def _combine_summaries(self, original_summary, new_findings):
        if not new_findings: return original_summary
        summary = original_summary.copy()
        summary['total'] += len(new_findings)
        for f in new_findings:
            sev = f.get('severity', 'MEDIUM')
            if sev in summary['by_severity']:
                summary['by_severity'][sev] += 1
            kw = f.get('shortform_keyword', 'UNKNOWN')
            summary['by_type'][kw] = summary['by_type'].get(kw, 0) + 1
        return summary

    def _map_confidence_to_severity(self, confidence: str) -> str:
        return {"HIGH": "HIGH", "MEDIUM": "MEDIUM", "LOW": "LOW"}.get(confidence, "MEDIUM")


