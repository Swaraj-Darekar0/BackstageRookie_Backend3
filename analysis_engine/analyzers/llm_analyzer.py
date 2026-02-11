import os
import json
import logging
from typing import Any, List, Dict
import re
import subprocess

import torch
from transformers import (
    AutoTokenizer,
    AutoModelForCausalLM,
    BitsAndBytesConfig
)
from peft import PeftModel

from analysis_engine.utils.model_manager import (
    ensure_model_downloaded,
    BASE_MODEL_DIR,
    ADAPTER_DIR
)

logger = logging.getLogger(__name__)

# Singleton cache to prevent reloading the model
_LLM_SINGLETON = {
    "model": None,
    "tokenizer": None,
    "initialized": False
}


class LLMAnalyzer:
    """
    Advanced LLM Analyzer using a fine-tuned Qwen model.
    Performs context-aware "vulnerability hunting" based on high-confidence seed findings.
    """

    def __init__(self, config: Dict = None, model_dir: str = None, adapter_dir: str = None):
        global _LLM_SINGLETON
        if not _LLM_SINGLETON["initialized"]:
            self._initialize_model(model_dir, adapter_dir)
        
        self.model = _LLM_SINGLETON["model"]
        self.tokenizer = _LLM_SINGLETON["tokenizer"]
        
        default_llm_config = {'max_hunts': 3, 'enable_risk_summary': True}
        self.config = default_llm_config
        if isinstance(config, dict):
            self.config.update(config)

    def _initialize_model(self, model_dir: str, adapter_dir: str):
        global _LLM_SINGLETON
        logger.info("Cold start: initializing LLM (4-bit quantized)...")
        ensure_model_downloaded()
        model_path = os.path.abspath(model_dir or BASE_MODEL_DIR)
        adapter_path = os.path.abspath(adapter_dir or ADAPTER_DIR)

        try:
            bnb_config = BitsAndBytesConfig(load_in_4bit=True, bnb_4bit_quant_type="nf4", bnb_4bit_use_double_quant=True, bnb_4bit_compute_dtype=torch.float16)
            self.tokenizer = AutoTokenizer.from_pretrained(model_path, trust_remote_code=True)
            base_model = AutoModelForCausalLM.from_pretrained(model_path, quantization_config=bnb_config, device_map="auto", trust_remote_code=True)
            
            if os.path.exists(adapter_path):
                logger.info("Loading fine-tuned LoRA adapter from %s...", adapter_path)
                self.model = PeftModel.from_pretrained(base_model, adapter_path)
            else:
                logger.warning("Adapter not found at %s, using base model only", adapter_path)
                self.model = base_model
            
            self.model.eval()
            _LLM_SINGLETON.update({"model": self.model, "tokenizer": self.tokenizer, "initialized": True})
            logger.info("LLM cold initialization completed and cached.")
        except Exception as e:
            logger.error(f"LLM initialization failed: {e}", exc_info=True)
            self.model = None
            self.tokenizer = None

    def analyze(self, repo_path: str, seed_findings: List[Dict], full_findings_summary: Dict) -> Dict[str, Any]:
        """
        Main entry point for LLM analysis.
        Orchestrates different LLM tasks based on config.
        """
        if not self.model or not self.tokenizer:
            return {"linked_findings": [], "risk_summary": ""}

        results = {}
        results["linked_findings"] = self._task_hunt_for_linked_vulnerabilities(repo_path, seed_findings)
        
        if self.config.get('enable_risk_summary'):
            # Risk summary should analyze ALL findings, including newly found linked ones.
            combined_summary = self._combine_summaries(full_findings_summary, results["linked_findings"])
            results["risk_summary"] = self._task_summarize_risk(combined_summary)
        
        return results

    def _generate(self, prompt: str, max_new_tokens: int = 512) -> str:
        if not self.tokenizer or not self.model: return ""
        messages = [{"role": "user", "content": prompt}]
        tokenized_chat = self.tokenizer.apply_chat_template(messages, tokenize=True, add_generation_prompt=True, return_tensors="pt")
        inputs = tokenized_chat.to(self.model.device)
        with torch.no_grad():
            output_ids = self.model.generate(inputs, max_new_tokens=max_new_tokens, do_sample=False, pad_token_id=self.tokenizer.eos_token_id)
        response_ids = output_ids[0][inputs.shape[1]:]
        return self.tokenizer.decode(response_ids, skip_special_tokens=True).strip()

    def _task_hunt_for_linked_vulnerabilities(self, repo_path: str, seed_findings: List[Dict]) -> List[Dict]:
        all_new_findings = []
        hunts_performed = 0
        for seed in seed_findings:
            if hunts_performed >= self.config.get('max_hunts', 3):
                logger.info("Reached max number of LLM hunts.")
                break
            
            logger.info(f"--- Starting LLM Hunt based on seed: {seed.get('shortform_keyword')} in {seed.get('file_path')} ---")
            try:
                # 1. Gather Context
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
                        # Use rg (ripgrep) for fast, cross-file searching
                        result = subprocess.run(['rg', '-l', target_entity, repo_path], capture_output=True, text=True)
                        if result.stdout:
                            cross_references = "The vulnerable entity is also mentioned in:\n" + result.stdout
                    except FileNotFoundError:
                        logger.warning("`rg` (ripgrep) not found. Cannot perform cross-reference search.")
                    except Exception as e:
                        logger.warning(f"Cross-reference search failed: {e}")

                # 2. Build and Execute Prompt
                prompt = self._build_hunt_prompt(seed, seed_file_content, cross_references)
                raw_output = self._generate(prompt, max_new_tokens=1024)
                
                # 3. Parse and Store
                new_findings = self._parse_finding_blocks(raw_output)
                if new_findings:
                    logger.info(f"LLM Hunt successful: Found {len(new_findings)} new linked vulnerabilities.")
                    all_new_findings.extend(new_findings)
                else:
                    logger.info("LLM Hunt did not yield any new findings.")
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
            return self._generate(prompt, max_new_tokens=250)
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
{seed_file_content[:4000]}
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
remediation steps: <brief_remediation_steps> 
---
""".strip()

    def _parse_finding_blocks(self, text: str) -> List[Dict]:
        findings = []
        for block_text in text.split('---'):
            if not block_text.strip() or block_text.strip().upper() == "NONE": continue
            finding = {"source": "llm-hunter", "confidence": "MEDIUM"}
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

