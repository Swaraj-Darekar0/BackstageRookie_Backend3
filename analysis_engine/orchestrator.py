import logging
import time
from copy import deepcopy
from typing import List, Dict

from analysis_engine.analyzers.regex_analyzer import RegexAnalyzer
from analysis_engine.analyzers.ast_analyzers import ASTAnalyzer
from analysis_engine.analyzers.external_tool_analyzer import ExternalToolAnalyzer
from analysis_engine.analyzers.llm_analyzer_gemini import LLMAnalyzer

logger = logging.getLogger(__name__)

class AnalysisOrchestrator:
    """
    Master orchestrator that runs all analysis methods and aggregates results.
    Supports plan-based enablement/disablement of analyzers and LLM vulnerability hunting.
    """

    def __init__(self, plan="basic", config=None):
        self.plan = plan
        self.config = deepcopy(config) if config else self._default_config()
        self._apply_plan_overrides()

        self.regex_analyzer = None
        self.ast_analyzer = None
        self.external_tool_analyzer = None
        self.llm_analyzer = None

        self._load_analyzers()
        logger.info("AnalysisOrchestrator initialized | plan=%s | config=%s", self.plan, self.config)

    def _default_config(self):
        """Default analysis configuration with new LLM task controls."""
        return {
            'regex': {'enabled': True, 'timeout': 30},
            'ast': {'enabled': True, 'timeout': 120},
            'external_tools': {'enabled': True, 'timeout': 180},
            'llm': {
                'enabled': True,
                'enable_hunt_mode': True,      # New: Main toggle for LLM hunting
                'enable_risk_summary': True,   # New: Toggle for final summary
                'max_hunts': 3,                # New: Max number of seeds to investigate
            },
            'deduplicate': True,
            'filter_low_confidence': True
        }

    def _apply_plan_overrides(self):
        overrides = self._plan_overrides(self.plan)
        if not overrides: return
        for section, values in overrides.items():
            if section in self.config and isinstance(self.config[section], dict):
                self.config[section].update(values)
            else:
                self.config[section] = values

    def _plan_overrides(self, plan):
        plan = (plan or "basic").lower()
        if plan == "full":
            return {'llm': {'enabled': True}}
        if plan == "basic":
            return {'llm': {'enabled': False}}
        return {}

    def _load_analyzers(self):
        if self.config.get('regex', {}).get('enabled'): self.regex_analyzer = RegexAnalyzer()
        if self.config.get('ast', {}).get('enabled'): self.ast_analyzer = ASTAnalyzer()
        if self.config.get('external_tools', {}).get('enabled'): self.external_tool_analyzer = ExternalToolAnalyzer()
        if self.config.get('llm', {}).get('enabled'):
            self.llm_analyzer = LLMAnalyzer(config=self.config.get('llm'))

    def analyze(self, repo_path, repository_info=None):
        logger.info("=" * 70)
        logger.info("STARTING COMPREHENSIVE SECURITY ANALYSIS")
        logger.info("=" * 70)
        
        start_time = time.time()
        initial_findings = []
        metrics = {'by_source': {}, 'execution_times': {}, 'llm_risk_summary': '', 'llm_attack_chains': []}
        
        # --- STAGES 1-3: Initial Static Analysis ---
        if self.regex_analyzer: self._run_sub_analyzer(initial_findings, metrics, 'regex', self.regex_analyzer, repo_path)
        if self.ast_analyzer: self._run_sub_analyzer(initial_findings, metrics, 'ast', self.ast_analyzer, repo_path)
        if self.external_tool_analyzer: self._run_sub_analyzer(initial_findings, metrics, 'external_tools', self.external_tool_analyzer, repo_path)
        
        all_findings = list(initial_findings)
        
        # --- STAGE 4: LLM Vulnerability Hunting ---
        llm_config = self.config.get('llm', {})
        if llm_config.get('enabled') and llm_config.get('enable_hunt_mode') and self.llm_analyzer and repository_info:
            logger.info("[4/4] Starting LLM Vulnerability Hunting...")
            llm_start = time.time()
            
            # Select high-confidence findings as "seeds" for the hunt
            seed_findings = self._select_seed_findings(all_findings)
            
            # The LLM now returns a dictionary of results
            full_findings_summary = self._summarize_findings(all_findings)
            llm_results = self.llm_analyzer.analyze(repo_path, seed_findings, full_findings_summary)
            
            linked_findings = llm_results.get('linked_findings', [])
            if linked_findings:
                logger.info(f"LLM Hunt found {len(linked_findings)} new linked vulnerabilities.")
                all_findings.extend(linked_findings)
            
            # Store summary and attack chains (if generated) in metrics
            metrics['llm_risk_summary'] = llm_results.get('risk_summary', 'Not generated.')
            
            llm_time = time.time() - llm_start
            metrics['execution_times']['llm_hunt'] = llm_time
            metrics['by_source']['llm-hunter'] = len(linked_findings)
            logger.info(f"✅ LLM Hunt completed in {llm_time:.1f}s")

        # --- Post-Processing ---
        final_findings = self._post_process_findings(all_findings)
        
        # --- Final Metrics ---
        metrics['total_findings'] = len(final_findings)
        metrics['by_severity'] = self._count_by_severity(final_findings)
        total_time = time.time() - start_time
        metrics['total_time'] = total_time
        
        logger.info("=" * 70)
        logger.info("ANALYSIS COMPLETE | Total Time: {:.1f}s".format(total_time))
        logger.info("Total Findings: {} | By Severity: {}".format(metrics['total_findings'], metrics['by_severity']))
        if metrics.get('llm_risk_summary'):
            logger.info(f"LLM Risk Summary: {metrics['llm_risk_summary']}")
        logger.info("=" * 70)
        
        return final_findings, metrics
    
    def _select_seed_findings(self, findings: List[Dict]) -> List[Dict]:
        """Select high-confidence findings to act as seeds for the LLM hunt."""
        seeds = [f for f in findings if f.get('severity') in ['CRITICAL', 'HIGH']]
        # Sort by severity to prioritize the most critical seeds
        sorted_seeds = sorted(seeds, key=lambda x: self._severity_rank(x.get('severity')), reverse=True)
        max_hunts = self.config.get('llm', {}).get('max_hunts', 3)
        logger.info(f"Selected {min(len(sorted_seeds), max_hunts)} high-confidence findings as seeds for LLM hunt.")
        return sorted_seeds[:max_hunts]

    def _run_sub_analyzer(self, all_findings, metrics, name, analyzer, repo_path):
        logger.info(f"Running {name.upper()} Analysis...")
        start = time.time()
        try:
            findings = analyzer.analyze(repo_path)
            all_findings.extend(findings)
            elapsed = time.time() - start
            metrics['execution_times'][name] = elapsed
            metrics['by_source'][name] = len(findings)
            logger.info(f"✅ {name.title()}: {len(findings)} findings in {elapsed:.1f}s")
        except Exception as e:
            logger.error(f"❌ {name.title()} analysis failed: {e}", exc_info=True)

    def _post_process_findings(self, findings):
        if self.config.get('deduplicate'):
            original_count = len(findings)
            findings = self._deduplicate_findings(findings)
            logger.info(f"[Post-Processing] Deduplicated: {original_count} → {len(findings)} findings")
        
        if self.config.get('filter_low_confidence'):
            original_count = len(findings)
            findings = self._filter_findings(findings)
            logger.info(f"[Post-Processing] Filtered low-confidence: {original_count} → {len(findings)} findings")
        
        logger.info("[Post-Processing] Ranking findings by severity...")
        return sorted(findings, key=lambda x: self._severity_rank(x.get('severity')), reverse=True)

    def _summarize_findings(self, findings):
        return {
            'total': len(findings),
            'by_severity': self._count_by_severity(findings),
            'by_type': self._count_by_type(findings),
            'samples': [f"{f.get('shortform_keyword')} in {f.get('file_path')}:L{f.get('line_number')}" for f in findings[:15]]
        }

    def _deduplicate_findings(self, findings):
        seen, unique = set(), []
        for finding in findings:
            # LLM-hunted findings are unique and shouldn't be deduplicated against file-specific ones
            if finding.get('source') == 'llm-hunter':
                unique.append(finding)
                continue
            key = (finding.get('file_path'), finding.get('line_number'), finding.get('shortform_keyword'))
            if key not in seen:
                seen.add(key)
                unique.append(finding)
        return unique

    def _filter_findings(self, findings):
        return [f for f in findings if f.get('confidence', 'MEDIUM') != 'LOW']

    def _count_by_severity(self, findings):
        counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
        for f in findings:
            sev = f.get('severity', 'MEDIUM')
            if sev in counts: counts[sev] += 1
        return counts

    def _count_by_type(self, findings):
        counts = {}
        for f in findings:
            keyword = f.get('shortform_keyword', 'UNKNOWN')
            counts[keyword] = counts.get(keyword, 0) + 1
        return counts

    def _severity_rank(self, severity):
        return {'CRITICAL': 5, 'HIGH': 4, 'MEDIUM': 3, 'LOW': 2, 'INFO': 1}.get(severity, 0)

    def run(self, repo_path, repository_info):
        return self.analyze(repo_path, repository_info)
