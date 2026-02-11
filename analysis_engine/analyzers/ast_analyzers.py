import ast
import os
import logging

logger = logging.getLogger(__name__)

class ASTAnalyzer:
    """Abstract Syntax Tree-based security analysis"""
    
    def analyze(self, repo_path):
        """Run AST analysis on all Python files"""
        findings = []
        
        for root, dirs, files in os.walk(repo_path):
            for file in files:
                if file.endswith('.py'):
                    file_path = os.path.join(root, file)
                    file_findings = self._analyze_file(file_path, repo_path)
                    findings.extend(file_findings)
        
        logger.info("ASTAnalyzer found {} findings".format(len(findings)))
        return findings
    
    def _analyze_file(self, file_path, repo_path):
        """Analyze file using AST"""
        findings = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            tree = ast.parse(content)
            
            findings.extend(self._check_missing_auth(tree, file_path, repo_path))
            findings.extend(self._check_idor(tree, file_path, repo_path))
            findings.extend(self._check_data_flow(tree, file_path, repo_path))
        
        except SyntaxError:
            logger.debug("Syntax error in file")
        except Exception as e:
            logger.warning("AST error: {}".format(str(e)))
        
        return findings
    
    def _check_missing_auth(self, tree, file_path, repo_path):
        """Check for functions without authentication"""
        findings = []
        
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                has_auth = any(self._is_auth_decorator(d) for d in node.decorator_list)
                
                if not has_auth and any(kw in node.name.lower() for kw in ['delete', 'transfer', 'admin']):
                    findings.append({
                        'Repository_name': repo_path.split(os.sep)[-1],
                        'shortform_keyword': 'MISSING-AUTH-CHECK',
                        'file_path': os.path.relpath(file_path, repo_path),
                        'line_number': node.lineno,
                        'severity': 'HIGH',
                        'context_snippet': 'Function {}'.format(node.name),
                        'source': 'ast',
                        'confidence': 'LOW'
                    })
        
        return findings
    
    def _check_idor(self, tree, file_path, repo_path):
        """Check for IDOR vulnerabilities"""
        findings = []
        
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if hasattr(node.func, 'attr') and node.func.attr in ['get', 'find']:
                    if node.args and self._is_user_input(node.args[0]):
                        findings.append({
                            'shortform_keyword': 'IDOR-VULNERABILITY',
                            'file_path': os.path.relpath(file_path, repo_path),
                            'line_number': node.lineno,
                            'severity': 'HIGH',
                            'context_snippet': 'Direct object reference',
                            'source': 'ast',
                            'confidence': 'MEDIUM'
                        })
        
        return findings
    
    def _check_data_flow(self, tree, file_path, repo_path):
        """Check for data flow vulnerabilities"""
        findings = []
        
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if hasattr(node.func, 'attr') and node.func.attr in ['execute', 'query']:
                    if node.args and self._is_user_input(node.args[0]):
                        findings.append({
                            'shortform_keyword': 'TAINTED-DATA-FLOW',
                            'file_path': os.path.relpath(file_path, repo_path),
                            'line_number': node.lineno,
                            'severity': 'HIGH',
                            'context_snippet': 'User input to query',
                            'source': 'ast',
                            'confidence': 'HIGH'
                        })
        
        return findings
    
    def _is_auth_decorator(self, node):
        if isinstance(node, ast.Name):
            return node.id in ['login_required', 'require_auth']
        return False
    
    def _is_user_input(self, node):
        if isinstance(node, ast.Attribute):
            if isinstance(node.value, ast.Name):
                return node.value.id in ['request', 'args']
        return False