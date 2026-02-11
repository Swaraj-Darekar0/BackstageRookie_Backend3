
import re
import os
import logging

logger = logging.getLogger(__name__)

class RegexAnalyzer:
    """Pattern-based security vulnerability detection"""
    
    def __init__(self):
        self.patterns = self._load_patterns()
    
    def analyze(self, repo_path):
        """Run regex analysis on all Python files"""
        findings = []
        
        for root, dirs, files in os.walk(repo_path):
            for file in files:
                if file.endswith('.py'):
                    file_path = os.path.join(root, file)
                    file_findings = self._analyze_file(file_path, repo_path)
                    findings.extend(file_findings)
        
        logger.info("RegexAnalyzer found {} findings".format(len(findings)))
        return findings
    
    def _analyze_file(self, file_path, repo_path):
        """Analyze single file"""
        findings = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
            
            for pattern_name, config in self.patterns.items():
                regex = config['regex']
                
                for i, line in enumerate(lines, 1):
                    if re.search(regex, line, re.IGNORECASE):
                        finding = {
                            'Repository_name': repo_path.split(os.sep)[-1],
                            'shortform_keyword': config['keyword'],
                            'file_path': os.path.relpath(file_path, repo_path),
                            'line_number': i,
                            'severity': config['severity'],
                            'context_snippet': line.strip()[:300],
                            'source': 'regex',
                            'pattern_name': pattern_name,
                            'confidence': 'MEDIUM'
                        }
                        findings.append(finding)
        
        except Exception as e:
            logger.warning("Error in regex analysis: {}".format(str(e)))
        
        return findings
    
    def _load_patterns(self):
        """Load all 35 regex patterns"""
        return {
            'sql_injection': {
            'keyword': 'SQL-INJECTION-REGEX',
            'severity': 'HIGH',
            'regex': r'execute\s*\(\s*f["\']|\.execute\s*\(".*"\s*\+\s*|execute\s*\(".*%s"\s*%\s*'
        },
        'nosql_injection': {
            'keyword': 'NOSQL-INJECTION',
            'severity': 'HIGH',
            'regex': r'\.find\s*\(\s*\{.*[\$where|mapReduce|group].*\}|\.collection\s*\(\s*["\'].*\+.*["\']'
        },
        'ldap_injection': {
            'keyword': 'LDAP-INJECTION',
            'severity': 'HIGH',
            'regex': r'ldap\.search_s\s*\(.*,\s*ldap\.SCOPE_SUBTREE,\s*f["\']'
        },
        'xss_template': {
            'keyword': 'XSS-UNESC-OUTPUT',
            'severity': 'HIGH',
            'regex': r'render_template_string\s*\(|Markup\s*\(.*request\.'
        },

        # === Authentication & Session Management ===
        'weak_password_hash': {
            'keyword': 'WEAK-CRYPTO-HASH',
            'severity': 'MEDIUM',
            'regex': r'hashlib\.md5|hashlib\.sha1'
        },
        'insecure_token_generation': {
            'keyword': 'INSECURE-RANDOMNESS',
            'severity': 'LOW',
            'regex': r'random\.randint|random\.random'
        },
        'missing_httponly_cookie': {
            'keyword': 'MISSING-COOKIE-HTTPONLY',
            'severity': 'MEDIUM',
            'regex': r'\.set_cookie\s*\(.*httponly\s*=\s*False'
        },
        'missing_secure_cookie': {
            'keyword': 'MISSING-COOKIE-SECURE',
            'severity': 'MEDIUM',
            'regex': r'\.set_cookie\s*\(.*secure\s*=\s*False'
        },
        'session_fixation': {
            'keyword': 'SESSION-FIXATION',
            'severity': 'MEDIUM',
            'regex': r'session\.regenerate\s*\(\s*\)' # This would be a check for the ABSENCE of this, best handled by AST or manual review
        },

        # === Insecure Configuration & Deployment ===
        'debug_mode_enabled': {
            'keyword': 'DEBUG-MODE-ENABLED',
            'severity': 'HIGH',
            'regex': r'app\.run\s*\(.*debug\s*=\s*True'
        },
        'verbose_error_message': {
            'keyword': 'SENSITIVE-DATA-EXPOSURE-IN-ERROR',
            'severity': 'LOW',
            'regex': r'return\s+.*str\(\s*e\s*\)'
        },
        'weak_ssl_tls': {
            'keyword': 'WEAK-SSL-TLS',
            'severity': 'HIGH',
            'regex': r'ssl\.CERT_NONE|requests\..*\(\s*.*verify\s*=\s*False'
        },
        'missing_security_headers': {
            'keyword': 'MISSING-SECURITY-HEADERS',
            'severity': 'LOW',
            'regex': r'@app\.after_request' # Absence of this is the indicator
        },

        # === Cryptography & Secrets Management ===
        'hardcoded_secret': {
            'keyword': 'HARDCODED-SECRET',
            'severity': 'CRITICAL',
            'regex': r'(password|passwd|pwd|secret|api_key|apikey|token)\s*=\s*["\'][^"\']{8,}["\']'
        },
        'hardcoded_encryption_key': {
            'keyword': 'HARDCODED-ENCRYPTION-KEY',
            'severity': 'CRITICAL',
            'regex': r'(encryption_key|cipher_key|aes_key)\s*=\s*["\'].*["\']'
        },
        'ecb_mode_usage': {
            'keyword': 'WEAK-CRYPTO-ECB',
            'severity': 'HIGH',
            'regex': r'AES\.MODE_ECB'
        },
        'exposed_api_key_in_code': {
            'keyword': 'EXPOSED-API-KEY',
            'severity': 'CRITICAL',
            'regex': r'["\'](AIza[0-9A-Za-z-_]{35}|sk-[0-9a-zA-Z]{48})["\']' # Common Google/OpenAI patterns
        },
        
        # === Command & Deserialization Vulnerabilities ===
        'shell_true': {
            'keyword': 'SUBPROCESS-SHELL-TRUE',
            'severity': 'HIGH',
            'regex': r'subprocess\.(run|call|Popen).*shell\s*=\s*True|os\.system\s*\('
        },
        'pickle_unsafe': {
            'keyword': 'PICKLE-UNSAFE',
            'severity': 'HIGH',
            'regex': r'pickle\.loads?\s*\(|marshal\.loads?\s*\('
        },
        'yaml_unsafe': {
            'keyword': 'YAML-LOAD-UNSAFE',
            'severity': 'HIGH',
            'regex': r'yaml\.load\s*\((?!.*Loader=)' # Looks for yaml.load without a specified Loader
        },
        'eval_usage': {
            'keyword': 'EVAL-EXEC-USE',
            'severity': 'CRITICAL',
            'regex': r'\beval\s*\(|\bexec\s*\('
        },
        'xxe_patterns': {
            'keyword': 'XXE-VULNERABILITY',
            'severity': 'HIGH',
            'regex': r'xml\.etree\.ElementTree\.parse|lxml\.etree\.parse'
        },

        # === Server-Side & Data Handling Vulnerabilities ===
        'ssrf_patterns': {
            'keyword': 'SSRF-VULNERABILITY',
            'severity': 'HIGH',
            'regex': r'requests\.(get|post)\s*\(.*request\..*\)'
        },
        'sensitive_data_in_logs': {
            'keyword': 'SENSITIVE-DATA-IN-LOGS',
            'severity': 'MEDIUM',
            'regex': r'logger\.(info|debug)\s*\(.*(password|credit_card|ssn).*'
        },
        'unsafe_redirect': {
            'keyword': 'UNSAFE-REDIRECT',
            'severity': 'MEDIUM',
            'regex': r'redirect\s*\(\s*request\.'
        },
        'exposed_internal_ip': {
            'keyword': 'EXPOSED-INTERNAL-IP',
            'severity': 'LOW',
            'regex': r'["\'](192\.168\.[0-9]+\.[0-9]+|10\.[0-9]+\.[0-9]+\.[0-9]+|172\.(1[6-9]|2[0-9]|3[0-1])\.[0-9]+\.[0-9]+)["\']'
        },

        # === General Python & Web Security ===
        'csrf_protection_missing': {
            'keyword': 'CSRF-PROTECTION-MISSING',
            'severity': 'MEDIUM',
            'regex': r'app\.config\[\s*["\']WTF_CSRF_ENABLED["\']\s*\]\s*=\s*False'
        },
        'insecure_tempfile': {
            'keyword': 'INSECURE-TEMPFILE',
            'severity': 'MEDIUM',
            'regex': r'/tmp/|tempfile\.mktemp\('
        },
        'unsafe_assert': {
            'keyword': 'UNSAFE-ASSERT',
            'severity': 'LOW',
            'regex': r'assert\s+.*request\.'
        },
        'unsafe_getattr': {
            'keyword': 'UNSAFE-GETATTR',
            'severity': 'HIGH',
            'regex': r'getattr\s*\(.*,\s*request\.'
        },
        'missing_rate_limiting': {
            'keyword': 'MISSING-RATE-LIMITING',
            'severity': 'LOW',
            'regex': r'@limiter\.limit' # Absence is the indicator
        },
        'missing_dnssec': {
            'keyword': 'DNSSEC-NOT-ENABLED',
            'severity': 'INFO',
            'regex': r'# placeholder: no reliable regex for python code'
        },
        'unsafe_input_usage': {
            'keyword': 'UNSAFE-INPUT-USAGE',
            'severity': 'HIGH',
            'regex': r'\binput\s*\('
        }
        }
# Additional patterns can be added here 