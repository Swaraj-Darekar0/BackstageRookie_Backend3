import subprocess
import json
import logging
import os
import concurrent.futures

logger = logging.getLogger(__name__)

class ExternalToolAnalyzer:
    """Integrates Bandit and pip-audit"""
    
    def __init__(self):
        self.bandit_mapping = self._load_bandit_mapping()
    
    def analyze(self, repo_path):
        """Run external tools"""
        findings = []
    
    # Run both tools in parallel using a ThreadPool
        with concurrent.futures.ThreadPoolExecutor() as executor:
            future_bandit = executor.submit(self._run_bandit, repo_path)
            future_pip = executor.submit(self._run_pip_audit, repo_path)
        
            findings.extend(future_bandit.result())
            findings.extend(future_pip.result())
        
        logger.info("ExternalToolAnalyzer found {} findings".format(len(findings)))
        return findings
    
    def _load_bandit_mapping(self):
        """Map Bandit test IDs to standardized keywords"""
        return {
    'B201': 'FLASK-DEBUG-MODE',           # flask_debug_true
    'B301': 'PICKLE-UNSAFE',              # pickle
    'B302': 'MARSHAL-UNSAFE',             # marshal
    'B303': 'MD5-WEAK-HASH',              # md5
    'B304': 'CIPHER-WEAK',                # ciphers
    'B305': 'CIPHER-MODE-WEAK',           # cipher_modes
    'B306': 'TEMP-WEAK',                  # mktemp_q
    'B307': 'EVAL-EXEC-USE',              # eval
    'B308': 'MARK-SAFE-USAGE',            # mark_safe
    'B309': 'HTTPSCONNECTION-UNVERIFIED', # httpsconnection
    'B310': 'URL-OPEN-UNVERIFIED',        # urllib_urlopen
    'B311': 'RANDOM-WEAK',                # random
    'B312': 'TELNETLIB-USAGE',            # telnetlib
    'B313': 'XML-ETREE-PARSE',            # xml_etree
    'B314': 'XML-EXPAT-PARSE',            # xml_expat
    'B315': 'XML-MINIDOM-PARSE',          # xml_minidom
    'B316': 'XML-PULLDOM-PARSE',          # xml_pulldom
    'B317': 'XML-SAX-PARSE',              # xml_sax
    'B318': 'XML-DOM-PARSE',              # xml_dom
    'B319': 'XML-ETREE-ITERPARSE',        # xml_etree_iterparse
    'B320': 'UNVERIFIED-CONTEXT-SSL',     # unverified_context
    'B321': 'FTPLIB-USAGE',               # ftplib
    'B322': 'INPUT-BUILTIN-USAGE',        # input
    'B323': 'UNVERIFIED-FTP-CONTEXT',     # unverified_ftp_context
    'B324': 'HASHLIB-PBKDF2-WEAK',        # hashlib_pbkdf2_weak
    
    # ======================================================================
    # HARDCODED SECRETS & CREDENTIALS
    # ======================================================================
    'B105': 'HARDCODED-PASSWORD-STRING',  # hardcoded_password_string
    'B106': 'HARDCODED-PASSWORD-FUNCARG', # hardcoded_password_funcarg
    'B107': 'HARDCODED-PASSWORD-DEFAULT', # hardcoded_password_default
    'B108': 'HARDCODED-TMP-DIRECTORY',    # hardcoded_tmp_directory
    'B109': 'PASSWORD-CONFIG-OPTION',     # password_config_option_not_marked_secret
    
    # ======================================================================
    # COMMAND INJECTION & OS OPERATIONS
    # ======================================================================
    'B602': 'SUBPROCESS-SHELL-TRUE',      # shell=True in subprocess
    'B603': 'SUBPROCESS-WITHOUT-SHELL',   # subprocess without shell equals true
    'B604': 'ANY-OTHER-FUNCTION-WITH-SHELL', # any_other_function_with_shell_equals_true
    'B605': 'START-PROCESS-WITH-SHELL',   # start_process_with_a_shell
    'B606': 'START-PROCESS-NO-SHELL',     # start_process_with_no_shell
    'B607': 'PARTIAL-PATH-EXECUTABLE',    # start_process_with_partial_path
    'B608': 'SQL-INJECTION-BANDIT',       # sql_injection
    'B609': 'WILDCARD-INJECTION',         # linux_commands_wildcard_injection
    'B610': 'DJANGO-SQL-INJECTION',       # django_sql_injection
    'B611': 'DJANGO-QUERY-INJECTION',     # django_query_injection
    'B612': 'LOG-SQL-INJECTION',          # logging_sql_injection
    'B613': 'REQUEST-VERIFY-FALSE',       # request_verify_false
    
    # ======================================================================
    # AUTHENTICATION & AUTHORIZATION
    # ======================================================================
    'B701': 'JINJA2-AUTOESCAPE-FALSE',    # jinja2_autoescape_false
    'B702': 'MAKO-ESCAPE-FALSE',          # mako_templates
    'B703': 'DJANGO-MARK-SAFE',           # django_mark_safe
    
    # ======================================================================
    # CRYPTOGRAPHY & SSL/TLS
    # ======================================================================
    'B501': 'SSL-CERT-NONE',              # ssl with verify disabled
    'B502': 'SSL-WITH-BAD-VERSION',       # ssl_with_bad_version
    'B503': 'SSL-WITH-BAD-DEFAULTS',      # ssl_with_bad_defaults
    'B504': 'SSL-WITH-NO-VERSION',        # ssl_with_no_version
    'B505': 'WEAK-CRYPTOGRAPHIC-KEY',     # weak_cryptographic_key
    'B506': 'YAML-LOAD-UNSAFE',           # yaml_load
    'B507': 'SSH-NO-HOST-KEY-VERIFICATION', # ssh_no_host_key_verification
    
    # ======================================================================
    # EXCEPTION HANDLING & FLOW CONTROL
    # ======================================================================
    'B110': 'TRY-EXCEPT-CONTINUE',        # try_except_continue
    'B111': 'TRY-EXCEPT-PASS',            # try_except_pass
    'B112': 'TRY-EXCEPT-BARE',            # try_except_bare
    'B113': 'REQUEST-TIMEOUT-MISSING',    # request_without_timeout
    
    # ======================================================================
    # ASSERTION & TESTING
    # ======================================================================
    'B101': 'ASSERT-USAGE',               # assert_used (in security context)
    'B102': 'EXEC-BUILTIN-USAGE',         # exec_used
    'B103': 'SET-BUILTIN-USAGE',          # set_builtin_usage (for blacklist)
    'B104': 'ASSERT-RAISES-USAGE',        # assert_raises_usage (for blacklist)
    
    # ======================================================================
    # FUNCTION & CLASS DEFINITIONS
    # ======================================================================
    'B201': 'FLASK-DEBUG-TRUE',           # flask_debug_true
    'B202': 'TARFILE-UNSAFE-EXTRACT',     # tarfile_unsafe_members
    'B203': 'YML-LOAD-UNSAFE',            # yaml_load (alternative)
    'B301': 'PICKLE-LOAD',                # pickle_load
    'B302': 'MARSHAL-LOAD',               # marshal_load
    
    # ======================================================================
    # FILE OPERATIONS
    # ======================================================================
    'B108': 'INSECURE-TEMPFILE',          # hardcoded_tmp_directory
    'B109': 'TEMP-FILE-NO-CLEANUP',       # password_config_option
    'B110': 'FILE-PERMISSIONS-WEAK',      # try_except_continue
    'B111': 'OPEN-FILE-NO-PERMISSION',    # try_except_pass
    
    # ======================================================================
    # NETWORK & COMMUNICATION
    # ======================================================================
    'B601': 'PARAMIKO-CALL',              # paramiko_calls
    'B602': 'POPEN-SHELL-TRUE',           # popen_with_shell_equals_true
    'B610': 'DJANGO-RAW-SQL',             # django_raw_sql
    'B611': 'DJANGO-QUERYSET-EXTRA',      # django_queryset_extra
    'B612': 'LOGGING-SQL',                # logging_sql
    'B613': 'REQUEST-NO-VERIFY',          # requests_no_verify
    
    # ======================================================================
    # GENERAL SECURITY
    # ======================================================================
    'B701': 'JINJA2-NO-AUTOESCAPE',       # jinja2_autoescape
    'B702': 'MAKO-TEMPLATES',             # mako_templates
    'B703': 'DJANGO-SAFE-MARK',           # django_mark_safe

    # UNUSED/DEPRECATED 
    'B999': 'BLACKLIST-CALL',  
        }
    
    def _run_bandit(self, repo_path):
        """Run Bandit and map findings"""
        findings = []
        
        try:
            # By setting cwd, bandit runs inside the repo_path, and paths in the output
            # will be relative to that directory. We scan '.' (current dir).
            result = subprocess.run(
                ['bandit', '-r', '.', '-f', 'json', '-ll', '-x', '.venv,venv,env,tests,node_modules'],
                capture_output=True,
                text=True,
                timeout=120,
                cwd=repo_path
                )
            
            if result.returncode in [0, 1]:
                try:
                    data = json.loads(result.stdout)
                    for issue in data.get('results', []):
                        test_id = issue.get('test_id', 'UNKNOWN')
                        
                        # Map Bandit test ID to keyword
                        keyword = self.bandit_mapping.get(test_id, 'BANDIT-{}'.format(test_id))
                        
                        # issue['filename'] is now correctly relative to repo_path
                        finding = {
                            'shortform_keyword': keyword,
                            'file_path': issue['filename'],
                            'line_number': issue['line_number'],
                            'severity': issue['issue_severity'],
                            'context_snippet': issue.get('code', '')[:300],
                            'source': 'bandit',
                            'confidence': 'HIGH',
                            'bandit_test_id': test_id,
                            'bandit_issue': issue.get('issue_text', '')
                        }
                        findings.append(finding)
                        logger.debug("Bandit {}: {} at {}:{}".format(
                            test_id, keyword, finding['file_path'], finding['line_number']
                        ))
                except json.JSONDecodeError:
                    logger.error("Bandit JSON parse error")
        
        except FileNotFoundError:
            logger.error("Bandit not installed: pip install bandit")
        except subprocess.TimeoutExpired:
            logger.error("Bandit timed out after 120 seconds")
        except Exception as e:
            logger.error("Bandit error: {}".format(str(e)))
        
        return findings
    
    def _run_pip_audit(self, repo_path):
        """Run pip-audit"""
        findings = []
        
        # By setting cwd, pip-audit runs inside the repo_path and will
        # automatically find requirements.txt or other dependency files.
        try:
            # Check if any dependency file exists before running
            if any(os.path.exists(os.path.join(repo_path, f)) for f in ['requirements.txt', 'Pipfile', 'pyproject.toml']):
                result = subprocess.run(
                    ['pip-audit', '--format', 'json'],
                    capture_output=True,
                    text=True,
                    timeout=20,
                    cwd=repo_path # Run from within the repo directory
                )
                
                if result.returncode in [0, 1] and result.stdout:
                    try:
                        data = json.loads(result.stdout)
                        for dep in data.get('dependencies', []):
                            for vuln in dep.get('vulns', []):
                                findings.append({
                                    'Repository_name': repo_path.split(os.sep)[-1], # Add repository name for context
                                    'shortform_keyword': 'VULNERABLE-DEPENDENCY',
                                    'file_path': 'dependency_file', # pip-audit doesn't specify file in this format
                                    'line_number': 0,
                                    'severity': 'HIGH',
                                    'context_snippet': f"{dep['name']}=={dep['version']} - {vuln['id']}: {vuln['description']}",
                                    'source': 'pip_audit',
                                    'confidence': 'HIGH',
                                    'cve': vuln.get('id')
                                })
                    except json.JSONDecodeError:
                        logger.error("pip-audit JSON parse error: %s", result.stdout)
        
        except FileNotFoundError:
            logger.error("pip-audit not installed")
        except subprocess.TimeoutExpired:
            logger.error("pip-audit timed out after 60 seconds")
        except Exception as e:
            logger.error("pip-audit error: {}".format(str(e)))
        
        return findings
