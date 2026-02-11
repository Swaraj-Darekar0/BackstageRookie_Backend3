
import os
import logging

logger = logging.getLogger(__name__)

class RepoInfoExtractor:
    """
    Extracts contextual information from repository for report generation
    This includes README, policy documents, and dependency files
    """
    
    def extract(self, repo_path):
        """Extract all repository context information"""
        logger.info(f"📄 Extracting repository information from: {repo_path}")
        
        info = {
            'readme': self._extract_readme(repo_path),
            'policies': self._extract_policies(repo_path),
            'dependencies': self._extract_dependencies(repo_path),
            'documentation': self._extract_documentation(repo_path)
        }
        
        logger.info(f"✅ Extracted: {len(info['policies'])} policies, {len(info['dependencies'])} dependency files")
        
        return info
    
    def _extract_readme(self, repo_path):
        """Extract README.md content"""
        readme_files = ['README.md', 'readme.md', 'README.MD', 'Readme.md']
        
        for readme_name in readme_files:
            readme_path = os.path.join(repo_path, readme_name)
            if os.path.exists(readme_path):
                try:
                    with open(readme_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        logger.debug(f"   Found README: {readme_name}")
                        return content
                except Exception as e:
                    logger.warning(f"⚠️  Error reading {readme_name}: {e}")
        
        logger.debug("   No README found")
        return None
    
    def _extract_policies(self, repo_path):
        """Extract policy documents (HIPAA, privacy, etc.)"""
        policies = {}
        
        # Look for policies directory
        policy_dir = os.path.join(repo_path, 'policies')
        
        if os.path.exists(policy_dir) and os.path.isdir(policy_dir):
            for filename in os.listdir(policy_dir):
                if filename.endswith('.md'):
                    file_path = os.path.join(policy_dir, filename)
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            policies[filename] = f.read()
                            logger.debug(f"   Found policy: {filename}")
                    except Exception as e:
                        logger.warning(f"⚠️  Error reading policy {filename}: {e}")
        
        # Also look for common policy files in root
        common_policy_files = [
            'SECURITY.md', 'security.md',
            'PRIVACY.md', 'privacy.md',
            'COMPLIANCE.md', 'compliance.md',
            'CODE_OF_CONDUCT.md'
        ]
        
        for filename in common_policy_files:
            file_path = os.path.join(repo_path, filename)
            if os.path.exists(file_path):
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        policies[filename] = f.read()
                        logger.debug(f"   Found policy: {filename}")
                except Exception as e:
                    logger.warning(f"⚠️  Error reading {filename}: {e}")
        
        return policies
    
    def _extract_dependencies(self, repo_path):
        """Extract dependency files"""
        dependencies = {}
        
        dependency_files = {
            'python': ['requirements.txt', 'Pipfile', 'pyproject.toml', 'setup.py'],
            'javascript': ['package.json', 'package-lock.json', 'yarn.lock'],
            'java': ['pom.xml', 'build.gradle', 'gradle.lockfile'],
            'ruby': ['Gemfile', 'Gemfile.lock'],
            'php': ['composer.json', 'composer.lock'],
            'go': ['go.mod', 'go.sum'],
            'rust': ['Cargo.toml', 'Cargo.lock'],
            'dotnet': ['packages.config', '*.csproj']
        }
        
        for language, files in dependency_files.items():
            for filename in files:
                file_path = os.path.join(repo_path, filename)
                if os.path.exists(file_path):
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            dependencies[filename] = {
                                'language': language,
                                'content': f.read()
                            }
                            logger.debug(f"   Found dependency file: {filename} ({language})")
                    except Exception as e:
                        logger.warning(f"⚠️  Error reading {filename}: {e}")
        
        return dependencies
    
    def _extract_documentation(self, repo_path):
        """Extract additional documentation files"""
        documentation = {}
        
        # Look for docs directory
        docs_dirs = ['docs', 'documentation', 'doc']
        
        for docs_dir_name in docs_dirs:
            docs_path = os.path.join(repo_path, docs_dir_name)
            
            if os.path.exists(docs_path) and os.path.isdir(docs_path):
                for root, dirs, files in os.walk(docs_path):
                    for filename in files:
                        if filename.endswith(('.md', '.txt', '.rst')):
                            file_path = os.path.join(root, filename)
                            relative_path = os.path.relpath(file_path, repo_path)
                            
                            try:
                                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                    documentation[relative_path] = f.read()
                                    logger.debug(f"   Found documentation: {relative_path}")
                            except Exception as e:
                                logger.warning(f"⚠️  Error reading {relative_path}: {e}")
        
        return documentation

