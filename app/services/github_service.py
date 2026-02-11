import git
import os
import subprocess
import json
from datetime import datetime
from flask import current_app, session
import google.generativeai as genai
from openai import OpenAI
from google.oauth2.credentials import Credentials
from dotenv import load_dotenv

load_dotenv()

class GitHubService:
    def __init__(self):
        self.pulled_code_dir = current_app.config.get('PULLED_CODE_DIR')

    # -----------------------------
    # PUBLIC ENTRY POINT
    # -----------------------------
    def clone_repository(self, github_url, destination_path,user_token):
        """
        High-level automated pipeline:
        1. Partial clone (no blobs)
        2. List repo tree
        3. Send tree to LLM (Gemini)
        4. Apply sparse checkout
        5. Pull only selected files
        """
        try:
            os.makedirs(destination_path, exist_ok=True)

            # 1. Partial clone (no file contents)
            self._partial_clone(github_url, destination_path)

            # 2. Extract repo tree
            repo_tree = self._get_repo_tree(destination_path)

            # 3. Ask LLM what to include
            include_rules = self._ask_llm_what_to_include(repo_tree,user_token)

            # 4. Apply sparse checkout
            self._apply_sparse_checkout(destination_path, include_rules)

            # 5. Final checkout (files downloaded here)
            self._checkout_selected_files(destination_path)

            # Log success
            self._log_clone_operation(github_url, destination_path)

            return destination_path

        except Exception as e:
            raise Exception(f"Failed to process repository: {str(e)}")

    # -----------------------------
    # STEP 1: PARTIAL CLONE
    # -----------------------------
    def _partial_clone(self, github_url, destination_path):
        subprocess.run(
            [
                "git", "clone",
                "--filter=blob:none",
                "--no-checkout",
                github_url,
                destination_path
            ],
            check=True
        )

    # -----------------------------
    # STEP 2: LIST REPO TREE
    # -----------------------------
    def _get_repo_tree(self, repo_path):
        result = subprocess.run(
            ["git", "ls-tree", "-r", "--name-only", "HEAD"],
            cwd=repo_path,
            capture_output=True,
            text=True,
            check=True
        )

        files = result.stdout.splitlines()

        return {
            "file_count": len(files),
            "files": files
        }

    # -----------------------------
    # STEP 3: LLM (GEMINI) DECISION
    # -----------------------------
    def _ask_llm_what_to_include(self, repo_tree,user_token):
        """
        Uses the user's Gemini credentials to decide which files are relevant for a security scan.
        """
        user_token = user_token
        # Fallback to default rules if no user token is available
        if not user_token:
            print("[GitHubService] No user token in session. Using default file include rules.")
            return self._get_default_include_rules()

        prompt = f"""
        You are an expert security analysis assistant. Your task is to decide which files from a repository are most relevant for a security scan.
        Focus on files related to backend logic, APIs, authentication, data handling, infrastructure configuration, and dependencies.
        Exclude documentation, images, and frontend-only assets unless they contain configuration.

        Analyze the following file tree and return a JSON object containing a single key "include" with a list of glob patterns for the files to check out.
        The patterns should be optimized for git sparse-checkout. For example, use `backend/` to include a whole directory.

        Repository file tree:
        {json.dumps(repo_tree, indent=2)}

        Respond with ONLY the JSON object.
        """

        # Use the established pattern for making a call on behalf of the user
        api_key_env = os.environ.pop('GOOGLE_API_KEY', None)
        gemini_key_env = os.environ.pop('GEMINI_API_KEY', None)


        try:
            api_key_env=os.getenv("GROQ_API_KEY")
            if not api_key_env:
                print("GROQ_API_KEY not found in environment variables. Cannot call Groq API.")
            client = OpenAI(
                    api_key=api_key_env,
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
            cleaned_text = raw_response.strip().replace('```json', '').replace('```', '').strip()
            groq_response = json.loads(cleaned_text)
            include_rules = groq_response.get("include", [])
            if isinstance(include_rules, list):
                    print(f"[GitHubService] system recommended include rules: {include_rules}")
                    return include_rules
            
        except Exception as e:
            print(f"trying fallback ,due to error{e}")

            try:
                user_credentials = Credentials(token=user_token)
                genai.configure(credentials=user_credentials)
                
                model = genai.GenerativeModel('gemini-2.5-flash-lite')
                response = model.generate_content(prompt)
                
                cleaned_text = response.text.strip().replace('```json', '').replace('```', '').strip()
                gemini_response = json.loads(cleaned_text)
                
                include_rules = gemini_response.get("include", [])
                if isinstance(include_rules, list):
                    print(f"[GitHubService] Gemini recommended include rules: {include_rules}")
                    return include_rules
                else:
                    print("[GitHubService] Gemini response for include rules was not a list. Falling back to default.")
                    return self._get_default_include_rules()

            except Exception as e:
                print(f"[GitHubService] Gemini API call failed: {e}. Falling back to default file include rules.")
                return self._get_default_include_rules()
            finally:
                # Restore environment variables
                if api_key_env:
                    os.environ['GOOGLE_API_KEY'] = api_key_env
                if gemini_key_env:
                    os.environ['GEMINI_API_KEY'] = gemini_key_env

    def _get_default_include_rules(self):
        """Provides a safe default set of rules if the LLM call fails."""
        return [
            "backend/",
            "src/",
            "app/",
            "api/",
            "**/*.py",
            "**/*.js",
            "!**/*.test.js",
            "**/*.go",
            "**/*.java",
            "**/*.rb",
            "**/*.php",
            "**/requirements.txt",
            "**/package.json",
            "**/pom.xml",
            "**/Gemfile",
            "**/composer.json",
            "**/go.mod",
            "**/Cargo.toml",
            "**/*.yaml",
            "**/*.yml",
            "**/*.json",
            "!**/__pycache__/*"
        ]

    # -----------------------------
    # STEP 4: SPARSE CHECKOUT
    # -----------------------------
    def _apply_sparse_checkout(self, repo_path, include_rules):
        repo = git.Repo(repo_path)

        repo.git.config("core.sparseCheckout", "true")

        sparse_file = os.path.join(repo_path, ".git", "info", "sparse-checkout")

        with open(sparse_file, "w") as f:
            for rule in include_rules:
                f.write(rule.strip() + "\n")

    # -----------------------------
    # STEP 5: CHECKOUT FILES
    # -----------------------------
    def _checkout_selected_files(self, repo_path):
        repo = git.Repo(repo_path)
        repo.git.checkout("HEAD")

    # -----------------------------
    # LOGGING (UNCHANGED)
    # -----------------------------
    def _log_clone_operation(self, github_url, clone_path):
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'github_url': github_url,
            'local_path': clone_path,
            'status': 'success'
        }
        print(f"Repository processed: {log_entry}")

    # -----------------------------
    # INFO EXTRACTION (UNCHANGED)
    # -----------------------------
    def get_repository_info(self, repo_path):
        info = {}

        readme_path = os.path.join(repo_path, 'README.md')
        if os.path.exists(readme_path):
            with open(readme_path, 'r', encoding='utf-8') as f:
                info['readme'] = f.read()

        package_files = ['requirements.txt', 'package.json', 'Pipfile', 'pom.xml']
        info['dependencies'] = {}

        for file in package_files:
            file_path = os.path.join(repo_path, file)
            if os.path.exists(file_path):
                with open(file_path, 'r', encoding='utf-8') as f:
                    info['dependencies'][file] = f.read()

        return info
