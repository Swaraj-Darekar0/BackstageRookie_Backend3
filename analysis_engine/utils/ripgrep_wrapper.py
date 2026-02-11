import subprocess
import json
import logging
import os
from typing import List, Dict, Optional

logger = logging.getLogger(__name__)

class RipGrep:
    """
    A wrapper around the `rg` (ripgrep) command-line tool to perform
    structured searches within a repository.
    Assumes `rg` is installed and available in the system's PATH.
    """

    def __init__(self, repo_path: str):
        if not os.path.isdir(repo_path):
            raise ValueError(f"Repository path '{repo_path}' is not a valid directory.")
        self.repo_path = repo_path
        self._check_ripgrep_installed()

    def _check_ripgrep_installed(self):
        try:
            subprocess.run(['rg', '--version'], capture_output=True, check=True)
        except (subprocess.CalledProcessError, FileNotFoundError):
            raise RuntimeError(
                "`rg` (ripgrep) not found. Please install ripgrep: "
                "https://github.com/BurntSushi/ripgrep#installation"
            )

    def search(
               self, 
               pattern: str,
               file_type: Optional[str] = None,
               context_lines: int = 5,
               max_results: int = 20) -> List[Dict]:
        """
        Searches for a pattern in the repository and returns structured results
        with surrounding context lines.

        Args:
            pattern (str): The regex pattern to search for.
            file_type (str, optional): Restrict search to specific file types (e.g., 'js', 'py').
            context_lines (int): Number of lines before and after the match to include.
            max_results (int): Maximum number of matches to return.

        Returns:
            List[Dict]: A list of dictionaries, each representing a match.
                        Example: {
                            'file_path': 'src/main.js',
                            'line_number': 15,
                            'line_content': '  vulnerableFunc(user_input);',
                            'context_before': [...],
                            'context_after': [...],
                            'match': 'vulnerableFunc'
                        }
        """
        cmd = [
            'rg',
            '--json',                   # Output results as JSON
            '--context', str(context_lines), # Include context lines
            '--max-count', str(max_results), # Limit number of results
            pattern,
            self.repo_path
        ]
        if file_type:
            cmd.extend(['-t', file_type])

        logger.debug(f"Running ripgrep command: {' '.join(cmd)}")

        try:
            process = subprocess.run(cmd, capture_output=True, text=True, check=True, encoding='utf-8')
        except subprocess.CalledProcessError as e:
            # rg exits with 1 if no matches, but 2 if error. Only raise on 2.
            if e.returncode == 1:
                logger.debug(f"No matches found for pattern '{pattern}'.")
                return []
            logger.error(f"ripgrep command failed with error: {e.stderr}", exc_info=True)
            raise RuntimeError(f"ripgrep error: {e.stderr}")
        except Exception as e:
            logger.error(f"Failed to run ripgrep: {e}", exc_info=True)
            raise

        results = []
        current_match_data = None
        for line in process.stdout.splitlines():
            try:
                json_data = json.loads(line)
                
                if json_data['type'] == 'begin':
                    current_match_data = {'file_path': os.path.relpath(json_data['data']['path']['text'], self.repo_path), 'context_before': [], 'context_after': []}
                elif json_data['type'] == 'match' and current_match_data:
                    current_match_data['line_number'] = json_data['data']['line_number']
                    current_match_data['line_content'] = json_data['data']['lines']['text'].strip()
                    current_match_data['match'] = pattern # For simplicity, store the pattern as match
                    # Add match to the results list and reset for next begin
                    results.append(current_match_data)
                    current_match_data = None # Reset to wait for next 'begin'
                elif json_data['type'] == 'context' and current_match_data:
                    if json_data['data']['submatches'][0]['start'] < json_data['data']['lines']['text'].strip().find(pattern): # This heuristic might be wrong without pattern matching logic
                        current_match_data['context_before'].append(json_data['data']['lines']['text'].strip())
                    else:
                        current_match_data['context_after'].append(json_data['data']['lines']['text'].strip())
                elif json_data['type'] == 'end':
                    # Should ideally have a match data here, but handle cases where match might be filtered
                    if current_match_data and 'line_number' in current_match_data: # Ensure it's a full match block
                        results.append(current_match_data)
                    current_match_data = None
                
            except json.JSONDecodeError:
                logger.warning(f"Failed to decode JSON line from ripgrep: {line}")
            except Exception as e:
                logger.error(f"Error processing ripgrep JSON output line: {line} - {e}", exc_info=True)
        
        # Rigrep outputs results stream, a 'match' event always follows a 'begin' event for actual matches.
        # The logic for accumulating context_before/after for a specific match from the raw rg --json stream is complex.
        # A simpler approach for the scope of this task is to extract only file_path, line_number and content,
        # and then re-read files for the context directly.
        # Let's simplify the parsing for now to just get file, line, and the match line itself.
        
        simplified_results = []
        for line in process.stdout.splitlines():
            try:
                json_data = json.loads(line)
                if json_data['type'] == 'match':
                    simplified_results.append({
                        'file_path': os.path.relpath(json_data['data']['path']['text'], self.repo_path),
                        'line_number': json_data['data']['line_number'],
                        'line_content': json_data['data']['lines']['text'].strip(),
                        'match_text': pattern # We'll re-read for context later
                    })
            except json.JSONDecodeError:
                pass # Ignore non-json lines or malformed lines
        
        # Now, for each simplified result, re-read the file to get N lines of context
        final_results = []
        for res in simplified_results:
            file_abs_path = os.path.join(self.repo_path, res['file_path'])
            try:
                with open(file_abs_path, 'r', encoding='utf-8', errors='ignore') as f:
                    lines = f.readlines()
                
                start_line_idx = max(0, res['line_number'] - 1 - context_lines)
                end_line_idx = min(len(lines), res['line_number'] + context_lines)
                
                context_snippet_lines = []
                for i in range(start_line_idx, end_line_idx):
                    line_prefix = f"{i + 1}: "
                    if i + 1 == res['line_number']:
                        context_snippet_lines.append(f"> {line_prefix}{lines[i].strip()}") # Mark the actual match line
                    else:
                        context_snippet_lines.append(f"  {line_prefix}{lines[i].strip()}")
                
                res['context_snippet'] = "\n".join(context_snippet_lines)
                final_results.append(res)
                if len(final_results) >= max_results: # Ensure we don't exceed max results after re-reading context
                    break

            except Exception as e:
                logger.warning(f"Could not read context for {res['file_path']}:{res['line_number']}: {e}")
        
        return final_results
