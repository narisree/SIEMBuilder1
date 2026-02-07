"""
Detection Engineering Module
Handles Sigma rule conversion to Splunk SPL and in-memory testing.

Improvements:
- Proper handling of OR/AND conditions in Sigma rules
- Support for field modifiers: |endswith, |startswith, |contains, |re, |all
- Multiple named selections with condition logic (selection OR selection_cmdline)
- GitHub API rate limit tracking and user feedback
"""

import os
import re
import json
import yaml
import hashlib
import pandas as pd
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime, timezone

# HTTP requests
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

# pySigma imports
try:
    from sigma.rule import SigmaRule
    from sigma.backends.splunk import SplunkBackend
    PYSIGMA_AVAILABLE = True
except ImportError:
    PYSIGMA_AVAILABLE = False


class SigmaDetectionEvaluator:
    """
    Evaluates Sigma detection logic against log events.
    
    Supports:
    - Multiple named selections (selection, selection_cmdline, filter, etc.)
    - Condition logic: OR, AND, NOT, and 1 of X / all of X
    - Field modifiers: |endswith, |startswith, |contains, |re, |all, |base64
    - List values (match any in list)
    - Wildcard matching in string values
    """

    def evaluate(self, df: pd.DataFrame, detection: dict) -> pd.DataFrame:
        """
        Evaluate full Sigma detection block against a DataFrame of events.
        
        Args:
            df: DataFrame of log events
            detection: The 'detection' block from a parsed Sigma rule
            
        Returns:
            DataFrame of matching events
        """
        if df.empty or not detection:
            return pd.DataFrame()

        # Separate condition from named selections
        condition = detection.get("condition", "")
        if not condition:
            # Fallback: if no condition, try to match 'selection'
            if "selection" in detection:
                return self._evaluate_selection(df, detection["selection"])
            return pd.DataFrame()

        # Build named selection masks
        named_masks = {}
        for key, value in detection.items():
            if key == "condition":
                continue
            named_masks[key] = self._evaluate_selection(df, value, return_mask=True)

        # Parse and evaluate the condition expression
        try:
            final_mask = self._evaluate_condition(df, condition, named_masks)
            return df[final_mask].copy()
        except Exception:
            # Fallback: try basic selection matching
            if "selection" in named_masks:
                return df[named_masks["selection"]].copy()
            return pd.DataFrame()

    def _evaluate_condition(
        self, df: pd.DataFrame, condition: str, named_masks: Dict[str, pd.Series]
    ) -> pd.Series:
        """
        Parse and evaluate a Sigma condition string.
        
        Handles patterns like:
        - "selection"
        - "selection or selection_cmdline"
        - "selection and not filter"
        - "1 of selection*"
        - "all of selection*"
        - "(selection1 or selection2) and not filter"
        """
        condition = condition.strip()

        # Handle "1 of <pattern>" and "all of <pattern>"
        one_of_match = re.match(r'^1\s+of\s+(\S+)$', condition, re.IGNORECASE)
        if one_of_match:
            pattern = one_of_match.group(1)
            return self._match_of_pattern(df, pattern, named_masks, mode="any")

        all_of_match = re.match(r'^all\s+of\s+(\S+)$', condition, re.IGNORECASE)
        if all_of_match:
            pattern = all_of_match.group(1)
            return self._match_of_pattern(df, pattern, named_masks, mode="all")

        # Handle "all of them"
        if condition.lower() == "all of them":
            combined = pd.Series([True] * len(df), index=df.index)
            for mask in named_masks.values():
                combined &= mask
            return combined

        # Handle "1 of them"
        if condition.lower() == "1 of them":
            combined = pd.Series([False] * len(df), index=df.index)
            for mask in named_masks.values():
                combined |= mask
            return combined

        # Tokenize and evaluate boolean expression
        return self._eval_bool_expr(df, condition, named_masks)

    def _match_of_pattern(
        self, df: pd.DataFrame, pattern: str, named_masks: Dict[str, pd.Series], mode: str
    ) -> pd.Series:
        """Handle '1 of selection*' or 'all of filter*' patterns."""
        if pattern.endswith("*"):
            prefix = pattern[:-1]
            matching = {k: v for k, v in named_masks.items() if k.startswith(prefix)}
        elif pattern == "them":
            matching = named_masks
        else:
            matching = {pattern: named_masks[pattern]} if pattern in named_masks else {}

        if not matching:
            return pd.Series([False] * len(df), index=df.index)

        if mode == "any":
            combined = pd.Series([False] * len(df), index=df.index)
            for mask in matching.values():
                combined |= mask
            return combined
        else:  # "all"
            combined = pd.Series([True] * len(df), index=df.index)
            for mask in matching.values():
                combined &= mask
            return combined

    def _eval_bool_expr(
        self, df: pd.DataFrame, condition: str, named_masks: Dict[str, pd.Series]
    ) -> pd.Series:
        """
        Evaluate a boolean expression like:
        "selection or selection_cmdline"
        "selection and not filter"
        "(selection1 or selection2) and not filter"
        """
        # Simple recursive descent parser for: AND, OR, NOT, parentheses, identifiers

        tokens = self._tokenize_condition(condition)
        pos = [0]  # mutable index

        def parse_or() -> pd.Series:
            left = parse_and()
            while pos[0] < len(tokens) and tokens[pos[0]].lower() == "or":
                pos[0] += 1
                right = parse_and()
                left = left | right
            return left

        def parse_and() -> pd.Series:
            left = parse_not()
            while pos[0] < len(tokens) and tokens[pos[0]].lower() == "and":
                pos[0] += 1
                right = parse_not()
                left = left & right
            return left

        def parse_not() -> pd.Series:
            if pos[0] < len(tokens) and tokens[pos[0]].lower() == "not":
                pos[0] += 1
                operand = parse_primary()
                return ~operand
            return parse_primary()

        def parse_primary() -> pd.Series:
            if pos[0] < len(tokens) and tokens[pos[0]] == "(":
                pos[0] += 1  # skip (
                result = parse_or()
                if pos[0] < len(tokens) and tokens[pos[0]] == ")":
                    pos[0] += 1  # skip )
                return result
            elif pos[0] < len(tokens):
                name = tokens[pos[0]]
                pos[0] += 1
                if name in named_masks:
                    return named_masks[name]
                else:
                    # Unknown identifier — treat as all False
                    return pd.Series([False] * len(df), index=df.index)
            return pd.Series([False] * len(df), index=df.index)

        return parse_or()

    def _tokenize_condition(self, condition: str) -> List[str]:
        """Tokenize a condition string into tokens."""
        # Split on whitespace but preserve parentheses as separate tokens
        raw = condition.replace("(", " ( ").replace(")", " ) ")
        return [t for t in raw.split() if t]

    def _evaluate_selection(
        self, df: pd.DataFrame, selection: Any, return_mask: bool = False
    ) -> Any:
        """
        Evaluate a single named selection against the DataFrame.
        
        A selection can be:
        - dict: field conditions (AND logic within a selection)
        - list of dicts: OR logic between dicts
        """
        if isinstance(selection, dict):
            mask = self._eval_selection_dict(df, selection)
        elif isinstance(selection, list):
            # List of dicts = OR between them
            mask = pd.Series([False] * len(df), index=df.index)
            for item in selection:
                if isinstance(item, dict):
                    mask |= self._eval_selection_dict(df, item)
                elif isinstance(item, str):
                    # String values in a list (unlikely but handle gracefully)
                    pass
        else:
            mask = pd.Series([False] * len(df), index=df.index)

        if return_mask:
            return mask
        return df[mask].copy()

    def _eval_selection_dict(self, df: pd.DataFrame, selection: dict) -> pd.Series:
        """Evaluate a selection dictionary (all conditions AND'd together)."""
        mask = pd.Series([True] * len(df), index=df.index)

        for field_expr, value in selection.items():
            field_mask = self._match_field(df, field_expr, value)
            mask &= field_mask

        return mask

    def _match_field(self, df: pd.DataFrame, field_expr: str, value: Any) -> pd.Series:
        """
        Match a field expression against DataFrame column values.
        
        Handles field modifiers:
        - Image|endswith: '\\mimikatz.exe'
        - CommandLine|contains: ['sekurlsa', 'logonpasswords']
        - CommandLine|startswith: 'C:\\Temp'
        - FieldName|re: 'regex_pattern'
        - FieldName|all: ['val1', 'val2'] (all must match)
        - FieldName|base64offset: value
        """
        # Parse field name and modifier
        if "|" in field_expr:
            parts = field_expr.split("|", 1)
            field_name = parts[0].strip()
            modifier = parts[1].strip().lower()
        else:
            field_name = field_expr.strip()
            modifier = None

        # Check if field exists in DataFrame
        if field_name not in df.columns:
            return pd.Series([False] * len(df), index=df.index)

        col = df[field_name].astype(str)

        # Normalize value to list for uniform handling
        if isinstance(value, list):
            values = value
        else:
            values = [value]

        # Apply modifier logic
        if modifier == "endswith":
            return self._match_any(col, values, lambda c, v: c.str.endswith(str(v), na=False))

        elif modifier == "startswith":
            return self._match_any(col, values, lambda c, v: c.str.startswith(str(v), na=False))

        elif modifier == "contains":
            if modifier == "contains" and field_expr.endswith("|all"):
                # |contains|all — all values must be present
                return self._match_all(col, values, lambda c, v: c.str.contains(str(v), case=False, na=False, regex=False))
            return self._match_any(col, values, lambda c, v: c.str.contains(str(v), case=False, na=False, regex=False))

        elif modifier == "re":
            return self._match_any(col, values, lambda c, v: c.str.contains(str(v), case=False, na=False, regex=True))

        elif modifier == "all":
            # All values must match (exact)
            return self._match_all(col, values, lambda c, v: c == str(v))

        elif modifier in ("base64", "base64offset"):
            # Simplified: just do contains for the plain text value
            return self._match_any(col, values, lambda c, v: c.str.contains(str(v), case=False, na=False, regex=False))

        else:
            # No modifier — exact match or wildcard
            return self._match_any(col, values, self._wildcard_match)

    def _match_any(self, col: pd.Series, values: list, match_fn) -> pd.Series:
        """Match if ANY value in the list matches (OR logic)."""
        combined = pd.Series([False] * len(col), index=col.index)
        for v in values:
            combined |= match_fn(col, v)
        return combined

    def _match_all(self, col: pd.Series, values: list, match_fn) -> pd.Series:
        """Match if ALL values in the list match (AND logic)."""
        combined = pd.Series([True] * len(col), index=col.index)
        for v in values:
            combined &= match_fn(col, v)
        return combined

    def _wildcard_match(self, col: pd.Series, value: Any) -> pd.Series:
        """Match a value with wildcard support (* at start/end)."""
        val_str = str(value)

        if val_str == "*":
            # Match anything non-empty
            return col.str.len() > 0

        if val_str.startswith("*") and val_str.endswith("*"):
            pattern = val_str.strip("*")
            return col.str.contains(pattern, case=False, na=False, regex=False)
        elif val_str.endswith("*"):
            pattern = val_str.rstrip("*")
            return col.str.startswith(pattern, na=False)
        elif val_str.startswith("*"):
            pattern = val_str.lstrip("*")
            return col.str.endswith(pattern, na=False)
        else:
            # Exact match (case-insensitive for strings)
            return col.str.lower() == val_str.lower()


class DetectionEngine:
    """Handles Sigma rule conversion and testing."""
    
    # Mapping of SIEMBuilder sources to SigmaHQ GitHub paths
    SIGMA_SOURCE_MAPPING = {
        "palo_alto": ["network/firewall"],
        "windows_events": ["windows/process_creation", "windows/powershell", "windows/registry"],
        "linux": ["linux/auditd", "linux/builtin"],
        "azure_ad": ["cloud/azure"],
        "cisco_asa": ["network/firewall"],
        "checkpoint": ["network/firewall"],
        "crowdstrike_edr": ["windows/process_creation", "windows/powershell"],
        "o365": ["cloud/m365"],
        "proofpoint": ["proxy"],
        "zscaler_proxy": ["proxy"]
    }
    
    GITHUB_API_BASE = "https://api.github.com/repos/SigmaHQ/sigma/contents/rules"
    
    def __init__(self, rules_dir: str = "data/sigma_rules"):
        """Initialize Detection Engine with rules directory."""
        self.rules_dir = Path(rules_dir)
        self.rules_dir.mkdir(parents=True, exist_ok=True)
        self._evaluator = SigmaDetectionEvaluator()
    
    def convert_sigma_to_spl(self, sigma_rule: str) -> dict:
        """
        Convert Sigma rule (YAML) to Splunk SPL query.
        
        Args:
            sigma_rule: Sigma rule in YAML format
            
        Returns:
            dict with success, spl_query, and error
        """
        if not PYSIGMA_AVAILABLE:
            return {
                "success": False,
                "spl_query": "",
                "error": "pySigma libraries not installed. Run: pip install pysigma pysigma-backend-splunk"
            }
        
        try:
            rule = SigmaRule.from_yaml(sigma_rule)
            backend = SplunkBackend()
            spl_queries = backend.convert_rule(rule)
            
            if isinstance(spl_queries, list):
                spl_query = "\n\n".join(spl_queries)
            else:
                spl_query = str(spl_queries)
            
            return {
                "success": True,
                "spl_query": spl_query,
                "error": ""
            }
            
        except yaml.YAMLError as e:
            return {
                "success": False,
                "spl_query": "",
                "error": f"Invalid YAML syntax: {str(e)}"
            }
        except Exception as e:
            return {
                "success": False,
                "spl_query": "",
                "error": f"Conversion failed: {str(e)}"
            }
    
    def test_sigma_rule(self, sigma_rule: str, test_logs: str) -> dict:
        """
        Test Sigma rule against synthetic logs using the improved evaluator.
        
        Args:
            sigma_rule: Sigma rule in YAML format
            test_logs: JSON array of log events as string
            
        Returns:
            dict with success, matches (DataFrame), count, and error
        """
        try:
            # Parse test logs
            try:
                logs = json.loads(test_logs)
                if not isinstance(logs, list):
                    logs = [logs]
            except json.JSONDecodeError as e:
                return {
                    "success": False,
                    "matches": pd.DataFrame(),
                    "count": 0,
                    "error": f"Invalid JSON format: {str(e)}"
                }
            
            df = pd.DataFrame(logs)
            
            if df.empty:
                return {
                    "success": False,
                    "matches": pd.DataFrame(),
                    "count": 0,
                    "error": "No log data provided"
                }
            
            # Parse Sigma rule to extract detection logic
            try:
                rule_data = yaml.safe_load(sigma_rule)
                detection = rule_data.get("detection", {})
            except yaml.YAMLError as e:
                return {
                    "success": False,
                    "matches": pd.DataFrame(),
                    "count": 0,
                    "error": f"Invalid Sigma rule YAML: {str(e)}"
                }
            
            if not detection:
                return {
                    "success": False,
                    "matches": pd.DataFrame(),
                    "count": 0,
                    "error": "No 'detection' block found in Sigma rule"
                }
            
            # Use the improved evaluator
            matches = self._evaluator.evaluate(df, detection)
            
            return {
                "success": True,
                "matches": matches,
                "count": len(matches),
                "error": ""
            }
            
        except Exception as e:
            return {
                "success": False,
                "matches": pd.DataFrame(),
                "count": 0,
                "error": f"Testing failed: {str(e)}"
            }
    
    def get_rules_for_source(self, source_id: str) -> List[dict]:
        """
        Get available Sigma rules for a specific log source.
        
        Args:
            source_id: Source identifier (e.g., 'windows_events')
            
        Returns:
            List of rule dictionaries with metadata
        """
        source_dir = self.rules_dir / source_id
        if not source_dir.exists():
            return []
        
        rules = []
        for rule_file in source_dir.glob("*.yml"):
            try:
                with open(rule_file, 'r', encoding='utf-8') as f:
                    rule_yaml = f.read()
                    rule_data = yaml.safe_load(rule_yaml)
                
                rules.append({
                    "filename": rule_file.name,
                    "title": rule_data.get("title", rule_file.stem),
                    "description": rule_data.get("description", "No description"),
                    "rule_yaml": rule_yaml,
                    "mitre_tags": [tag for tag in rule_data.get("tags", []) if tag.startswith("attack.")],
                    "status": rule_data.get("status", "unknown"),
                    "level": rule_data.get("level", "medium")
                })
            except Exception:
                continue
        
        return rules
    
    def get_test_logs_for_rule(self, source_id: str, rule_filename: str) -> str:
        """
        Get test logs for a specific rule.
        
        Args:
            source_id: Source identifier
            rule_filename: Name of the rule file
            
        Returns:
            JSON string of test logs
        """
        test_logs_dir = self.rules_dir / source_id / "test_logs"
        if not test_logs_dir.exists():
            return "[]"
        
        rule_name = Path(rule_filename).stem
        test_log_file = test_logs_dir / f"{rule_name}.json"
        
        if test_log_file.exists():
            try:
                with open(test_log_file, 'r', encoding='utf-8') as f:
                    return f.read()
            except Exception:
                pass
        
        return "[]"
    
    def download_rules_from_github(self, source_id: str, max_rules_per_path: int = 7) -> dict:
        """
        Download Sigma rules from SigmaHQ GitHub repository.
        Includes rate limit tracking and user-friendly error messages.
        
        Args:
            source_id: Source identifier
            max_rules_per_path: Maximum rules to download per path
            
        Returns:
            dict with success, counts, rate limit info, and rule lists
        """
        if not REQUESTS_AVAILABLE:
            return {
                "success": False,
                "error": "requests library not installed. Run: pip install requests",
                "downloaded_count": 0,
                "skipped_count": 0,
                "updated_count": 0
            }

        if source_id not in self.SIGMA_SOURCE_MAPPING:
            return {
                "success": False,
                "error": f"Unknown source: {source_id}",
                "downloaded_count": 0,
                "skipped_count": 0,
                "updated_count": 0
            }
        
        github_paths = self.SIGMA_SOURCE_MAPPING[source_id]
        downloaded = []
        skipped = []
        updated = []
        
        # Track rate limit across requests
        rate_limit_remaining = None
        rate_limit_reset = None
        rate_limited = False
        
        for path in github_paths:
            try:
                url = f"{self.GITHUB_API_BASE}/{path}"
                headers = {
                    "Accept": "application/vnd.github.v3+json",
                    "User-Agent": "SIEMBuilder-App"  # GitHub requires User-Agent
                }
                
                response = requests.get(url, headers=headers, timeout=15)
                
                # --- Extract rate limit headers ---
                rate_limit_remaining = int(response.headers.get("X-RateLimit-Remaining", -1))
                reset_epoch = response.headers.get("X-RateLimit-Reset")
                if reset_epoch:
                    try:
                        rate_limit_reset = datetime.fromtimestamp(
                            int(reset_epoch), tz=timezone.utc
                        ).strftime("%H:%M:%S UTC")
                    except (ValueError, OSError):
                        rate_limit_reset = "unknown"
                
                # Check for rate limiting
                if response.status_code == 403:
                    rate_limited = True
                    return {
                        "success": False,
                        "error": "GitHub API rate limit exceeded",
                        "rate_limited": True,
                        "rate_limit_remaining": 0,
                        "rate_limit_reset": rate_limit_reset or "~1 hour",
                        "downloaded_count": len(downloaded),
                        "skipped_count": len(skipped),
                        "updated_count": len(updated),
                        "new_rules": downloaded,
                        "skipped_rules": skipped,
                        "updated_rules": updated,
                    }
                
                response.raise_for_status()
                files = response.json()
                
                # Check if we got a list (directory) or a dict (error/file)
                if not isinstance(files, list):
                    continue
                
                rule_count = 0
                
                for item in files:
                    if rule_count >= max_rules_per_path:
                        break
                    
                    if item.get("type") != "file" or not item.get("name", "").endswith(".yml"):
                        continue
                    
                    save_path = self.rules_dir / source_id / item["name"]
                    
                    # Check if file already exists with same hash
                    if save_path.exists():
                        with open(save_path, "rb") as f:
                            local_hash = hashlib.sha1(f.read()).hexdigest()
                        
                        if local_hash == item.get("sha", ""):
                            skipped.append(item["name"])
                            continue
                    
                    # Download file
                    download_url = item.get("download_url")
                    if not download_url:
                        continue
                    
                    file_response = requests.get(download_url, timeout=10)
                    file_response.raise_for_status()
                    
                    # Validate YAML
                    try:
                        rule_data = yaml.safe_load(file_response.text)
                        status = rule_data.get("status", "")
                        
                        if status in ["stable", "test"]:
                            save_path.parent.mkdir(parents=True, exist_ok=True)
                            
                            was_existing = save_path.exists()
                            
                            with open(save_path, "w", encoding="utf-8") as f:
                                f.write(file_response.text)
                            
                            if was_existing:
                                updated.append(item["name"])
                            else:
                                downloaded.append(item["name"])
                            rule_count += 1
                    except yaml.YAMLError:
                        continue
                        
            except requests.exceptions.Timeout:
                continue
            except requests.exceptions.RequestException:
                continue
        
        return {
            "success": True,
            "downloaded_count": len(downloaded),
            "skipped_count": len(skipped),
            "updated_count": len(updated),
            "new_rules": downloaded,
            "skipped_rules": skipped,
            "updated_rules": updated,
            "rate_limited": rate_limited,
            "rate_limit_remaining": rate_limit_remaining,
            "rate_limit_reset": rate_limit_reset,
            "error": ""
        }
