"""
Detection Engineering Module
Handles Sigma rule conversion to Splunk SPL and in-memory testing.
"""

import os
import json
import yaml
import sqlite3
import hashlib
import requests
import pandas as pd
from pathlib import Path
from typing import Dict, List, Optional
from io import StringIO

# pySigma imports
try:
    from sigma.rule import SigmaRule
    from sigma.backends.splunk import SplunkBackend
    from sigma.pipelines.splunk import splunk_windows_pipeline
    PYSIGMA_AVAILABLE = True
except ImportError:
    PYSIGMA_AVAILABLE = False


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
            # Parse Sigma rule
            rule = SigmaRule.from_yaml(sigma_rule)
            
            # Create Splunk backend
            backend = SplunkBackend()
            
            # Convert to SPL
            spl_queries = backend.convert_rule(rule)
            
            # Join multiple queries if present
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
        Test Sigma rule against synthetic logs using in-memory SQLite.
        
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
            
            # Create DataFrame from logs
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
            
            # Simple matching logic (basic implementation)
            # This is a simplified version - full pySigma SQLite backend would be more robust
            matches = self._apply_sigma_detection(df, detection)
            
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
    
    def _apply_sigma_detection(self, df: pd.DataFrame, detection: dict) -> pd.DataFrame:
        """
        Apply Sigma detection logic to DataFrame.
        Simplified implementation for basic field matching.
        """
        if "selection" in detection:
            selection = detection["selection"]
            mask = pd.Series([True] * len(df))
            
            for field, value in selection.items():
                if field in df.columns:
                    if isinstance(value, str):
                        # Handle wildcards and contains
                        if value.startswith("*") and value.endswith("*"):
                            pattern = value.strip("*")
                            mask &= df[field].astype(str).str.contains(pattern, case=False, na=False)
                        elif value.endswith("*"):
                            pattern = value.rstrip("*")
                            mask &= df[field].astype(str).str.startswith(pattern, na=False)
                        elif value.startswith("*"):
                            pattern = value.lstrip("*")
                            mask &= df[field].astype(str).str.endswith(pattern, na=False)
                        else:
                            mask &= df[field] == value
                    elif isinstance(value, list):
                        mask &= df[field].isin(value)
            
            return df[mask]
        
        return pd.DataFrame()
    
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
                
                # Extract metadata
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
            rule_filename: Name of the rule file (e.g., 'mimikatz.yml')
            
        Returns:
            JSON string of test logs
        """
        # Try to find matching test log file
        test_logs_dir = self.rules_dir / source_id / "test_logs"
        if not test_logs_dir.exists():
            return "[]"
        
        # Try with same name but .json extension
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
        
        Args:
            source_id: Source identifier
            max_rules_per_path: Maximum rules to download per path
            
        Returns:
            dict with success, counts, and rule lists
        """
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
        
        for path in github_paths:
            try:
                # Call GitHub API
                url = f"{self.GITHUB_API_BASE}/{path}"
                headers = {"Accept": "application/vnd.github.v3+json"}
                
                response = requests.get(url, headers=headers, timeout=15)
                response.raise_for_status()
                
                files = response.json()
                rule_count = 0
                
                # Filter and download .yml files
                for item in files:
                    if rule_count >= max_rules_per_path:
                        break
                    
                    if item["type"] == "file" and item["name"].endswith(".yml"):
                        save_path = self.rules_dir / source_id / item["name"]
                        
                        # Check if file already exists
                        if save_path.exists():
                            with open(save_path, "rb") as f:
                                local_hash = hashlib.sha1(f.read()).hexdigest()
                            
                            if local_hash == item["sha"]:
                                skipped.append(item["name"])
                                continue
                        
                        # Download file
                        file_response = requests.get(item["download_url"], timeout=10)
                        file_response.raise_for_status()
                        
                        # Validate YAML
                        try:
                            rule_data = yaml.safe_load(file_response.text)
                            status = rule_data.get("status", "")
                            
                            # Only download stable or test rules
                            if status in ["stable", "test"]:
                                save_path.parent.mkdir(parents=True, exist_ok=True)
                                
                                with open(save_path, "w", encoding="utf-8") as f:
                                    f.write(file_response.text)
                                
                                if save_path.exists():
                                    if item["name"] in [s.split("/")[-1] for s in skipped]:
                                        updated.append(item["name"])
                                    else:
                                        downloaded.append(item["name"])
                                    rule_count += 1
                        except yaml.YAMLError:
                            continue
                            
            except requests.exceptions.RequestException as e:
                # Continue with next path even if one fails
                continue
        
        return {
            "success": True,
            "downloaded_count": len(downloaded),
            "skipped_count": len(skipped),
            "updated_count": len(updated),
            "new_rules": downloaded,
            "skipped_rules": skipped,
            "updated_rules": updated,
            "error": ""
        }
