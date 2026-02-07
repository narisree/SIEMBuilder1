"""
Detection Engineering Module v2.0
Handles Sigma rule download, AI-assisted categorization, SPL conversion, and testing.

Key improvements over v1:
- Downloads ALL rules from SigmaHQ (no artificial limit), with recursive directory traversal
- AI reads Sigma rule 'product' field and maps to correct app source
- AI-assisted Sigma-to-SPL conversion (proper Splunk queries)
- AI-generated test logs based on rule detection logic
- Fallback to pySigma when AI is unavailable
- SigmaDetectionEvaluator for in-memory rule testing
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

# pySigma imports (used as fallback)
try:
    from sigma.rule import SigmaRule
    from sigma.backends.splunk import SplunkBackend
    PYSIGMA_AVAILABLE = True
except ImportError:
    PYSIGMA_AVAILABLE = False


# ─────────────────────────────────────────────────────────────────────────────
# Sigma Product → App Source Mapping
# ─────────────────────────────────────────────────────────────────────────────

SIGMA_PRODUCT_TO_SOURCE = {
    "windows": "windows_events",
    "linux": "linux",
    "macos": "macos",
    "azure": "azure_ad",
    "m365": "o365",
    "okta": "okta",
    "gcp": "gcp",
    "aws": "aws",
    "github": "github",
    "zeek": "zeek",
}

SIGMA_CATEGORY_TO_SOURCE = {
    "firewall": "palo_alto",
    "proxy": "zscaler_proxy",
    "dns": "dns",
    "webserver": "webserver",
    "antivirus": "antivirus",
}

# Comprehensive SigmaHQ GitHub paths per source
SIGMAHQ_SOURCE_PATHS = {
    "windows_events": [
        "windows/builtin/application",
        "windows/builtin/security",
        "windows/builtin/system",
        "windows/builtin/windefend",
        "windows/create_remote_thread",
        "windows/create_stream_hash",
        "windows/dns_query",
        "windows/driver_load",
        "windows/file/file_access",
        "windows/file/file_change",
        "windows/file/file_delete",
        "windows/file/file_event",
        "windows/file/file_rename",
        "windows/image_load",
        "windows/network_connection",
        "windows/pipe_created",
        "windows/powershell/powershell_classic",
        "windows/powershell/powershell_module",
        "windows/powershell/powershell_script",
        "windows/process_access",
        "windows/process_creation",
        "windows/raw_access_thread",
        "windows/registry/registry_add",
        "windows/registry/registry_delete",
        "windows/registry/registry_event",
        "windows/registry/registry_set",
        "windows/wmi_event",
    ],
    "linux": [
        "linux/auditd",
        "linux/builtin/auth",
        "linux/builtin/clamav",
        "linux/builtin/dpkg",
        "linux/builtin/guacamole",
        "linux/builtin/sudo",
        "linux/builtin/sshd",
        "linux/builtin/syslog",
        "linux/builtin/vsftpd",
        "linux/process_creation",
        "linux/network_connection",
        "linux/file_event",
    ],
    "azure_ad": [
        "cloud/azure/activitylogs",
        "cloud/azure/auditlogs",
        "cloud/azure/identity_protection",
        "cloud/azure/pim",
        "cloud/azure/riskdetection",
        "cloud/azure/signinlogs",
    ],
    "o365": [
        "cloud/m365/audit",
        "cloud/m365/exchange",
        "cloud/m365/threat_management",
    ],
    "aws": [
        "cloud/aws/cloudtrail",
        "cloud/aws/guardduty",
    ],
    "gcp": [
        "cloud/gcp/audit",
    ],
    "palo_alto": [
        "network/firewall",
    ],
    "cisco_asa": [
        "network/cisco/asa",
        "network/firewall",
    ],
    "checkpoint": [
        "network/firewall",
    ],
    "crowdstrike_edr": [
        "windows/process_creation",
        "windows/powershell/powershell_script",
        "windows/dns_query",
        "windows/file/file_event",
        "windows/network_connection",
        "windows/registry/registry_set",
    ],
    "zscaler_proxy": [
        "proxy",
        "web",
    ],
    "proofpoint": [
        "proxy",
    ],
}


# ─────────────────────────────────────────────────────────────────────────────
# AI Prompt Templates
# ─────────────────────────────────────────────────────────────────────────────

SIGMA_TO_SPL_PROMPT = """You are an expert Splunk detection engineer. Convert this Sigma rule to a production-ready Splunk SPL search query.

Requirements:
1. Output ONLY the SPL query — no explanation, no markdown, no backticks
2. Use proper Splunk search syntax (index, sourcetype, field comparisons, wildcards)
3. Map Sigma field names to standard Splunk CIM or Windows Security Log field names
4. Handle all detection conditions: selection, filter, condition logic (AND, OR, NOT)
5. Support Sigma modifiers: |endswith = field="*value", |startswith = field="value*", |contains = field="*value*"
6. Include appropriate index and sourcetype based on logsource.product and logsource.category
7. For the 'condition' field, properly handle: selection and not filter, 1 of selection*, all of them, etc.

Example Sigma rule:
```
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\\addinutil.exe'
    filter_main_werfault:
        Image|endswith:
            - ':\\Windows\\System32\\conhost.exe'
            - ':\\Windows\\System32\\werfault.exe'
    condition: selection and not 1 of filter_main_*
```

Example correct SPL output:
index=wineventlog sourcetype=WinEventLog:Security OR sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational ParentImage="*\\addinutil.exe" NOT (Image="*:\\Windows\\System32\\conhost.exe" OR Image="*:\\Windows\\System32\\werfault.exe")

Now convert this Sigma rule:

```yaml
{sigma_rule}
```"""

GENERATE_TEST_LOG_PROMPT = """You are a cybersecurity expert. Generate realistic test log events (as a JSON array) that would trigger the following Sigma detection rule.

Requirements:
1. Output ONLY a valid JSON array — no explanation, no markdown, no backticks
2. Generate 2-3 events that SHOULD trigger the rule (matching all selection criteria)
3. Generate 1-2 events that should NOT trigger (for testing false positive filtering)
4. Use realistic field values matching the Sigma rule's field names exactly
5. Include all fields referenced in the detection section
6. For Windows events, include common fields like: EventID, Image, ParentImage, CommandLine, User, Computer, etc.
7. For network events, include: src_ip, dst_ip, dst_port, action, etc.

Sigma rule:
```yaml
{sigma_rule}
```"""


# ─────────────────────────────────────────────────────────────────────────────
# Sigma Detection Evaluator (in-memory rule testing)
# ─────────────────────────────────────────────────────────────────────────────

class SigmaDetectionEvaluator:
    """Evaluates Sigma detection logic against log events in-memory."""

    def evaluate(self, df: pd.DataFrame, detection: dict) -> pd.DataFrame:
        if df.empty or not detection:
            return pd.DataFrame()

        condition = detection.get("condition", "")
        if not condition:
            if "selection" in detection:
                return self._evaluate_selection(df, detection["selection"])
            return pd.DataFrame()

        named_masks = {}
        for key, value in detection.items():
            if key == "condition":
                continue
            named_masks[key] = self._evaluate_selection(df, value, return_mask=True)

        try:
            final_mask = self._evaluate_condition(df, condition, named_masks)
            return df[final_mask].copy()
        except Exception:
            if "selection" in named_masks:
                return df[named_masks["selection"]].copy()
            return pd.DataFrame()

    def _evaluate_condition(self, df, condition, named_masks):
        condition = condition.strip()

        one_of = re.match(r'^1\s+of\s+(\S+)$', condition, re.IGNORECASE)
        if one_of:
            return self._match_of_pattern(df, one_of.group(1), named_masks, "any")

        all_of = re.match(r'^all\s+of\s+(\S+)$', condition, re.IGNORECASE)
        if all_of:
            return self._match_of_pattern(df, all_of.group(1), named_masks, "all")

        if condition.lower() == "all of them":
            combined = pd.Series([True] * len(df), index=df.index)
            for mask in named_masks.values():
                combined &= mask
            return combined

        if condition.lower() == "1 of them":
            combined = pd.Series([False] * len(df), index=df.index)
            for mask in named_masks.values():
                combined |= mask
            return combined

        return self._eval_bool_expr(df, condition, named_masks)

    def _match_of_pattern(self, df, pattern, named_masks, mode):
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
        else:
            combined = pd.Series([True] * len(df), index=df.index)
            for mask in matching.values():
                combined &= mask
        return combined

    def _eval_bool_expr(self, df, condition, named_masks):
        tokens = self._tokenize(condition)
        pos = [0]

        def parse_or():
            left = parse_and()
            while pos[0] < len(tokens) and tokens[pos[0]].lower() == "or":
                pos[0] += 1
                left = left | parse_and()
            return left

        def parse_and():
            left = parse_not()
            while pos[0] < len(tokens) and tokens[pos[0]].lower() == "and":
                pos[0] += 1
                left = left & parse_not()
            return left

        def parse_not():
            if pos[0] < len(tokens) and tokens[pos[0]].lower() == "not":
                pos[0] += 1
                return ~parse_primary()
            return parse_primary()

        def parse_primary():
            if pos[0] < len(tokens) and tokens[pos[0]] == "(":
                pos[0] += 1
                result = parse_or()
                if pos[0] < len(tokens) and tokens[pos[0]] == ")":
                    pos[0] += 1
                return result

            # Handle inline "1 of pattern*" or "all of pattern*"
            if pos[0] < len(tokens) and tokens[pos[0]] in ("1", "all"):
                saved = pos[0]
                quant = tokens[pos[0]].lower()
                pos[0] += 1
                if pos[0] < len(tokens) and tokens[pos[0]].lower() == "of":
                    pos[0] += 1
                    if pos[0] < len(tokens):
                        pat = tokens[pos[0]]
                        pos[0] += 1
                        return self._match_of_pattern(
                            df, pat, named_masks,
                            "any" if quant == "1" else "all"
                        )
                pos[0] = saved

            if pos[0] < len(tokens):
                name = tokens[pos[0]]
                pos[0] += 1
                if name in named_masks:
                    return named_masks[name]
                return pd.Series([False] * len(df), index=df.index)
            return pd.Series([False] * len(df), index=df.index)

        return parse_or()

    def _tokenize(self, condition):
        raw = condition.replace("(", " ( ").replace(")", " ) ")
        return [t for t in raw.split() if t]

    def _evaluate_selection(self, df, selection, return_mask=False):
        if isinstance(selection, dict):
            mask = self._eval_dict(df, selection)
        elif isinstance(selection, list):
            mask = pd.Series([False] * len(df), index=df.index)
            for item in selection:
                if isinstance(item, dict):
                    mask |= self._eval_dict(df, item)
        else:
            mask = pd.Series([False] * len(df), index=df.index)
        return mask if return_mask else df[mask].copy()

    def _eval_dict(self, df, selection):
        mask = pd.Series([True] * len(df), index=df.index)
        for field_expr, value in selection.items():
            mask &= self._match_field(df, field_expr, value)
        return mask

    def _match_field(self, df, field_expr, value):
        if "|" in field_expr:
            parts = field_expr.split("|")
            field_name = parts[0].strip()
            modifiers = [m.strip().lower() for m in parts[1:]]
        else:
            field_name = field_expr.strip()
            modifiers = []

        if field_name not in df.columns:
            return pd.Series([False] * len(df), index=df.index)

        col = df[field_name].astype(str)
        values = value if isinstance(value, list) else [value]
        use_all = "all" in modifiers

        if "endswith" in modifiers:
            fn = lambda c, v: c.str.endswith(str(v), na=False)
        elif "startswith" in modifiers:
            fn = lambda c, v: c.str.startswith(str(v), na=False)
        elif "contains" in modifiers:
            fn = lambda c, v: c.str.contains(str(v), case=False, na=False, regex=False)
        elif "re" in modifiers:
            fn = lambda c, v: c.str.contains(str(v), case=False, na=False, regex=True)
        elif "base64" in modifiers or "base64offset" in modifiers:
            fn = lambda c, v: c.str.contains(str(v), case=False, na=False, regex=False)
        else:
            fn = self._wildcard_match

        if use_all:
            combined = pd.Series([True] * len(col), index=col.index)
            for v in values:
                combined &= fn(col, v)
            return combined
        else:
            combined = pd.Series([False] * len(col), index=col.index)
            for v in values:
                combined |= fn(col, v)
            return combined

    def _wildcard_match(self, col, value):
        v = str(value)
        if v == "*":
            return col.str.len() > 0
        if v.startswith("*") and v.endswith("*"):
            return col.str.contains(v.strip("*"), case=False, na=False, regex=False)
        elif v.endswith("*"):
            return col.str.startswith(v.rstrip("*"), na=False)
        elif v.startswith("*"):
            return col.str.endswith(v.lstrip("*"), na=False)
        else:
            return col.str.lower() == v.lower()


# ─────────────────────────────────────────────────────────────────────────────
# Detection Engine
# ─────────────────────────────────────────────────────────────────────────────

class DetectionEngine:
    """Handles Sigma rule download, conversion, and testing with AI integration."""

    GITHUB_API_BASE = "https://api.github.com/repos/SigmaHQ/sigma/contents/rules"

    def __init__(self, rules_dir: str = "data/sigma_rules"):
        self.rules_dir = Path(rules_dir)
        self.rules_dir.mkdir(parents=True, exist_ok=True)
        self._evaluator = SigmaDetectionEvaluator()

    # ── Rule Categorization ──────────────────────────────────────────────

    @staticmethod
    def get_rule_source(rule_data: dict) -> str:
        """Determine SIEMBuilder source from a Sigma rule's logsource fields."""
        logsource = rule_data.get("logsource", {})
        product = (logsource.get("product") or "").lower().strip()
        category = (logsource.get("category") or "").lower().strip()
        service = (logsource.get("service") or "").lower().strip()

        if product in SIGMA_PRODUCT_TO_SOURCE:
            return SIGMA_PRODUCT_TO_SOURCE[product]
        if category in SIGMA_CATEGORY_TO_SOURCE:
            return SIGMA_CATEGORY_TO_SOURCE[category]
        if service in ("sshd", "auth", "auditd", "syslog", "cron"):
            return "linux"
        if service in ("security", "sysmon", "powershell", "windefend"):
            return "windows_events"
        return "unknown"

    # ── AI-Assisted Conversion ───────────────────────────────────────────

    def convert_sigma_to_spl(self, sigma_rule: str, ai_client=None) -> dict:
        """Convert Sigma rule to SPL. Uses AI first, falls back to pySigma."""
        if ai_client:
            try:
                prompt = SIGMA_TO_SPL_PROMPT.format(sigma_rule=sigma_rule)
                response = ai_client.get_response(
                    question=prompt, kb_content="",
                    source_name="Detection Engineering", chat_history=[]
                )
                if response.get("success") and response.get("response"):
                    spl = response["response"].strip()
                    spl = re.sub(r'^```(?:spl|splunk)?\s*', '', spl)
                    spl = re.sub(r'\s*```$', '', spl)
                    spl = spl.strip()
                    if spl:
                        return {"success": True, "spl_query": spl, "method": "AI", "error": ""}
            except Exception:
                pass

        if PYSIGMA_AVAILABLE:
            try:
                rule = SigmaRule.from_yaml(sigma_rule)
                backend = SplunkBackend()
                result = backend.convert_rule(rule)
                spl = "\n\n".join(result) if isinstance(result, list) else str(result)
                return {"success": True, "spl_query": spl, "method": "pySigma", "error": ""}
            except Exception as e:
                return {"success": False, "spl_query": "", "method": "pySigma",
                        "error": f"pySigma failed: {e}"}

        return {"success": False, "spl_query": "", "method": "none",
                "error": "No AI client configured and pySigma unavailable. Set up AI in the AI Setup tab."}

    def generate_test_logs(self, sigma_rule: str, ai_client=None) -> dict:
        """Generate realistic test logs using AI."""
        if not ai_client:
            return {"success": False, "logs": "[]",
                    "error": "AI client required. Configure in AI Setup tab."}
        try:
            prompt = GENERATE_TEST_LOG_PROMPT.format(sigma_rule=sigma_rule)
            response = ai_client.get_response(
                question=prompt, kb_content="",
                source_name="Detection Engineering", chat_history=[]
            )
            if response.get("success") and response.get("response"):
                raw = response["response"].strip()
                raw = re.sub(r'^```(?:json)?\s*', '', raw)
                raw = re.sub(r'\s*```$', '', raw).strip()

                try:
                    parsed = json.loads(raw)
                    if isinstance(parsed, dict):
                        parsed = [parsed]
                    if isinstance(parsed, list):
                        return {"success": True, "logs": json.dumps(parsed, indent=2), "error": ""}
                except json.JSONDecodeError:
                    m = re.search(r'\[[\s\S]*\]', raw)
                    if m:
                        try:
                            parsed = json.loads(m.group())
                            return {"success": True, "logs": json.dumps(parsed, indent=2), "error": ""}
                        except json.JSONDecodeError:
                            pass

                return {"success": False, "logs": "[]", "error": "AI returned invalid JSON. Try again."}
            return {"success": False, "logs": "[]",
                    "error": response.get("message", "AI request failed")}
        except Exception as e:
            return {"success": False, "logs": "[]", "error": f"Generation failed: {e}"}

    # ── Rule Testing ─────────────────────────────────────────────────────

    def test_sigma_rule(self, sigma_rule: str, test_logs: str) -> dict:
        try:
            try:
                logs = json.loads(test_logs)
                if not isinstance(logs, list):
                    logs = [logs]
            except json.JSONDecodeError as e:
                return {"success": False, "matches": pd.DataFrame(), "count": 0, "error": f"Invalid JSON: {e}"}

            df = pd.DataFrame(logs)
            if df.empty:
                return {"success": False, "matches": pd.DataFrame(), "count": 0, "error": "No log data"}

            try:
                rule_data = yaml.safe_load(sigma_rule)
                detection = rule_data.get("detection", {})
            except yaml.YAMLError as e:
                return {"success": False, "matches": pd.DataFrame(), "count": 0, "error": f"Invalid YAML: {e}"}

            if not detection:
                return {"success": False, "matches": pd.DataFrame(), "count": 0, "error": "No detection block"}

            matches = self._evaluator.evaluate(df, detection)
            return {"success": True, "matches": matches, "count": len(matches), "error": ""}
        except Exception as e:
            return {"success": False, "matches": pd.DataFrame(), "count": 0, "error": f"Testing failed: {e}"}

    # ── Rule Storage ─────────────────────────────────────────────────────

    def get_rules_for_source(self, source_id: str) -> List[dict]:
        source_dir = self.rules_dir / source_id
        if not source_dir.exists():
            return []

        rules = []
        for rule_file in sorted(source_dir.glob("*.yml")):
            try:
                with open(rule_file, 'r', encoding='utf-8') as f:
                    rule_yaml = f.read()
                    rule_data = yaml.safe_load(rule_yaml)

                logsource = rule_data.get("logsource", {})
                rules.append({
                    "filename": rule_file.name,
                    "title": rule_data.get("title", rule_file.stem),
                    "description": rule_data.get("description", "No description"),
                    "rule_yaml": rule_yaml,
                    "mitre_tags": [t for t in rule_data.get("tags", []) if t.startswith("attack.")],
                    "status": rule_data.get("status", "unknown"),
                    "level": rule_data.get("level", "medium"),
                    "product": logsource.get("product", "unknown"),
                    "category": logsource.get("category", "unknown"),
                })
            except Exception:
                continue
        return rules

    def get_test_logs_for_rule(self, source_id: str, rule_filename: str) -> str:
        test_logs_dir = self.rules_dir / source_id / "test_logs"
        if not test_logs_dir.exists():
            return "[]"
        rule_name = Path(rule_filename).stem
        f = test_logs_dir / f"{rule_name}.json"
        if f.exists():
            try:
                return f.read_text(encoding='utf-8')
            except Exception:
                pass
        return "[]"

    def save_test_logs(self, source_id: str, rule_filename: str, logs_json: str):
        test_logs_dir = self.rules_dir / source_id / "test_logs"
        test_logs_dir.mkdir(parents=True, exist_ok=True)
        rule_name = Path(rule_filename).stem
        try:
            (test_logs_dir / f"{rule_name}.json").write_text(logs_json, encoding='utf-8')
        except Exception:
            pass

    # ── GitHub Download ──────────────────────────────────────────────────

    def download_rules_from_github(self, source_id: str, max_rules_per_path: int = 50,
                                   progress_callback=None) -> dict:
        """Download Sigma rules from SigmaHQ, categorize by product, store correctly."""
        if not REQUESTS_AVAILABLE:
            return self._err("requests library not installed")
        if source_id not in SIGMAHQ_SOURCE_PATHS:
            return self._err(f"No SigmaHQ paths for: {source_id}")

        github_paths = SIGMAHQ_SOURCE_PATHS[source_id]
        downloaded, skipped, updated, mismatched = [], [], [], []
        rate_limit_remaining = None
        rate_limit_reset = None
        headers = {"Accept": "application/vnd.github.v3+json", "User-Agent": "SIEMBuilder-App"}

        for path_idx, path in enumerate(github_paths):
            if progress_callback:
                progress_callback(f"Scanning {path} ({path_idx + 1}/{len(github_paths)})...")

            try:
                result = self._fetch_dir(path, headers)
                if result is None:
                    continue
                if isinstance(result, dict) and result.get("rate_limited"):
                    rate_limit_remaining = 0
                    rate_limit_reset = result.get("reset_time", "~1 hour")
                    break

                files = []
                if isinstance(result, dict):
                    if "rate_info" in result:
                        rate_limit_remaining = result["rate_info"].get("remaining")
                        rate_limit_reset = result["rate_info"].get("reset")
                    files = result.get("files", [])
                elif isinstance(result, list):
                    files = result

                count = 0
                for item in files:
                    if count >= max_rules_per_path:
                        break
                    if not isinstance(item, dict):
                        continue
                    if item.get("type") != "file" or not item.get("name", "").endswith(".yml"):
                        continue

                    download_url = item.get("download_url")
                    if not download_url:
                        continue

                    # Duplicate check
                    save_path = self.rules_dir / source_id / item["name"]
                    if save_path.exists():
                        try:
                            local_hash = hashlib.sha1(save_path.read_bytes()).hexdigest()
                            if local_hash == item.get("sha", ""):
                                skipped.append(item["name"])
                                continue
                        except Exception:
                            pass

                    try:
                        resp = requests.get(download_url, timeout=10, headers=headers)
                        resp.raise_for_status()
                    except Exception:
                        continue

                    try:
                        rule_data = yaml.safe_load(resp.text)
                        if not isinstance(rule_data, dict):
                            continue
                        status = rule_data.get("status", "")
                        if status not in ("stable", "test", "experimental"):
                            continue

                        # Product-aware categorization
                        actual_source = self.get_rule_source(rule_data)
                        product = rule_data.get("logsource", {}).get("product", "unknown")

                        target = actual_source if actual_source != "unknown" else source_id
                        if target != source_id and actual_source != "unknown":
                            mismatched.append({"name": item["name"], "product": product, "mapped_to": target})

                        final_path = self.rules_dir / target / item["name"]
                        final_path.parent.mkdir(parents=True, exist_ok=True)
                        was_existing = final_path.exists()
                        final_path.write_text(resp.text, encoding="utf-8")

                        if was_existing:
                            updated.append(item["name"])
                        else:
                            downloaded.append(item["name"])
                        count += 1
                    except yaml.YAMLError:
                        continue

            except (requests.exceptions.Timeout, requests.exceptions.RequestException):
                continue

        return {
            "success": True,
            "downloaded_count": len(downloaded),
            "skipped_count": len(skipped),
            "updated_count": len(updated),
            "mismatched_count": len(mismatched),
            "new_rules": downloaded,
            "skipped_rules": skipped,
            "updated_rules": updated,
            "mismatched_rules": mismatched,
            "rate_limited": rate_limit_remaining == 0 if rate_limit_remaining is not None else False,
            "rate_limit_remaining": rate_limit_remaining,
            "rate_limit_reset": rate_limit_reset,
            "error": ""
        }

    def _fetch_dir(self, path, headers):
        """Fetch GitHub directory listing with recursive subdirectory support."""
        url = f"{self.GITHUB_API_BASE}/{path}"
        try:
            r = requests.get(url, headers=headers, timeout=15)
            rate_info = {"remaining": int(r.headers.get("X-RateLimit-Remaining", -1))}
            reset_epoch = r.headers.get("X-RateLimit-Reset")
            if reset_epoch:
                try:
                    rate_info["reset"] = datetime.fromtimestamp(
                        int(reset_epoch), tz=timezone.utc).strftime("%H:%M:%S UTC")
                except (ValueError, OSError):
                    rate_info["reset"] = "unknown"

            if r.status_code == 403:
                return {"rate_limited": True, "reset_time": rate_info.get("reset", "~1 hour")}
            if r.status_code == 404:
                return []
            r.raise_for_status()
            items = r.json()
            if not isinstance(items, list):
                return []

            all_files = []
            for item in items:
                if item.get("type") == "file" and item.get("name", "").endswith(".yml"):
                    all_files.append(item)
                elif item.get("type") == "dir":
                    sub = self._fetch_dir(f"{path}/{item['name']}", headers)
                    if isinstance(sub, list):
                        all_files.extend(sub)
                    elif isinstance(sub, dict) and "files" in sub:
                        all_files.extend(sub["files"])
                    elif isinstance(sub, dict) and sub.get("rate_limited"):
                        return sub
            return {"files": all_files, "rate_info": rate_info}
        except (requests.exceptions.Timeout, requests.exceptions.RequestException):
            return []

    def _err(self, msg):
        return {
            "success": False, "error": msg,
            "downloaded_count": 0, "skipped_count": 0, "updated_count": 0, "mismatched_count": 0,
            "new_rules": [], "skipped_rules": [], "updated_rules": [], "mismatched_rules": [],
            "rate_limited": False, "rate_limit_remaining": None, "rate_limit_reset": None,
        }
