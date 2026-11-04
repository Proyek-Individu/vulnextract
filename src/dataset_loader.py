"""
Universal Dataset Adapter and Normalizer.

Transforms heterogeneous vulnerability datasets into the canonical 11-column
schema expected by CveMethodPipeline (mode "pairs"), FeatureExtractionPipeline
(mode "features"), and ClassificationPipeline (mode "classify"):

    cve_id, vulnerability_type, language, file, method,
    vulnerable_code, fixed_code, commit_hash, repo, commit_msg, granularity

Supported dataset families out of the box:
1. Paired CVE commit datasets (e.g. `cve_fix_pairs.csv`):
   Columns already contain `vulnerable_code` and `fixed_code` (or aliases such
   as `func_before`/`func_after`, `before`/`after`).
2. Single-snippet vulnerability datasets (e.g. `code_vulnerabilities.csv`):
   Columns such as `Code Snippet`, `Vulnerability Type`, `Location`,
   `Preprocessed Tokens` without an explicit `language` or `fixed_code` column.
3. Safety-labeled file/method datasets (e.g. `CVEFixes.csv`):
   Columns `code`, `language`, `safety` (`vulnerable` vs `safe`).
4. Advisory / link-based datasets (e.g. `Security Vulnerabilities.csv`):
   Columns `Title`, `Date`, `Severity`, `Summary`, `Link` (GitHub Advisory URLs).
   Attempts to fetch commit diffs from GitHub Advisory/Commit APIs with an
   automatic offline/rate-limit circuit breaker and deterministic AST-valid
   code synthesis fallback.
"""

import json
import logging
import os
import re
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

import pandas as pd

from .config import is_url

logger = logging.getLogger(__name__)

CANONICAL_COLUMNS: List[str] = [
    "cve_id",
    "vulnerability_type",
    "language",
    "file",
    "method",
    "vulnerable_code",
    "fixed_code",
    "commit_hash",
    "repo",
    "commit_msg",
    "granularity",
]

# Maps language names, file extensions, and package ecosystems to canonical names.
LANGUAGE_ALIASES: Dict[str, str] = {
    # Python
    "python": "python",
    "py": "python",
    "python3": "python",
    "pip": "python",
    "pypi": "python",
    # JavaScript
    "javascript": "javascript",
    "js": "javascript",
    "mjs": "javascript",
    "cjs": "javascript",
    "jsx": "javascript",
    "node": "javascript",
    "nodejs": "javascript",
    "npm": "javascript",
    # TypeScript
    "typescript": "typescript",
    "ts": "typescript",
    "tsx": "typescript",
    # PHP
    "php": "php",
    "phpt": "php",
    "phtml": "php",
    "ctp": "php",
    "composer": "php",
    "packagist": "php",
    # Go
    "go": "go",
    "golang": "go",
    # Java
    "java": "java",
    "maven": "java",
    "gradle": "java",
    "jar": "java",
    # C / C++
    "c": "c",
    "h": "c",
    "cpp": "c",
    "c++": "c",
    "cc": "c",
    "cxx": "c",
    "hpp": "c",
    "hh": "c",
    # Rust
    "rust": "rust",
    "rs": "rust",
    "cargo": "rust",
    "crates.io": "rust",
}

SAFE_LABELS = frozenset({
    "safe", "fixed", "benign", "clean", "0", "false", "no",
    "negative", "patched", "non-vulnerable", "non_vulnerable", "secure", "none",
})

VULNERABLE_LABELS = frozenset({
    "vulnerable", "vuln", "unsafe", "1", "true", "yes",
    "positive", "buggy", "flawed", "insecure",
})

INVALID_CODE_PLACEHOLDERS = frozenset({
    "404: not found",
    "not found",
    "null",
    "none",
    "nan",
})

_CVE_OR_GHSA_RE = re.compile(r"(CVE-\d{4}-\d+|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4})", re.IGNORECASE)
_SUMMARY_PKG_ECO_RE = re.compile(r"published\s+for\s*([^\s(]+)\s*\(([^)]+)\)", re.IGNORECASE)
_PAREN_TOKEN_RE = re.compile(r"\(([^)]+)\)")
_FUNC_NAME_PATTERNS = [
    re.compile(r"\bdef\s+([A-Za-z_][A-Za-z0-9_]*)\s*\("),
    re.compile(r"\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\s*\("),
    re.compile(r"\bfunc\s+(?:\([^)]+\)\s*)?([A-Za-z_][A-Za-z0-9_]*)\s*\("),
    re.compile(r"\bfn\s+([A-Za-z_][A-Za-z0-9_]*)\s*[<(]"),
    re.compile(r"\b(?:public|private|protected|static|\s)+[\w<>\[\]]+\s+([A-Za-z_][A-Za-z0-9_]*)\s*\("),
]


def _norm_col(col: str) -> str:
    return re.sub(r"[\s\-]+", "_", str(col).strip().lower())


def normalize_language(raw_lang: Any, code: str = "", file_path: str = "", summary: str = "") -> str:
    """Normalizes a language / ecosystem string or infers it from code/metadata."""
    if raw_lang is not None and not pd.isna(raw_lang):
        cleaned = str(raw_lang).strip().lower()
        if cleaned in LANGUAGE_ALIASES:
            return LANGUAGE_ALIASES[cleaned]
        if cleaned and cleaned not in ("other", "unknown", "none", "nan"):
            return cleaned

    # Try file extension
    if file_path:
        ext = Path(str(file_path)).suffix.lstrip(".").lower()
        if ext in LANGUAGE_ALIASES:
            return LANGUAGE_ALIASES[ext]

    # Try ecosystem in summary (e.g. "(pip)", "(npm)", "(Composer)", "(Go)")
    if summary:
        m = _SUMMARY_PKG_ECO_RE.search(summary)
        if m:
            eco = m.group(2).strip().lower()
            if eco in LANGUAGE_ALIASES:
                return LANGUAGE_ALIASES[eco]
            return eco
        for token in _PAREN_TOKEN_RE.findall(summary):
            t_low = token.strip().lower()
            if t_low in LANGUAGE_ALIASES:
                return LANGUAGE_ALIASES[t_low]

    return infer_language_from_code(code)


def infer_language_from_code(code: str) -> str:
    """Infers programming language from source code / snippet syntax."""
    if not isinstance(code, str) or not code.strip():
        return ""
    s = code.strip()

    # PHP indicators
    if "<?php" in s or "<?=" in s or "$this->" in s or "$_GET" in s or "$_POST" in s or "mysqli_" in s:
        return "php"
    if re.search(r"\$[A-Za-z_][A-Za-z0-9_]*\s*=", s):
        return "php"

    # Go indicators
    if re.search(r"\bfunc\s+(?:\([^)]+\)\s*)?[A-Za-z_]", s) or " := " in s or "fmt.Sprintf" in s or "err != nil" in s:
        return "go"

    # Java indicators
    if "public class " in s or "System.out." in s or "throws " in s or "ArrayList<" in s:
        return "java"

    # Rust indicators
    if re.search(r"\b(?:pub\s+)?fn\s+[A-Za-z_]", s) or "let mut " in s or "::new(" in s:
        return "rust"

    # C / C++ indicators
    if "#include" in s or "malloc(" in s or "sizeof(" in s or re.search(r"\bchar\s*\*", s):
        return "c"

    # JavaScript / DOM / Node indicators
    js_markers = (
        "document.", "window.", "alert(", "console.log", ".innerHTML",
        "connection.query(", "require(", "module.exports", "===", "!==",
        "const ", "let ", "var ", "=>",
    )
    if any(m in s for m in js_markers):
        return "javascript"

    # Python indicators
    py_markers = (
        "def ", "import ", "from ", "cursor.execute", "db.execute",
        "os.system", "subprocess.", "shlex.", "pickle.loads", "yaml.load",
        "render_template", "elif ", "except ",
    )
    if any(m in s for m in py_markers):
        return "python"

    # SQL assignment snippet heuristic (e.g. `query = 'SELECT ...' + email_input`)
    if re.match(r"^[A-Za-z_][A-Za-z0-9_]*\s*=\s*['\"]SELECT\b", s, re.IGNORECASE) and not s.endswith(";"):
        return "python"

    if s.endswith(";"):
        return "javascript"

    return "python"


def infer_vulnerability_type(title_or_text: str, code: str = "", default: str = "Vulnerability") -> str:
    """Infers canonical vulnerability category from advisory title, summary, or code."""
    text = f"{title_or_text or ''} {code or ''}".lower()
    if not text.strip():
        return default

    rules: List[Tuple[Tuple[str, ...], str]] = [
        (("sql injection", "sqli", "select * from", "pragma table_info"), "SQL Injection"),
        (("cross-site scripting", "cross site scripting", "xss", "innerhtml", "document.write", "alert("), "XSS"),
        (("command injection", "os command", "shell injection", "exec.command", "os.system", "child_process"), "Command Injection"),
        (("code execution", "rce", "arbitrary code", "dynamic import", "eval("), "Code Execution"),
        (("path traversal", "directory traversal", "file read", "file write", "file download", "file deletion", "symlink"), "Path Traversal"),
        (("server-side request forgery", "ssrf", "request smuggling"), "SSRF"),
        (("deserialization", "unserialize", "pickle.loads", "yaml.load"), "Insecure Deserialization"),
        (("xml external entity", "xxe"), "XXE"),
        (("cross-site request forgery", "csrf"), "CSRF"),
        (("prototype pollution",), "Prototype Pollution"),
        (("denial of service", "dos", "redos", "infinite loop", "memory exhaustion"), "Denial of Service"),
        (("buffer overflow", "out-of-bounds", "use-after-free", "heap overflow", "null pointer"), "Buffer Overflow"),
        (("information disclosure", "information exposure", "sensitive data", "share hashed"), "Information Disclosure"),
        (("privilege", "unauthorized", "access control", "authentication", "permission", "bypass", "credential"), "Broken Access Control"),
        (("input validation", "unsanitized", "sanitize", "escaping"), "Improper Input Validation"),
    ]
    for keywords, label in rules:
        if any(k in text for k in keywords):
            return label

    cleaned = str(title_or_text or "").strip()
    return cleaned[:80] if cleaned else default


def _extract_method_name(code: str, fallback: str) -> str:
    if not isinstance(code, str) or not code.strip():
        return fallback
    for pattern in _FUNC_NAME_PATTERNS:
        m = pattern.search(code)
        if m:
            return m.group(1)
    return fallback


def _is_valid_code(code: Any) -> bool:
    if not isinstance(code, str):
        return False
    stripped = code.strip()
    if not stripped:
        return False
    if stripped.lower() in INVALID_CODE_PLACEHOLDERS:
        return False
    return True


# ---------------------------------------------------------------------------
# GitHub Advisory / Commit Fetcher with Fast Circuit Breaker & AST Fallback
# ---------------------------------------------------------------------------

class _GitHubAdvisoryResolver:
    """
    Resolves GitHub Advisory links (`https://github.com/advisories/GHSA-...`)
    or commit URLs to `(vulnerable_code, fixed_code)` pairs.

    Uses a circuit breaker so that if the machine is offline or rate-limited,
    subsequent rows immediately use the deterministic AST-valid fallback
    without waiting for network timeouts on thousands of rows.
    """

    def __init__(self, enabled: bool = True, timeout: float = 2.5, max_remote_calls: int = 25) -> None:
        self.enabled = enabled
        self.timeout = timeout
        self.max_remote_calls = max_remote_calls
        self._calls_made = 0
        self._circuit_open = False
        self._cache: Dict[str, Tuple[str, str, str]] = {}

    def _headers(self) -> Dict[str, str]:
        headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": "vulnextract-dataset-adapter/1.0",
        }
        token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
        if token:
            headers["Authorization"] = f"Bearer {token.strip()}"
        return headers

    def fetch_from_link(self, link: str) -> Optional[Tuple[str, str, str]]:
        """Returns (vulnerable_code, fixed_code, commit_hash) if fetched, else None."""
        if not self.enabled or self._circuit_open or not link:
            return None
        link = str(link).strip()
        if link in self._cache:
            return self._cache[link]
        if self._calls_made >= self.max_remote_calls:
            return None

        ghsa_match = re.search(r"(GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4})", link, re.IGNORECASE)
        commit_match = re.search(r"github\.com/([^/]+/[^/]+)/commit/([0-9a-f]{7,40})", link, re.IGNORECASE)

        try:
            self._calls_made += 1
            commit_url = None
            if commit_match:
                commit_url = f"https://api.github.com/repos/{commit_match.group(1)}/commits/{commit_match.group(2)}"
            elif ghsa_match:
                adv_url = f"https://api.github.com/advisories/{ghsa_match.group(1)}"
                req = urllib.request.Request(adv_url, headers=self._headers())
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    adv_data = json.loads(resp.read().decode("utf-8", errors="replace"))
                refs = adv_data.get("references") or []
                for ref in refs:
                    ref_url = ref if isinstance(ref, str) else (ref.get("url") or "")
                    cm = re.search(r"github\.com/([^/]+/[^/]+)/commit/([0-9a-f]{7,40})", str(ref_url), re.IGNORECASE)
                    if cm:
                        commit_url = f"https://api.github.com/repos/{cm.group(1)}/commits/{cm.group(2)}"
                        break

            if not commit_url:
                return None

            req = urllib.request.Request(commit_url, headers=self._headers())
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                commit_data = json.loads(resp.read().decode("utf-8", errors="replace"))

            sha = str(commit_data.get("sha") or "")
            for file_obj in commit_data.get("files") or []:
                patch = file_obj.get("patch")
                if patch:
                    vuln, fixed = _split_unified_diff(patch)
                    if vuln.strip() and fixed.strip():
                        result = (vuln, fixed, sha)
                        self._cache[link] = result
                        return result
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError, ValueError):
            # Trip circuit breaker on network / rate-limit failure so remaining rows don't stall
            self._circuit_open = True
            logger.info("GitHub API tidak dapat diakses / terkena rate-limit — beralih ke fallback lokal.")
            return None

        return None


def _split_unified_diff(patch: str) -> Tuple[str, str]:
    """Reconstructs before (vulnerable) and after (fixed) snippets from a unified diff patch."""
    vuln_lines: List[str] = []
    fixed_lines: List[str] = []
    for line in patch.splitlines():
        if line.startswith(("@@", "---", "+++")):
            continue
        if line.startswith("-"):
            vuln_lines.append(line[1:])
        elif line.startswith("+"):
            fixed_lines.append(line[1:])
        else:
            content = line[1:] if line.startswith(" ") else line
            vuln_lines.append(content)
            fixed_lines.append(content)
    return "\n".join(vuln_lines).strip(), "\n".join(fixed_lines).strip()


def synthesize_advisory_code_pair(
    language: str,
    vuln_type: str,
    func_name: str,
    title: str,
    severity: str,
    cve_id: str,
) -> Tuple[str, str]:
    """
    Fallback generator when a dataset row only provides advisory metadata/links
    (e.g. `Security Vulnerabilities.csv` when offline). Produces AST-valid
    vulnerable and fixed functions in the target language matching context.md's
    category D/E sink and sanitizer signatures so AST tree-building, diff
    labeling, and ML/XAI pipelines operate on valid syntax trees.
    """
    lang = language.lower().strip()
    vtype = vuln_type.lower()
    safe_fn = re.sub(r"[^A-Za-z0-9_]", "_", func_name or "handle_request").strip("_") or "handle_request"
    if safe_fn[0].isdigit():
        safe_fn = f"fn_{safe_fn}"
    doc = re.sub(r'["\'\\\r\n]+', " ", f"{cve_id} [{severity}] {title}").strip()[:120]

    if lang == "python":
        if "sql" in vtype:
            vuln = (
                f"def {safe_fn}(cursor, user_input):\n"
                f"    note = \"{doc}\"\n"
                f"    query = \"SELECT * FROM records WHERE key = '\" + user_input\n"
                f"    return cursor.execute(query)\n"
            )
            fixed = (
                f"def {safe_fn}(cursor, user_input):\n"
                f"    note = \"{doc}\"\n"
                f"    if not user_input:\n"
                f"        raise ValueError(\"invalid input\")\n"
                f"    return cursor.execute(\"SELECT * FROM records WHERE key = %s\", (user_input,))\n"
            )
        elif "xss" in vtype or "scripting" in vtype or "output" in vtype:
            vuln = (
                f"def {safe_fn}(user_input):\n"
                f"    note = \"{doc}\"\n"
                f"    tpl = \"<div>\" + user_input\n"
                f"    return render_template_string(tpl)\n"
            )
            fixed = (
                f"def {safe_fn}(user_input):\n"
                f"    note = \"{doc}\"\n"
                f"    clean = bleach.clean(user_input)\n"
                f"    return render_template(\"view.html\", content=clean)\n"
            )
        elif "command" in vtype or "code execution" in vtype:
            vuln = (
                f"def {safe_fn}(user_cmd):\n"
                f"    note = \"{doc}\"\n"
                f"    cmd = \"run_task \" + user_cmd\n"
                f"    return os.system(cmd)\n"
            )
            fixed = (
                f"def {safe_fn}(user_cmd):\n"
                f"    note = \"{doc}\"\n"
                f"    safe_arg = shlex.quote(user_cmd)\n"
                f"    return subprocess.run([\"run_task\", safe_arg], check=True)\n"
            )
        elif "path" in vtype or "file" in vtype:
            vuln = (
                f"def {safe_fn}(base_dir, user_path):\n"
                f"    note = \"{doc}\"\n"
                f"    target = base_dir + \"/\" + user_path\n"
                f"    return open(target).read()\n"
            )
            fixed = (
                f"def {safe_fn}(base_dir, user_path):\n"
                f"    note = \"{doc}\"\n"
                f"    if \"..\" in user_path:\n"
                f"        raise ValueError(\"invalid path\")\n"
                f"    return pathlib.Path(base_dir, user_path).read_text()\n"
            )
        elif "ssrf" in vtype or "request" in vtype:
            vuln = (
                f"def {safe_fn}(target_url):\n"
                f"    note = \"{doc}\"\n"
                f"    url = \"http://\" + target_url\n"
                f"    return requests.get(url)\n"
            )
            fixed = (
                f"def {safe_fn}(target_url):\n"
                f"    note = \"{doc}\"\n"
                f"    if not target_url.startswith(\"https://trusted.example.com\"):\n"
                f"        raise ValueError(\"untrusted host\")\n"
                f"    return requests.get(target_url, timeout=5)\n"
            )
        else:
            vuln = (
                f"def {safe_fn}(payload):\n"
                f"    note = \"{doc}\"\n"
                f"    data = pickle.loads(payload)\n"
                f"    return eval(str(data))\n"
            )
            fixed = (
                f"def {safe_fn}(payload):\n"
                f"    note = \"{doc}\"\n"
                f"    if not payload:\n"
                f"        raise ValueError(\"empty payload\")\n"
                f"    return json.loads(payload)\n"
            )
        return vuln, fixed

    if lang in ("javascript", "typescript"):
        if "sql" in vtype:
            vuln = (
                f"function {safe_fn}(db, userInput) {{\n"
                f"  const note = \"{doc}\";\n"
                f"  const sql = \"SELECT * FROM items WHERE id = \" + userInput;\n"
                f"  return db.query(sql);\n"
                f"}}\n"
            )
            fixed = (
                f"function {safe_fn}(db, userInput) {{\n"
                f"  const note = \"{doc}\";\n"
                f"  if (!userInput) {{\n"
                f"    throw new Error(\"invalid input\");\n"
                f"  }}\n"
                f"  return db.query(\"SELECT * FROM items WHERE id = ?\", [userInput]);\n"
                f"}}\n"
            )
        elif "command" in vtype or "code execution" in vtype:
            vuln = (
                f"function {safe_fn}(userInput) {{\n"
                f"  const note = \"{doc}\";\n"
                f"  const expr = \"run(\" + userInput + \")\";\n"
                f"  return eval(expr);\n"
                f"}}\n"
            )
            fixed = (
                f"function {safe_fn}(userInput) {{\n"
                f"  const note = \"{doc}\";\n"
                f"  const safe = encodeURIComponent(userInput);\n"
                f"  return safe;\n"
                f"}}\n"
            )
        elif "path" in vtype or "file" in vtype:
            vuln = (
                f"function {safe_fn}(userPath) {{\n"
                f"  const note = \"{doc}\";\n"
                f"  const target = \"/var/data/\" + userPath;\n"
                f"  return fs.readFileSync(target);\n"
                f"}}\n"
            )
            fixed = (
                f"function {safe_fn}(userPath) {{\n"
                f"  const note = \"{doc}\";\n"
                f"  if (userPath.includes(\"..\")) {{\n"
                f"    throw new Error(\"invalid path\");\n"
                f"  }}\n"
                f"  return path.basename(userPath);\n"
                f"}}\n"
            )
        else:
            vuln = (
                f"function {safe_fn}(el, userInput) {{\n"
                f"  const note = \"{doc}\";\n"
                f"  el.innerHTML = \"<span>\" + userInput + \"</span>\";\n"
                f"  return el;\n"
                f"}}\n"
            )
            fixed = (
                f"function {safe_fn}(el, userInput) {{\n"
                f"  const note = \"{doc}\";\n"
                f"  const clean = DOMPurify.sanitize(userInput);\n"
                f"  el.textContent = clean;\n"
                f"  return el;\n"
                f"}}\n"
            )
        return vuln, fixed

    if lang == "php":
        if "sql" in vtype:
            vuln = (
                f"<?php\nfunction {safe_fn}($db, $input) {{\n"
                f"    $note = \"{doc}\";\n"
                f"    $sql = \"SELECT * FROM users WHERE name = '\" . $input . \"'\";\n"
                f"    return $db->query($sql);\n"
                f"}}\n"
            )
            fixed = (
                f"<?php\nfunction {safe_fn}($db, $input) {{\n"
                f"    $note = \"{doc}\";\n"
                f"    $safe = mysqli_real_escape_string($db, $input);\n"
                f"    return $db->prepare(\"SELECT * FROM users WHERE name = ?\");\n"
                f"}}\n"
            )
        elif "command" in vtype or "code execution" in vtype:
            vuln = (
                f"<?php\nfunction {safe_fn}($cmd) {{\n"
                f"    $note = \"{doc}\";\n"
                f"    $full = \"ls \" . $cmd;\n"
                f"    return shell_exec($full);\n"
                f"}}\n"
            )
            fixed = (
                f"<?php\nfunction {safe_fn}($cmd) {{\n"
                f"    $note = \"{doc}\";\n"
                f"    $clean = filter_var($cmd, FILTER_SANITIZE_SPECIAL_CHARS);\n"
                f"    return $clean;\n"
                f"}}\n"
            )
        elif "path" in vtype or "file" in vtype:
            vuln = (
                f"<?php\nfunction {safe_fn}($file) {{\n"
                f"    $note = \"{doc}\";\n"
                f"    $path = \"/uploads/\" . $file;\n"
                f"    return file_get_contents($path);\n"
                f"}}\n"
            )
            fixed = (
                f"<?php\nfunction {safe_fn}($file) {{\n"
                f"    $note = \"{doc}\";\n"
                f"    $clean = filter_var($file, FILTER_SANITIZE_SPECIAL_CHARS);\n"
                f"    return basename($clean);\n"
                f"}}\n"
            )
        else:
            vuln = (
                f"<?php\nfunction {safe_fn}($input) {{\n"
                f"    $note = \"{doc}\";\n"
                f"    echo \"<div>\" . $input . \"</div>\";\n"
                f"}}\n"
            )
            fixed = (
                f"<?php\nfunction {safe_fn}($input) {{\n"
                f"    $note = \"{doc}\";\n"
                f"    $safe = htmlspecialchars($input, ENT_QUOTES, 'UTF-8');\n"
                f"    return $safe;\n"
                f"}}\n"
            )
        return vuln, fixed

    if lang == "go":
        if "sql" in vtype:
            vuln = (
                f"func {safe_fn}(db *sql.DB, input string) (*sql.Rows, error) {{\n"
                f"\tnote := \"{doc}\"\n"
                f"\t_ = note\n"
                f"\tq := fmt.Sprintf(\"SELECT * FROM items WHERE name = '%s'\", input)\n"
                f"\treturn db.Query(q)\n"
                f"}}\n"
            )
            fixed = (
                f"func {safe_fn}(db *sql.DB, input string) (*sql.Rows, error) {{\n"
                f"\tnote := \"{doc}\"\n"
                f"\t_ = note\n"
                f"\tif input == \"\" {{\n"
                f"\t\treturn nil, errors.New(\"empty input\")\n"
                f"\t}}\n"
                f"\treturn db.Query(\"SELECT * FROM items WHERE name = ?\", input)\n"
                f"}}\n"
            )
        elif "command" in vtype or "code execution" in vtype:
            vuln = (
                f"func {safe_fn}(arg string) ([]byte, error) {{\n"
                f"\tnote := \"{doc}\"\n"
                f"\t_ = note\n"
                f"\tcmdLine := fmt.Sprintf(\"sh -c %s\", arg)\n"
                f"\treturn exec.Command(\"sh\", \"-c\", cmdLine).Output()\n"
                f"}}\n"
            )
            fixed = (
                f"func {safe_fn}(arg string) ([]byte, error) {{\n"
                f"\tnote := \"{doc}\"\n"
                f"\t_ = note\n"
                f"\tif strings.Contains(arg, \";\") {{\n"
                f"\t\treturn nil, errors.New(\"invalid argument\")\n"
                f"\t}}\n"
                f"\treturn []byte(arg), nil\n"
                f"}}\n"
            )
        else:
            vuln = (
                f"func {safe_fn}(userPath string) ([]byte, error) {{\n"
                f"\tnote := \"{doc}\"\n"
                f"\t_ = note\n"
                f"\tfull := \"/srv/data/\" + userPath\n"
                f"\treturn os.ReadFile(full)\n"
                f"}}\n"
            )
            fixed = (
                f"func {safe_fn}(userPath string) ([]byte, error) {{\n"
                f"\tnote := \"{doc}\"\n"
                f"\t_ = note\n"
                f"\tif strings.Contains(userPath, \"..\") {{\n"
                f"\t\treturn nil, errors.New(\"invalid path\")\n"
                f"\t}}\n"
                f"\tclean := filepath.Clean(userPath)\n"
                f"\treturn []byte(clean), nil\n"
                f"}}\n"
            )
        return vuln, fixed

    if lang == "java":
        vuln = (
            f"public class Advisory {{\n"
            f"    public Object {safe_fn}(String input) {{\n"
            f"        String note = \"{doc}\";\n"
            f"        String query = \"SELECT * FROM records WHERE id = '\" + input + \"'\";\n"
            f"        return statement.executeQuery(query);\n"
            f"    }}\n"
            f"}}\n"
        )
        fixed = (
            f"public class Advisory {{\n"
            f"    public Object {safe_fn}(String input) {{\n"
            f"        String note = \"{doc}\";\n"
            f"        if (input == null || input.isEmpty()) {{\n"
            f"            throw new IllegalArgumentException(\"invalid input\");\n"
            f"        }}\n"
            f"        return preparedStatement.executeQuery();\n"
            f"    }}\n"
            f"}}\n"
        )
        return vuln, fixed

    if lang == "rust":
        vuln = (
            f"fn {safe_fn}(input: &str) -> String {{\n"
            f"    let _note = \"{doc}\";\n"
            f"    let query = format!(\"SELECT * FROM items WHERE id = {{}}\", input);\n"
            f"    query\n"
            f"}}\n"
        )
        fixed = (
            f"fn {safe_fn}(input: &str) -> Result<String, &'static str> {{\n"
            f"    let _note = \"{doc}\";\n"
            f"    if input.is_empty() {{\n"
            f"        return Err(\"invalid input\");\n"
            f"    }}\n"
            f"    Ok(input.trim().to_string())\n"
            f"}}\n"
        )
        return vuln, fixed

    # Default generic fallback
    return f"// {doc}\n{title}", f"// {doc} (patched)\n{title}"


def synthesize_remediated_snippet(vulnerable_code: str, language: str, vuln_type: str = "") -> str:
    """
    Creates a safe remediated counterpart for a single-sided vulnerable snippet
    (used by ClassificationPipeline when an input dataset such as
    `code_vulnerabilities.csv` contains 100% positive/vulnerable samples and no
    negative/safe class to train a binary classifier on).
    """
    s = (vulnerable_code or "").strip()
    lang = (language or "").strip().lower()

    if lang == "python":
        if "cursor.execute" in s or "db.execute" in s:
            callee = "cursor.execute" if "cursor.execute" in s else "db.execute"
            return (
                "if not user_input:\n"
                "    raise ValueError('invalid input')\n"
                f"{callee}('SELECT * FROM records WHERE id = %s', (user_input,))"
            )
        if s.startswith("query"):
            return "query = 'SELECT * FROM customers WHERE email = %s'"
        return "clean_value = shlex.quote(str(user_input))"

    if lang in ("javascript", "typescript"):
        if ".query(" in s:
            return "connection.query('SELECT * FROM users WHERE username = ?', [input_string]);"
        if ".innerHTML" in s:
            return "document.getElementById('input').textContent = DOMPurify.sanitize(user_input);"
        if "document.write" in s:
            return "const safeText = DOMPurify.sanitize(content);"
        if "location" in s:
            return "const safeParam = encodeURIComponent(user_input);"
        if "alert(" in s:
            return "console.log(encodeURIComponent(user_input));"
        return "const sanitized = DOMPurify.sanitize(user_input);"

    if lang == "php":
        return "$safe = htmlspecialchars($input, ENT_QUOTES, 'UTF-8');"

    if lang == "go":
        return "clean := filepath.Clean(userInput)"

    return f"// safe remediated\n{s}"


# ---------------------------------------------------------------------------
# Main DataFrame Normalization & File Loading
# ---------------------------------------------------------------------------

def load_dataset(
    input_path: Union[str, Path],
    max_rows: Optional[int] = None,
    fetch_github: bool = True,
) -> pd.DataFrame:
    """
    Loads a CSV dataset from `input_path` (local path or URL), optionally
    limiting to `max_rows` rows (critical for multi-GB files like CVEFixes.csv),
    and normalizes it into the canonical 11-column DataFrame schema.
    """
    if not is_url(str(input_path)):
        input_path = Path(input_path)
        if not input_path.exists():
            raise FileNotFoundError(f"Input file not found at: {input_path}")

    nrows = int(max_rows) if (max_rows is not None and int(max_rows) > 0) else None
    if nrows:
        logger.info(f"Loading input dataset from {input_path} (max_rows={nrows})...")
    else:
        logger.info(f"Loading input dataset from {input_path}...")

    df = pd.read_csv(input_path, nrows=nrows, low_memory=False)
    return normalize_dataframe(df, max_rows=nrows, fetch_github=fetch_github)


def normalize_dataframe(
    df: pd.DataFrame,
    max_rows: Optional[int] = None,
    fetch_github: bool = True,
) -> pd.DataFrame:
    """
    Normalizes an in-memory DataFrame of any supported vulnerability dataset
    format into the canonical schema while preserving existing columns.
    """
    if df is None or df.empty:
        return pd.DataFrame(columns=CANONICAL_COLUMNS)

    if max_rows is not None and int(max_rows) > 0 and len(df) > int(max_rows):
        df = df.head(int(max_rows)).copy()

    col_map = {_norm_col(c): c for c in df.columns}

    # Case 1: Already has both `vulnerable_code` and `fixed_code` (e.g. cve_fix_pairs.csv)
    if "vulnerable_code" in col_map and "fixed_code" in col_map:
        out = df.copy()
        if col_map["vulnerable_code"] != "vulnerable_code":
            out["vulnerable_code"] = out[col_map["vulnerable_code"]]
        if col_map["fixed_code"] != "fixed_code":
            out["fixed_code"] = out[col_map["fixed_code"]]
        for col in CANONICAL_COLUMNS:
            if col not in out.columns:
                if col in col_map:
                    out[col] = out[col_map[col]]
                else:
                    out[col] = "method" if col == "granularity" else ""
        return out

    # Identify column roles across heterogeneous schemas
    vuln_code_col = next((col_map[k] for k in (
        "vulnerable_code", "func_before", "code_before", "before",
        "buggy_code", "flawed_code", "old_code", "vul_code",
    ) if k in col_map), None)
    fixed_code_col = next((col_map[k] for k in (
        "fixed_code", "func_after", "code_after", "after",
        "patched_code", "repaired_code", "new_code", "patch_code",
    ) if k in col_map), None)
    single_code_col = next((col_map[k] for k in (
        "code", "code_snippet", "snippet", "source_code",
        "func", "function", "statement", "raw_code", "content",
    ) if k in col_map), None)
    link_col = next((col_map[k] for k in (
        "link", "url", "github_link", "github_url", "advisory_url", "commit_url", "reference",
    ) if k in col_map), None)
    safety_col = next((col_map[k] for k in (
        "safety", "label", "target", "is_vulnerable", "vulnerable", "status", "class", "verdict",
    ) if k in col_map), None)
    severity_col = next((col_map[k] for k in (
        "severity", "cvss_severity", "risk", "priority",
    ) if k in col_map), None)
    lang_col = next((col_map[k] for k in (
        "language", "lang", "programming_language", "file_extension", "ext", "ecosystem",
    ) if k in col_map), None)
    vtype_col = next((col_map[k] for k in (
        "vulnerability_type", "vuln_type", "cwe", "cwe_id", "cwe_name",
        "category", "attack_type", "flaw_type",
    ) if k in col_map), None)
    cve_col = next((col_map[k] for k in (
        "cve_id", "cve", "ghsa_id", "advisory_id", "id",
    ) if k in col_map), None)
    file_col = next((col_map[k] for k in (
        "file", "file_path", "filename", "filepath", "location",
    ) if k in col_map), None)
    method_col = next((col_map[k] for k in (
        "method", "function_name", "func_name", "symbol",
    ) if k in col_map), None)
    repo_col = next((col_map[k] for k in (
        "repo", "repository", "project", "package",
    ) if k in col_map), None)
    commit_col = next((col_map[k] for k in (
        "commit_hash", "commit", "commit_id", "sha",
    ) if k in col_map), None)
    msg_col = next((col_map[k] for k in (
        "commit_msg", "title", "message", "description",
    ) if k in col_map), None)
    summary_col = col_map.get("summary")

    gh_resolver = _GitHubAdvisoryResolver(enabled=fetch_github)
    normalized_rows: List[Dict[str, Any]] = []

    for idx, row in df.iterrows():
        raw_summary = str(row.get(summary_col, "") or "") if summary_col else ""
        raw_title = str(row.get(msg_col, "") or "") if msg_col else ""
        raw_link = str(row.get(link_col, "") or "") if link_col else ""
        raw_severity = str(row.get(severity_col, "") or "") if severity_col else ""

        # 1. Extract / infer CVE or Advisory ID
        cve_id = str(row.get(cve_col, "") or "").strip() if cve_col else ""
        if not cve_id or cve_id.lower() == "nan":
            m_id = _CVE_OR_GHSA_RE.search(f"{raw_summary} {raw_title} {raw_link}")
            cve_id = m_id.group(1) if m_id else f"ROW-{idx}"

        # 2. Extract / infer repository or package name
        repo = str(row.get(repo_col, "") or "").strip() if repo_col else ""
        if not repo or repo.lower() == "nan":
            m_pkg = _SUMMARY_PKG_ECO_RE.search(raw_summary)
            if m_pkg:
                repo = m_pkg.group(1).strip()
            elif raw_link:
                repo = raw_link

        # 3. Extract code (paired, single-column, or via advisory link)
        v_code = str(row.get(vuln_code_col, "") or "") if vuln_code_col and not pd.isna(row.get(vuln_code_col)) else ""
        f_code = str(row.get(fixed_code_col, "") or "") if fixed_code_col and not pd.isna(row.get(fixed_code_col)) else ""
        single_code = str(row.get(single_code_col, "") or "") if single_code_col and not pd.isna(row.get(single_code_col)) else ""

        if not _is_valid_code(v_code):
            v_code = ""
        if not _is_valid_code(f_code):
            f_code = ""
        if not _is_valid_code(single_code):
            single_code = ""

        # 4. Determine language
        raw_lang_val = row.get(lang_col) if lang_col else None
        raw_file_val = str(row.get(file_col, "") or "").strip() if file_col and not pd.isna(row.get(file_col)) else ""
        language = normalize_language(
            raw_lang_val,
            code=v_code or single_code or f_code,
            file_path=raw_file_val,
            summary=raw_summary,
        )

        # 5. Determine vulnerability type
        raw_vtype = str(row.get(vtype_col, "") or "").strip() if vtype_col and not pd.isna(row.get(vtype_col)) else ""
        if raw_vtype:
            vuln_type = raw_vtype
        else:
            vuln_type = infer_vulnerability_type(
                f"{raw_title} {raw_summary}",
                code=v_code or single_code,
                default=raw_severity or "Vulnerability",
            )

        # 6. Determine safety / side assignment for single-code or link datasets
        commit_hash = str(row.get(commit_col, "") or "").strip() if commit_col and not pd.isna(row.get(commit_col)) else ""
        granularity = str(row.get(col_map["granularity"], "") or "").strip() if "granularity" in col_map else ""

        if not v_code and not f_code and single_code:
            is_safe = False
            if safety_col and not pd.isna(row.get(safety_col)):
                s_val = str(row.get(safety_col)).strip().lower()
                if s_val in SAFE_LABELS:
                    is_safe = True
                elif s_val in VULNERABLE_LABELS:
                    is_safe = False
            elif raw_vtype and raw_vtype.strip().lower() in SAFE_LABELS:
                is_safe = True

            if is_safe:
                v_code = ""
                f_code = single_code
                vuln_type = "none"
            else:
                v_code = single_code
                f_code = ""
            if not granularity:
                granularity = "statement" if "\n" not in single_code.strip() else "method"

        elif not v_code and not f_code and (raw_link or raw_title or raw_summary):
            # Advisory dataset (e.g. Security Vulnerabilities.csv)
            fetched = gh_resolver.fetch_from_link(raw_link) if raw_link else None
            if fetched is not None:
                v_code, f_code, fetched_sha = fetched
                if fetched_sha and not commit_hash:
                    commit_hash = fetched_sha
            else:
                pkg_slug = re.sub(r"[^A-Za-z0-9_]", "_", repo.split("/")[-1] if repo else f"adv_{idx}")
                v_code, f_code = synthesize_advisory_code_pair(
                    language=language,
                    vuln_type=vuln_type,
                    func_name=f"handle_{pkg_slug}_{idx}",
                    title=raw_title or raw_summary,
                    severity=raw_severity or "Moderate",
                    cve_id=cve_id,
                )
            if not granularity:
                granularity = "method"

        # 7. Populate file and method identifiers for traceability and group-splitting
        code_for_meta = v_code or f_code
        method_name = str(row.get(method_col, "") or "").strip() if method_col and not pd.isna(row.get(method_col)) else ""
        if not method_name:
            method_name = _extract_method_name(code_for_meta, fallback=f"snippet_{idx}")

        file_name = raw_file_val
        if not file_name:
            ext_map = {
                "python": "py", "javascript": "js", "typescript": "ts",
                "php": "php", "go": "go", "java": "java", "c": "c", "rust": "rs",
            }
            ext = ext_map.get(language, "txt")
            file_name = f"file_{idx}.{ext}"
        elif file_name.isdigit():
            # e.g. Location column in code_vulnerabilities.csv ("8", "19", ...)
            ext_map = {"python": "py", "javascript": "js", "typescript": "ts", "php": "php", "go": "go"}
            ext = ext_map.get(language, "txt")
            file_name = f"line_{file_name}_{idx}.{ext}"

        commit_msg = raw_title or raw_summary
        if not granularity:
            granularity = "method"

        normalized_rows.append({
            "cve_id": cve_id,
            "vulnerability_type": vuln_type,
            "language": language,
            "file": file_name,
            "method": method_name,
            "vulnerable_code": v_code,
            "fixed_code": f_code,
            "commit_hash": commit_hash,
            "repo": repo,
            "commit_msg": commit_msg,
            "granularity": granularity,
        })

    return pd.DataFrame(normalized_rows, columns=CANONICAL_COLUMNS)


def ensure_binary_classes_for_classification(raw_df: pd.DataFrame) -> pd.DataFrame:
    """
    Checks whether `raw_df` produces both positive (vulnerable) and negative
    (fixed/safe) samples. If the dataset is 100% single-sided vulnerable
    snippets (such as `code_vulnerabilities.csv`, which has no `fixed_code` or
    safe rows), populates `fixed_code` with a remediated safe counterpart on
    a copy of `raw_df` so binary classification and XAI can run.
    """
    if raw_df is None or raw_df.empty:
        return raw_df

    has_v = raw_df["vulnerable_code"].fillna("").astype(str).str.strip().astype(bool)
    has_f = raw_df["fixed_code"].fillna("").astype(str).str.strip().astype(bool)

    # If there are already safe/fixed samples alongside vulnerable ones, keep as-is
    if has_v.any() and has_f.any():
        return raw_df

    if has_v.any() and not has_f.any():
        logger.info(
            "Dataset hanya memiliki sampel vulnerable tanpa sampel safe/fixed — "
            "membuat pasangan kode aman (remediated baseline) secara otomatis untuk klasifikasi biner."
        )
        augmented = raw_df.copy()
        fixed_list: List[str] = []
        for _, row in augmented.iterrows():
            v_code = str(row.get("vulnerable_code", "") or "")
            lang = str(row.get("language", "") or "")
            vtype = str(row.get("vulnerability_type", "") or "")
            fixed_list.append(synthesize_remediated_snippet(v_code, lang, vtype) if v_code.strip() else "")
        augmented["fixed_code"] = fixed_list
        return augmented

    return raw_df

