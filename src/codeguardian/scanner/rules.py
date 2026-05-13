"""Rule definitions and built-in rule registries for security and style checks."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

from codeguardian.models.findings import Severity


@dataclass
class SecurityRule:
    """A single detection rule that can be used for security, style, or other checks."""

    rule_id: str
    title: str
    description: str
    severity: Severity
    patterns: list[str]          # regex patterns applied per-line
    file_extensions: list[str]   # file extensions this rule applies to (empty = all)
    suggestion: str
    category: str                # sql_injection | secrets | xss | naming | structure | etc.
    max_lines: int | None = None           # for function-length checks (0 = no limit)
    disallowed_keywords: list[str] | None = None  # simple substring-disallowed checks


def load_builtin_rules() -> list[SecurityRule]:
    """Return all built-in security rules."""

    return [
        # ========== SQL Injection ==========
        SecurityRule(
            rule_id="SEC-001",
            title="String concatenation in SQL query",
            description="SQL query constructed via string concatenation is vulnerable to SQL injection.",
            severity=Severity.CRITICAL,
            patterns=[
                r'(?i)(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE)\b.*\+',
                r'(?i)\+\s*["\'](?:SELECT|INSERT|UPDATE|DELETE|DROP)\b',
            ],
            file_extensions=[".py", ".js", ".ts", ".java", ".kt", ".go", ".rb", ".php", ".cs", ".swift"],
            suggestion="Use parameterized queries or an ORM instead of string concatenation.",
            category="sql_injection",
        ),
        SecurityRule(
            rule_id="SEC-002",
            title="F-string / format in SQL query",
            description="SQL query built with f-string or .format() allows injection via user-controlled variables.",
            severity=Severity.CRITICAL,
            patterns=[
                r'(?i)f["\'].*?(?:SELECT|INSERT|UPDATE|DELETE|DROP)\b.*?\{.*?\}',
                r'(?i)["\'].*?(?:SELECT|INSERT|UPDATE|DELETE|DROP)\b.*?["\'].*?\.format\(',
            ],
            file_extensions=[".py"],
            suggestion="Use parameterized queries with placeholders instead of f-strings.",
            category="sql_injection",
        ),
        SecurityRule(
            rule_id="SEC-003",
            title="Bare execute() with variable SQL",
            description="Raw execute() called with a variable containing SQL is likely injectable.",
            severity=Severity.CRITICAL,
            patterns=[
                r'\.execute\([^"].*?\)',
                r'execute\([^"\'][^)]*?\+',
            ],
            file_extensions=[".py", ".java", ".kt", ".go", ".rb", ".js", ".ts"],
            suggestion="Use parameterized queries with placeholder values.",
            category="sql_injection",
        ),
        SecurityRule(
            rule_id="SEC-004",
            title="%s / % operator in SQL",
            description="SQL built with Python % formatting is vulnerable to injection.",
            severity=Severity.CRITICAL,
            patterns=[
                r'(?i)(?:SELECT|INSERT|UPDATE|DELETE|DROP)\b.*?%\s*[sdr]',
                r'(?i)["\'].*?(?:SELECT|INSERT|UPDATE|DELETE|DROP)\b.*?["\']\s*%',
            ],
            file_extensions=[".py"],
            suggestion="Use parameterized queries (cursor.execute(sql, params)).",
            category="sql_injection",
        ),

        # ========== Hardcoded Secrets ==========
        SecurityRule(
            rule_id="SEC-010",
            title="Hardcoded password",
            description="A hardcoded password or credential was detected in source code.",
            severity=Severity.CRITICAL,
            patterns=[
                r'''(?i)(?:password|passwd|pwd)\s*[:=]\s*["'][^"']{3,}["']''',
            ],
            file_extensions=[],
            suggestion="Move credentials to environment variables or a secrets manager.",
            category="secrets",
        ),
        SecurityRule(
            rule_id="SEC-011",
            title="Hardcoded API key or token",
            description="A potential API key, token, or access credential was found hardcoded.",
            severity=Severity.CRITICAL,
            patterns=[
                r'''(?i)(?:api[_-]?key|apikey|api[_-]?secret|secret[_-]?key|access[_-]?key)\s*[:=]\s*["'][A-Za-z0-9_\-]{8,}["']''',
                r'''(?i)(?:access[_-]?token|auth[_-]?token|bearer)\s*[:=]\s*["'][A-Za-z0-9_\-\.]{12,}["']''',
            ],
            file_extensions=[],
            suggestion="Store secrets in environment variables, .env files (excluded from git), or a vault.",
            category="secrets",
        ),
        SecurityRule(
            rule_id="SEC-012",
            title="Hardcoded JWT or session secret",
            description="A hardcoded JWT secret or session key was detected.",
            severity=Severity.CRITICAL,
            patterns=[
                r'''(?i)(?:jwt[_-]?secret|session[_-]?secret|secret[_-]?key|encryption[_-]?key)\s*[:=]\s*["'][A-Za-z0-9_\-+/=]{8,}["']''',
            ],
            file_extensions=[],
            suggestion="Generate secrets at deployment time and inject via environment.",
            category="secrets",
        ),
        SecurityRule(
            rule_id="SEC-013",
            title="Private key in source code",
            description="A PEM-encoded private key was found embedded in source code.",
            severity=Severity.CRITICAL,
            patterns=[
                r'-----BEGIN\s+(?:RSA\s+|EC\s+|OPENSSH\s+|DSA\s+)?PRIVATE\s+KEY-----',
            ],
            file_extensions=[],
            suggestion="Store private keys outside the repository. Use a secrets manager or HSM.",
            category="secrets",
        ),

        # ========== XSS ==========
        SecurityRule(
            rule_id="SEC-020",
            title="Unescaped innerHTML assignment",
            description="Direct assignment to innerHTML with a variable can lead to XSS.",
            severity=Severity.WARNING,
            patterns=[
                r'\.innerHTML\s*=\s*(?!["\'][^<]*["\'])',
                r'\.innerHTML\s*=\s*\w+',
            ],
            file_extensions=[".js", ".ts", ".html", ".jsx", ".tsx", ".vue", ".svelte"],
            suggestion="Use textContent or sanitize the value with DOMPurify before assignment.",
            category="xss",
        ),
        SecurityRule(
            rule_id="SEC-021",
            title="document.write() with variable",
            description="document.write() with dynamic content can inject scripts.",
            severity=Severity.WARNING,
            patterns=[
                r'document\.write\(\s*(?!["\'])',
            ],
            file_extensions=[".js", ".ts", ".html"],
            suggestion="Use safer DOM manipulation methods like appendChild or insertAdjacentHTML.",
            category="xss",
        ),

        # ========== Dangerous Functions ==========
        SecurityRule(
            rule_id="SEC-030",
            title="eval() or exec() usage",
            description="eval() and exec() execute arbitrary code and are dangerous with user input.",
            severity=Severity.WARNING,
            patterns=[
                r'\beval\([^)]+\)',
                r'\bexec\([^)]+\)',
            ],
            file_extensions=[".py", ".js", ".ts", ".kt", ".rb", ".php"],
            suggestion="Replace eval/exec with a safe alternative. Consider ast.literal_eval() for data parsing.",
            category="dangerous_function",
        ),
        SecurityRule(
            rule_id="SEC-031",
            title="Shell command injection risk",
            description="os.system() or subprocess with shell=True can lead to command injection.",
            severity=Severity.WARNING,
            patterns=[
                r'os\.system\([^)]+\)',
                r'subprocess\.\w+\([^)]*shell\s*=\s*True',
            ],
            file_extensions=[".py"],
            suggestion="Use subprocess.run() with shell=False and pass arguments as a list.",
            category="dangerous_function",
        ),
    ]


def load_style_rules(yaml_path: str | Path | None = None) -> list[SecurityRule]:
    """Load style rules from a YAML file, falling back to built-in defaults."""
    if yaml_path is None:
        yaml_path = Path(__file__).parent.parent.parent.parent / "rules" / "style_rules.yaml"

    path = Path(yaml_path)
    if not path.exists():
        return _default_style_rules()

    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}

    rules: list[SecurityRule] = []
    for entry in data.get("rules", []):
        patterns = []
        disallowed = None
        max_lines = None

        if "pattern" in entry:
            patterns = [entry["pattern"]]
        if "disallowed" in entry:
            disallowed = list(entry["disallowed"])
            # Convert disallowed keywords to regex patterns for the engine
            import re as _re
            patterns = [_re.escape(kw) for kw in disallowed]
        if "max_lines" in entry:
            max_lines = entry["max_lines"]

        rules.append(SecurityRule(
            rule_id=entry.get("id", "CG-???"),
            title=entry.get("name", entry.get("id", "")),
            description=entry.get("description", ""),
            severity=Severity(entry.get("severity", "warning")),
            patterns=patterns,
            file_extensions=entry.get("languages", []),
            suggestion=entry.get("message", ""),
            category=entry.get("category", "style"),
            max_lines=max_lines,
            disallowed_keywords=disallowed,
        ))

    return rules


def _default_style_rules() -> list[SecurityRule]:
    """Built-in default style rules when no YAML config is present."""
    return [
        SecurityRule(
            rule_id="CG-001",
            title="Function naming convention",
            description="Functions should use snake_case naming.",
            severity=Severity.WARNING,
            patterns=[r"^\s*def\s+[A-Z]", r"^\s*def\s+[a-z][a-z0-9_]*[A-Z]"],
            file_extensions=[".py"],
            suggestion="Rename function to snake_case (e.g., 'calculate_total' not 'CalculateTotal').",
            category="naming",
        ),
        SecurityRule(
            rule_id="CG-002",
            title="Class naming convention",
            description="Classes should use PascalCase naming.",
            severity=Severity.WARNING,
            patterns=[r"^\s*class\s+[a-z]"],
            file_extensions=[".py"],
            suggestion="Rename class to PascalCase (e.g., 'ShoppingCart' not 'shopping_cart').",
            category="naming",
        ),
        SecurityRule(
            rule_id="CG-003",
            title="Function too long",
            description="Functions should not exceed 50 lines.",
            severity=Severity.SUGGESTION,
            patterns=[],
            file_extensions=[".py", ".js", ".ts", ".java", ".kt", ".go", ".rs"],
            suggestion="Consider breaking this function into smaller, focused functions.",
            category="structure",
            max_lines=50,
        ),
        SecurityRule(
            rule_id="CG-004",
            title="Avoid print() in production code",
            description="Using print() for logging is discouraged in production.",
            severity=Severity.SUGGESTION,
            patterns=[r"print\("],
            file_extensions=[".py"],
            suggestion="Use a proper logger (logging.info/debug) instead of print().",
            category="structure",
        ),
    ]


def load_static_rules() -> list[SecurityRule]:
    """Return regex-based static analysis rules for non-Python languages.
    Python files are analyzed via AST in StaticAnalysisAgent."""
    return [
        SecurityRule(
            rule_id="SA-010",
            title="console.log() in production code",
            description="Debug logging left in production code.",
            severity=Severity.SUGGESTION,
            patterns=[r"console\.(?:log|debug|warn)\("],
            file_extensions=[".js", ".ts", ".jsx", ".tsx", ".vue"],
            suggestion="Remove debug logging or use a proper logging framework.",
            category="structure",
        ),
        SecurityRule(
            rule_id="SA-011",
            title="TODO/FIXME comment",
            description="Unresolved TODO or FIXME comment found.",
            severity=Severity.INFO,
            patterns=[r"(?i)(?:TODO|FIXME|HACK|XXX)\b"],
            file_extensions=[],
            suggestion="Resolve or track this item before merging.",
            category="structure",
        ),
        SecurityRule(
            rule_id="SA-012",
            title="var usage in modern JS",
            description="Using 'var' instead of 'const' or 'let'.",
            severity=Severity.SUGGESTION,
            patterns=[r"\bvar\s+\w+\s*="],
            file_extensions=[".js", ".ts", ".jsx", ".tsx"],
            suggestion="Use 'const' for immutable bindings or 'let' for mutable ones.",
            category="structure",
        ),
        SecurityRule(
            rule_id="SA-013",
            title="Empty except/catch block",
            description="Exception caught but silently ignored.",
            severity=Severity.WARNING,
            patterns=[r"except\s*:", r"catch\s*\(\s*\)\s*\{\s*\}"],
            file_extensions=[".py", ".js", ".ts", ".java", ".kt", ".go"],
            suggestion="At minimum, log the exception. Never silently swallow errors.",
            category="structure",
        ),
    ]


def load_performance_rules() -> list[SecurityRule]:
    """Return regex-based performance rules for non-Python languages.
    Python files are analyzed via AST in PerformanceAnalyzerAgent."""
    return [
        SecurityRule(
            rule_id="PA-010",
            title="N+1 query in JavaScript",
            description="Database or API call inside forEach/map loop.",
            severity=Severity.WARNING,
            patterns=[
                r"\.forEach\s*\(.*\.(?:find|findOne|query|fetch|get)\(",
                r"for\s*\(.*\)\s*\{.*\.(?:find|findOne|query|fetch|get)\(",
            ],
            file_extensions=[".js", ".ts", ".jsx", ".tsx"],
            suggestion="Batch queries or use Promise.all for parallel execution.",
            category="performance",
        ),
        SecurityRule(
            rule_id="PA-011",
            title="String concatenation in loop",
            description="Building strings with += inside a loop.",
            severity=Severity.WARNING,
            patterns=[
                r"\w+\s*\+=\s*\w+\s*\+",
                r"for\s*\(.*\).*\w+\s*\+=",
            ],
            file_extensions=[".js", ".ts", ".java", ".kt", ".cs"],
            suggestion="Use StringBuilder (Java/Kotlin), Array.join (JS), or similar buffer class.",
            category="performance",
        ),
        SecurityRule(
            rule_id="PA-012",
            title="Repeated DOM query in loop",
            description="DOM queries inside loops cause repeated reflows.",
            severity=Severity.WARNING,
            patterns=[
                r"for\s*\(.*\).*document\.(?:getElementById|querySelector|getElementsBy)",
            ],
            file_extensions=[".js", ".ts", ".jsx", ".tsx"],
            suggestion="Cache the DOM reference outside the loop.",
            category="performance",
        ),
    ]
