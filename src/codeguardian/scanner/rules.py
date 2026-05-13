"""Security rule definitions and built-in rule registry."""

from __future__ import annotations

from dataclasses import dataclass

from codeguardian.models.findings import Severity


@dataclass
class SecurityRule:
    """A single security detection rule."""

    rule_id: str
    title: str
    description: str
    severity: Severity
    patterns: list[str]          # regex patterns applied per-line
    file_extensions: list[str]   # file extensions this rule applies to (empty = all)
    suggestion: str
    category: str                # sql_injection | secrets | xss | dangerous_function


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
            file_extensions=[".py", ".js", ".ts", ".java", ".go", ".rb", ".php", ".cs", ".swift"],
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
            file_extensions=[".py", ".java", ".go", ".rb", ".js", ".ts"],
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
            file_extensions=[".py", ".js", ".ts", ".rb", ".php"],
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
