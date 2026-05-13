# CodeGuardian

Multi-agent collaborative automated code review system. Six specialized agents analyze code from different perspectives, with optional Semgrep, LLM filtering, and vector knowledge base.

[![CI](https://github.com/ttzhou616/codeguardian/actions/workflows/ci.yml/badge.svg)](https://github.com/ttzhou616/codeguardian/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/)
[![Tests](https://img.shields.io/badge/tests-78%20passed-green)](https://github.com/ttzhou616/codeguardian)

---

## Architecture

```
                      +--------------------+
   git diff / path -->|   Orchestrator     |--- parallel dispatch
                      +--------------------+
                              |
         +----------+---------+---------+----------+----------+
         |          |         |         |          |          |
    Security    Static     Style     Design     Test     Performance
    Scanner    Analysis   Checker   Reviewer   Reviewer   Analyzer
         |          |         |         |          |          |
         +----------+---------+---------+----------+----------+
                              |
                      +--------v--------+
                      |   Synthesizer   | (dedup + prioritize)
                      +--------+--------+
                               |
                      +--------v--------+
                      | LLM Filter      | (optional DeepSeek)
                      +--------+--------+
                               |
                      +--------v--------+
                      |   Reporter      | (Markdown/JSON/SARIF)
                      +-----------------+
```

## Six Agents

| Agent | What It Checks | Rules | Python | JS/TS | Java | Go |
|-------|---------------|-------|--------|-------|------|----|
| **Security Scanner** | SQL injection, hardcoded secrets, XSS, command injection, weak crypto | 25 | AST + Regex | Regex | -- | -- |
| **Static Analysis** | Cyclomatic complexity, nesting depth, parameter count, bare excepts | 10 | AST | Regex | -- | -- |
| **Style Checker** | Naming conventions, function length, print() usage | 4 | Regex | Regex | -- | -- |
| **Performance Analyzer** | N+1 queries, string concatenation in loops, range(len), DOM in loops | 8 | AST | Regex | -- | -- |
| **Test Reviewer** | Missing test files, untested functions, no assertions, low coverage | 4 | File map + AST | -- | -- | -- |
| **Design Reviewer** | Circular imports, god classes, high coupling, deep inheritance | 5 | AST | -- | -- | -- |

**Total: 56 built-in rules + 21 Semgrep rules = 77 rules. 78 tests.**

## Quick Start

```bash
# Clone and install
git clone https://github.com/ttzhou616/codeguardian.git
cd codeguardian
pip install -e ".[dev]"

# Generate config
codeg init

# Interactive review (step-by-step prompts)
codeg review

# Review a directory (non-interactive)
codeg review --path ./src

# Run a single agent
codeg review --path ./src --only performance_analyzer

# Review git changes
codeg review --diff HEAD~3..HEAD --format markdown

# CI check (non-zero exit on issues)
codeg check --path ./src --threshold critical

# List agents
codeg agents
```

## CLI Commands

| Command | Purpose |
|---------|---------|
| `review` | Review code, output report (markdown/json/sarif) |
| `check` | CI-friendly: exit code 2 if issues found above threshold |
| `pr-review` | Review a GitHub PR and post results as comment |
| `init` | Generate `.codeguardian.yaml` config file |
| `agents` | List all review agents |
| `kb-stats` | Show knowledge base statistics |

## Configuration

```yaml
# .codeguardian.yaml
agents:
  security_scanner:
    enabled: true
    severity_threshold: info
  static_analysis:
    enabled: true
  # ... (style_checker, design_reviewer, test_reviewer, performance_analyzer)

report_format: markdown          # markdown | json | sarif
severity_threshold: info         # info | suggestion | warning | critical
fail_on: null                    # set to e.g. 'critical' to fail CI

# LLM filter (optional)
llm_provider: deepseek           # deepseek | openai
llm_model: deepseek-chat
llm_api_key: ${CG_LLM_API_KEY}   # from env var
```

All settings overridable via `CG_` prefixed env vars:

```bash
export CG_LLM_API_KEY="sk-xxxx"
export CG_FAIL_ON="warning"
```

## System Features

### GitHub PR Review
Automatic PR review via GitHub Actions (`.github/workflows/pr-review.yml`). Posts findings as PR comments; updates on new commits.

### Semgrep Integration
Install with `pip install codeguardian[semgrep]`. Security Scanner automatically runs bundled Semgrep rules alongside built-in checks.

### LLM False-Positive Filter
Set `CG_LLM_API_KEY` to enable DeepSeek/OpenAI-based context analysis. The LLM distinguishes test data, docstrings, and safe wrappers from real vulnerabilities.

### Vector Knowledge Base
Install with `pip install codeguardian[vectordb]`. ChromaDB-backed persistent storage with semantic search. Past false positives are auto-suppressed even when code moves.

## Install Options

```bash
pip install -e ".[dev]"              # tests + lint
pip install -e ".[dev,semgrep]"      # + Semgrep (2000+ community rules)
pip install -e ".[dev,semgrep,vectordb]"  # full install
```

## GitHub CI Integration

```yaml
# .github/workflows/ci.yml
- name: CodeGuardian Check
  run: |
    pip install -e ".[dev]"
    codeg check --path ./src --threshold critical
```

For PR comments and SARIF upload, see [USAGE.md](USAGE.md).
