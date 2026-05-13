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
git clone https://github.com/ttzhou616/codeguardian.git
cd codeguardian
pip install -e ".[dev]"

# 交互式审查（推荐新手）—— 逐步提示选择路径、Agent、格式
codeg review

# 非交互 —— 一行命令直接跑
codeg review --path ./src --format markdown
```

## Interactive Mode

输入 `codeg review`（不带任何参数）进入四步引导：

```
CodeGuardian Interactive Review
────────────────────────────────────────

1. 请输入要审查的目录或文件路径
   D:\myproject\src

2. 选择审查 Agent
   ┌───┬──────────────────────┬──────────────────────────────────┐
   │ # │ Agent                │ Description                      │
   ├───┼──────────────────────┼──────────────────────────────────┤
   │ 1 │ security_scanner     │ 安全扫描 — SQL注入/密钥/XSS      │
   │ 2 │ static_analysis      │ 静态分析 — 复杂度/嵌套/参数      │
   │ 3 │ style_checker        │ 风格检查 — 命名/函数长度         │
   │ 4 │ design_reviewer      │ 设计审查 — 循环依赖/上帝类       │
   │ 5 │ test_reviewer        │ 测试审查 — 缺失测试/断言         │
   │ 6 │ performance_analyzer │ 性能分析 — N+1查询/循环拼接      │
   │ 0 │ all                  │ 全部运行                         │
   └───┴──────────────────────┴──────────────────────────────────┘
   输入序号 (0=全部, 1-6) [0]: 6

3. 输出格式
   ┌───┬──────────┬────────────────────────────────────┐
   │ # │ Format   │ Description                        │
   ├───┼──────────┼────────────────────────────────────┤
   │ 1 │ markdown │ 可读报告，适合终端查看和文件保存   │
   │ 2 │ json     │ 机器可读，适合 CI 流水线           │
   │ 3 │ sarif    │ SARIF 标准，可导入 GitHub Scanning │
   └───┴──────────┴────────────────────────────────────┘
   选择格式 [1]: 1

4. 保存到文件？ [y/n]: y
   文件名 [review_report.md]: review_report.md

开始审查？ [y/n]: y
```

| 步骤 | 操作 | 说明 |
|------|------|------|
| 1 | 输入路径 | 支持绝对路径、相对路径。路径不存在会提示重新输入 |
| 2 | 选择 Agent | `0`=全部分析，`1-6`=只运行单个 Agent |
| 3 | 输出格式 | markdown（可读）/ json（CI）/ sarif（GitHub Code Scanning） |
| 4 | 保存文件 | 可选保存到文件；不保存则直接输出到终端 |
| — | 确认执行 | 最后确认才真正运行审查 |

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
