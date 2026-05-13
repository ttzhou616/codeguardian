# CodeGuardian

Multi-agent collaborative automated code review system.

## Architecture

CodeGuardian uses a team of specialized agents to review code from different perspectives:

| Agent | Focus |
|-------|-------|
| Static Analysis | Complexity, dead code, type safety |
| Security Scanner | SQL injection, XSS, hardcoded secrets |
| Design Reviewer | SOLID violations, coupling, circular dependencies |
| Test Reviewer | Coverage gaps, boundary conditions |
| Performance Analyzer | N+1 queries, memory leaks, lock contention |
| Style Checker | Naming conventions, code style consistency |

## Quick Start

```bash
pip install -e ".[dev]"

# Initialize a config file
codeguardian init

# Review a directory
codeguardian review --path ./src

# Review a git diff
codeguardian review --diff HEAD~1..HEAD

# Output as JSON
codeguardian review --path ./src --format json
```

## Configuration

Configuration is loaded from `.codeguardian.yaml` in the current directory, or set via environment variables prefixed with `CG_`.
