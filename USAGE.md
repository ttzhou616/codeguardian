# CodeGuardian 使用说明

## 目录

1. [安装](#1-安装)
2. [快速开始](#2-快速开始)
3. [CLI 命令详解](#3-cli-命令详解)
4. [配置文件](#4-配置文件)
5. [六个审查 Agent](#5-六个审查-agent)
6. [高级功能](#6-高级功能)
7. [GitHub CI 集成](#7-github-ci-集成)
8. [常见问题](#8-常见问题)

---

## 1. 安装

### 环境要求

- Python 3.11+
- Git（用于 diff 审查）

### 基础安装

```bash
git clone https://github.com/ttzhou616/codeguardian.git
cd codeguardian
pip install -e ".[dev]"
```

### 全功能安装

```bash
# 包含 Semgrep（2000+ 社区规则）和 ChromaDB（向量知识库）
pip install -e ".[dev,semgrep,vectordb]"
```

可用 extras：
| extra | 作用 |
|-------|------|
| `dev` | 测试、lint（pytest, ruff） |
| `semgrep` | Semgrep CLI，2000+ 社区安全规则 |
| `vectordb` | ChromaDB 向量知识库，持久化误报学习 |

---

## 2. 快速开始

```bash
# 1. 生成配置
codeg init

# 2. 交互式审查（逐步提示：路径→Agent→格式→输出）
codeg review

# 3. 审查一个目录（非交互）
codeg review --path ./src

# 4. 只运行单个 Agent
codeg review --path ./src --only performance_analyzer

# 5. 审查 Git 变更
codeg review --diff HEAD~3..HEAD

# 6. CI 检查（有严重问题返回非零退出码）
codeg check --path ./src --threshold critical

# 7. 查看所有 Agent
codeg agents
```

---

## 3. CLI 命令详解

### `review` — 代码审查

```bash
codeg review [OPTIONS]
```

| 选项 | 说明 | 示例 |
|------|------|------|
| `--path, -p` | 要审查的文件或目录 | `--path ./src` |
| `--diff` | Git diff 范围 | `--diff HEAD~1..HEAD` |
| `--config, -c` | 配置文件路径 | `--config ./my-rules.yaml` |
| `--format, -f` | 输出格式：markdown / json / sarif | `--format json` |
| `--output, -o` | 输出到文件（默认输出到终端） | `--output report.md` |
| `--only` | 只运行指定 Agent | `--only security_scanner` |
| `--interactive, -i` | 显式进入交互模式 | `--interactive` |

#### 交互模式

**触发方式**：不加 `--path` 和 `--diff`，直接输入 `codeg review`。

**完整流程演示：**

```
$ codeg review

CodeGuardian Interactive Review
────────────────────────────────────────

1. 请输入要审查的目录或文件路径: D:\myproject\src
   ✓ D:\myproject\src

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
   ✓ performance_analyzer

                            3. 输出格式
┌───┬──────────┬────────────────────────────────────┐
│ # │ Format   │ Description                        │
├───┼──────────┼────────────────────────────────────┤
│ 1 │ markdown │ 可读报告，适合终端查看和文件保存   │
│ 2 │ json     │ 机器可读，适合 CI 流水线           │
│ 3 │ sarif    │ SARIF 标准，可导入 GitHub Scanning │
└───┴──────────┴────────────────────────────────────┘
选择格式 [1]: 1
   ✓ markdown

4. 保存到文件？ [y/n]: y
文件名 [review_report.md]: review_report.md
   ✓ D:\myproject\review_report.md

────────────────────────────────────────
开始审查？ [y/n]: y

   Review Summary
┌──────────┬───────┐
│ Severity │ Count │
├──────────┼───────┤
│ Warning  │     3 │
└──────────┴───────┘
Total: 3 finding(s)
报告已保存至: D:\myproject\review_report.md
```

**各步骤说明：**

| 步骤 | 输入 | 校验 | 默认值 |
|------|------|------|--------|
| 1. 路径 | 文件或目录的绝对/相对路径 | 路径不存在会重新提示 | 无（必填） |
| 2. Agent | `0`=全部，`1-6`=单个 | 无效数字重新提示 | `0`（全部） |
| 3. 格式 | `1`=markdown，`2`=json，`3`=sarif | — | `1`（markdown） |
| 4. 输出 | y/n + 文件名 | — | `y` + `review_report.{ext}` |
| 确认 | y/n | — | `y` |

#### 非交互模式示例

```bash
# 审查单个文件
codeg review --path src/app.py

# 只运行性能分析
codeg review --path ./src --only performance_analyzer

# 审查整个目录，JSON 格式输出到文件
codeg review --path ./src --format json --output report.json

# 审查 PR 变更
codeg review --diff origin/main...HEAD --format markdown

# 显式进入交互模式（即使指定了 --path）
codeg review --path ./src --interactive
```

**输出格式说明：**

- **markdown**：人类可读的完整报告，含代码片段和建议修复
- **json**：机器可读，适合 CI 流水线解析
- **sarif**：SARIF 2.1.0 标准格式，可导入 GitHub Code Scanning / SonarQube

### `check` — CI 友好检查

```bash
codeg check --path ./src --threshold warning
codeg check --path ./src --threshold critical --only security_scanner
```

退出码：
- `0` — 没有问题（或问题低于阈值）
- `2` — 发现达到阈值的问题
- `1` — 运行错误

```bash
# 在 CI 中使用
codeg check --path ./src --threshold critical || exit 2
```

### `pr-review` — PR 审查

```bash
codeg pr-review [OPTIONS]
```

需要 `GITHUB_TOKEN` 环境变量或已认证的 `gh` CLI。

```bash
# 自动检测当前 PR（在 GitHub Actions 中运行）
codeg pr-review

# 手动指定 PR
codeg pr-review --pr 42 --repo owner/repo

# 指定配置文件
codeg pr-review --pr 42 --config ./codeguardian.yaml
```

审查结果自动以 Comment 形式贴到 PR 中。同一 PR 有新 commit 时会更新已有 Comment。

### `init` — 生成配置文件

```bash
codeg init [--output path]
```

```bash
# 默认位置
codeg init
# → ./.codeguardian.yaml

# 自定义位置
codeg init --output ./config/cg.yaml
```

### `agents` — 列出 Agent

```bash
codeg agents
```

输出：
```
┌──────────────────────┬────────────────────────────────────────────┐
│ Agent                │ Description                                │
├──────────────────────┼────────────────────────────────────────────┤
│ static_analysis      │ Complexity, dead code, type safety         │
│ security_scanner     │ SQL injection, XSS, hardcoded secrets      │
│ design_reviewer      │ SOLID, coupling, architecture patterns     │
│ test_reviewer        │ Coverage gaps, boundary conditions         │
│ performance_analyzer │ N+1 queries, memory leaks, lock contention │
│ style_checker        │ Naming conventions, formatting, consistency│
└──────────────────────┴────────────────────────────────────────────┘
```

### `kb-stats` — 知识库统计

```bash
codeg kb-stats
```

输出：
```
Vector KB: 127 entries, 23 false positives
  Storage: .codeguardian_vectordb
```

---

## 4. 配置文件

配置文件默认加载顺序：
1. `--config` 指定的路径
2. 当前目录的 `.codeguardian.yaml`
3. 当前目录的 `codeguardian.yaml`
4. 环境变量 `CG_*` 覆盖

### 完整配置示例

```yaml
# .codeguardian.yaml

# ── Agent 配置 ──────────────────────────────
agents:
  static_analysis:
    enabled: true
    severity_threshold: info

  security_scanner:
    enabled: true
    severity_threshold: info
    # 自定义规则路径（可选）
    rules_path: ./my-security-rules.yaml

  design_reviewer:
    enabled: true
    severity_threshold: suggestion

  test_reviewer:
    enabled: true
    severity_threshold: suggestion

  performance_analyzer:
    enabled: true
    severity_threshold: info

  style_checker:
    enabled: true
    severity_threshold: info
    # 自定义风格规则
    rules_path: ./rules/style_rules.yaml

# ── 输出配置 ──────────────────────────────
report_format: markdown       # markdown | json | sarif
output_dir: reports
severity_threshold: info      # 过滤低于此级别的发现
max_findings_per_category: 50

# 有 CRITICAL 问题时 CI 退出码 2
fail_on: critical             # critical | warning | suggestion | info

# ── LLM 配置 ──────────────────────────────
llm_provider: deepseek        # deepseek | openai
llm_model: deepseek-chat
llm_api_key: ${CG_LLM_API_KEY}  # 从环境变量读取
```

### 环境变量

所有配置项都可通过环境变量覆盖，前缀为 `CG_`，分隔符为 `__`：

```bash
export CG_REPORT_FORMAT=json
export CG_FAIL_ON=critical
export CG_LLM_API_KEY="sk-xxxx"
export CG_LLM_MODEL="deepseek-v4-pro"
export CG_AGENTS__SECURITY_SCANNER__SEVERITY_THRESHOLD=warning

# Semgrep 规则目录
export CG_SEMGREP_RULES="./custom-semgrep-rules/"
```

---

## 5. 六个审查 Agent

### Security Scanner（安全扫描）

| 规则ID | 检测内容 | 严重级别 |
|--------|---------|---------|
| SEC-001 | 字符串拼接构造 SQL | CRITICAL |
| SEC-002 | f-string / format 拼接 SQL | CRITICAL |
| SEC-003 | 裸 execute() 含变量拼接 | CRITICAL |
| SEC-004 | %s 格式化构造 SQL | CRITICAL |
| SEC-010 | 硬编码密码 | CRITICAL |
| SEC-011 | 硬编码 API Key | CRITICAL |
| SEC-012 | 硬编码 JWT Secret | CRITICAL |
| SEC-013 | 私钥内嵌 | CRITICAL |
| SEC-020 | innerHTML 未转义 | WARNING |
| SEC-021 | document.write() 注入 | WARNING |
| SEC-030 | eval() / exec() | WARNING |
| SEC-031 | os.system() / shell=True | WARNING |

**Semgrep 增强规则**（安装 semgrep 后自动启用，13 条）：

| 规则 | 检测内容 |
|------|---------|
| cg.sqli.* | SQL 注入（f-string / 拼接 / % 格式化） |
| cg.cmd.* | 命令注入（os.system / shell=True） |
| cg.deser.* | 反序列化漏洞（pickle / yaml.load） |
| cg.path.* | 路径遍历 |
| cg.crypto.* | 弱加密算法（MD5 / SHA1） |
| cg.redirect.* | 开放重定向 |
| cg.secrets.* | 密钥泄露 |
| cg.xss.* | XSS（Django mark_safe） |

### Static Analysis（静态分析）

| 规则ID | 检测内容 | 阈值 | 严重级别 |
|--------|---------|------|---------|
| SA-001 | 圈复杂度（McCabe） | >10 | WARNING |
| SA-002 | 函数参数过多 | >5 | SUGGESTION |
| SA-003 | 嵌套深度过深 | >4 | WARNING |
| SA-004 | 裸 except 子句 | — | WARNING |
| SA-005 | 返回语句过多 | >4 | SUGGESTION |
| SA-006 | 局部变量过多 | >10 | SUGGESTION |
| SA-010 | console.log 残留 | — | SUGGESTION |
| SA-011 | TODO / FIXME 标记 | — | INFO |
| SA-012 | var 代替 const / let | — | SUGGESTION |
| SA-013 | 空的 except / catch | — | WARNING |

### Style Checker（风格检查）

| 规则ID | 检测内容 | 严重级别 |
|--------|---------|---------|
| CG-001 | 函数名不符合 snake_case | WARNING |
| CG-002 | 类名不符合 PascalCase | WARNING |
| CG-003 | 函数超过 50 行 | SUGGESTION |
| CG-004 | 使用 print() 代替 logger | SUGGESTION |

### Performance Analyzer（性能分析）

| 规则ID | 检测内容 | 严重级别 |
|--------|---------|---------|
| PA-001 | 循环内数据库查询（N+1） | WARNING |
| PA-002 | 循环内 list.append（应改用推导式） | SUGGESTION |
| PA-003 | 循环内字符串 += 拼接 | WARNING |
| PA-004 | 循环内重复属性访问（应提升） | SUGGESTION |
| PA-005 | range(len(...)) 反模式 | SUGGESTION |
| PA-010 | JS forEach 内 DB 调用 | WARNING |
| PA-011 | 循环内字符串拼接（Java/JS） | WARNING |
| PA-012 | 循环内 DOM 查询 | WARNING |

### Test Reviewer（测试审查）

| 规则ID | 检测内容 | 严重级别 |
|--------|---------|---------|
| TR-001 | 源文件缺少对应测试文件 | SUGGESTION |
| TR-002 | 函数缺少 test_<name> 测试 | INFO |
| TR-003 | 测试文件无断言 | WARNING |
| TR-004 | 测试函数覆盖率 <50% | SUGGESTION |

### Design Reviewer（设计审查）

| 规则ID | 检测内容 | 阈值 | 严重级别 |
|--------|---------|------|---------|
| DR-001 | 模块间循环导入 | — | WARNING |
| DR-002 | 上帝类（方法过多） | >15 | WARNING |
| DR-003 | 高耦合（导入过多） | >12 | SUGGESTION |
| DR-004 | 深层继承 | >3 | SUGGESTION |
| DR-005 | 大抽象类（抽象方法过多） | >6 | SUGGESTION |

---

## 6. 高级功能

### Semgrep 完整集成

```bash
# 安装 Semgrep
pip install codeguardian[semgrep]

# 验证
semgrep --version

# 内置 13 条规则位于 rules/semgrep/
# Security Scanner 自动检测并合并结果

# 使用自定义 Semgrep 规则
export CG_SEMGREP_RULES="./my-semgrep-rules/"
codeg review --path ./src
```

### LLM 智能误报过滤

利用 DeepSeek（或 OpenAI 兼容）API 对发现结果做上下文分析，自动过滤误报。

```bash
# 设置 API Key
export CG_LLM_API_KEY="sk-your-deepseek-key"

# 可选：自定义模型
export CG_LLM_MODEL="deepseek-chat"

# 正常使用，LLM 过滤自动生效
codeg review --path ./src
```

**LLM 能识别的情况：**

- 测试文件中的测试密码、测试数据
- 文档 / 注释中的示例代码
- 安全函数包装器内的危险调用（如 `ast.literal_eval` 内的 `eval`）
- 从环境变量加载的配置（`os.environ["KEY"]`）
- 类型桩文件中的占位代码

**容错设计：**LLM API 不可用时自动跳过，不影响正常审查。

### 向量知识库

```bash
# 安装 ChromaDB
pip install codeguardian[vectordb]

# 查看知识库状态
codeg kb-stats

# 数据存储在 .codeguardian_vectordb/ 目录
# 团队可共享此目录（gitignore 已排除）
```

**与传统 KnowledgeBase 对比：**

| | 内存 KB (默认) | 向量 KB (vectordb) |
|---|---|---|
| 持久化 | 重启丢失 | 本地文件持久 |
| 匹配方式 | 精确（文件+行号+规则ID） | 语义相似度 |
| 代码移动 | 失效 | 仍能匹配 |
| 跨会话 | 不支持 | 支持 |
| 依赖 | 无 | chromadb |
| 共享 | 不支持 | 目录拷贝即可 |

### 自定义规则

**Style 规则**（`rules/style_rules.yaml`）：

```yaml
rules:
  - id: "CG-005"
    name: "no_todo_comments"
    description: "避免在代码中留下 TODO"
    pattern: "(?i)TODO"
    severity: suggestion
    languages: [".py"]
    message: "清理或创建 issue 跟踪此 TODO"
    category: "structure"
```

支持的规则类型：
- `pattern`：正则匹配
- `disallowed`：禁止关键词列表
- `max_lines`：行数限制

---

## 7. GitHub CI 集成

### 方式一：PR 自动审查

仓库中已有 `.github/workflows/pr-review.yml`，无需额外配置。

行为：
1. PR 被创建或更新时自动触发
2. 检出代码，安装 CodeGuardian
3. 运行六个 Agent 对变更文件进行审查
4. 将审查报告作为 PR Comment 贴出
5. 同一 PR 有新 commit 时更新已有 Comment

### 方式二：CI 检查流水线

在 `.github/workflows/ci.yml` 末尾加入：

```yaml
- name: CodeGuardian Check
  run: |
    pip install -e ".[dev]"
    codeg check --path ./src --threshold critical
```

当发现 CRITICAL 问题时流水线失败。

---

## 8. 常见问题

### Q: 如何只启用部分 Agent？

编辑 `.codeguardian.yaml`：

```yaml
agents:
  security_scanner:
    enabled: true
  style_checker:
    enabled: true
  static_analysis:
    enabled: false   # 关闭
  design_reviewer:
    enabled: false
  test_reviewer:
    enabled: false
  performance_analyzer:
    enabled: false
```

### Q: 如何处理误报？

**方式 1：LLM 过滤（推荐）**
设置 `CG_LLM_API_KEY`，LLM 自动分析上下文过滤误报。

**方式 2：向量知识库**
手动标记一次，后续类似发现自动过滤。

**方式 3：调整阈值**
在配置中提高 `severity_threshold`：
```yaml
agents:
  style_checker:
    severity_threshold: warning  # 忽略 suggestion 级别
```

### Q: 审查一个已经很大的仓库太慢？

- 只审查变更文件：`--diff HEAD~1..HEAD`
- 关闭不需要的 Agent
- 确保 semgrep 已安装（内置规则比完整 Semgrep 快很多）

### Q: 如何在 CI 中获取审查报告作为构建产物？

```yaml
- name: CodeGuardian Review
  run: codeg review --path ./src --format sarif --output cg-results.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: cg-results.sarif
```

### Q: Semgrep 扫描失败怎么办？

CodeGuardian 的内置 12 条规则独立运行，不依赖 Semgrep。Semgrep 失败不会影响审查结果，只会在日志中记录 warning。
