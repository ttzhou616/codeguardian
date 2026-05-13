"""Configuration system using pydantic-settings."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import yaml
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from codeguardian.models.findings import ReportFormat, Severity


class AgentConfig(BaseModel):
    """Per-agent configuration."""

    enabled: bool = True
    rules_path: Optional[Path] = None
    custom_rules: list[str] = Field(default_factory=list)
    severity_threshold: Severity = Severity.INFO


class CodeGuardianSettings(BaseSettings):
    """Top-level settings loaded from YAML config and env vars."""

    model_config = SettingsConfigDict(
        env_prefix="CG_",
        env_nested_delimiter="__",
        yaml_file=None,
    )

    # Agent configurations keyed by agent name
    agents: dict[str, AgentConfig] = Field(default_factory=lambda: {
        "static_analysis": AgentConfig(),
        "security_scanner": AgentConfig(),
        "design_reviewer": AgentConfig(),
        "test_reviewer": AgentConfig(severity_threshold=Severity.SUGGESTION),
        "performance_analyzer": AgentConfig(),
        "style_checker": AgentConfig(),
    })

    report_format: ReportFormat = ReportFormat.MARKDOWN
    output_dir: Path = Field(default_factory=lambda: Path("reports"))
    severity_threshold: Severity = Severity.INFO
    max_findings_per_category: int = 50
    fail_on: Optional[Severity] = None  # If set, exit non-zero when findings at this level exist

    # LLM configuration (Phase 2)
    llm_provider: str = "deepseek"
    llm_model: str = "deepseek-v4-pro"
    llm_api_key: Optional[str] = None


def load_config(config_path: Optional[str | Path] = None) -> CodeGuardianSettings:
    """Load configuration from a YAML file, falling back to defaults and env vars."""
    settings = CodeGuardianSettings()

    paths_to_try = [
        Path(config_path) if config_path else None,
        Path.cwd() / ".codeguardian.yaml",
        Path.cwd() / "codeguardian.yaml",
    ]

    for path in paths_to_try:
        if path and path.exists():
            with open(path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
            settings = CodeGuardianSettings(**data)
            break

    return settings


def generate_default_config(output_path: Path) -> None:
    """Write a default YAML config file."""
    default = CodeGuardianSettings()
    data = {
        "agents": {
            name: agent.model_dump(mode="json")
            for name, agent in default.agents.items()
        },
        "report_format": default.report_format.value,
        "output_dir": str(default.output_dir),
        "severity_threshold": default.severity_threshold.value,
        "max_findings_per_category": default.max_findings_per_category,
        "fail_on": None,
    }
    with open(output_path, "w", encoding="utf-8") as f:
        yaml.dump(data, f, default_flow_style=False, allow_unicode=True, sort_keys=False)
