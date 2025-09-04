from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional


@dataclass
class Thresholds:
    block: float = 0.85
    sanitize: float = 0.60


@dataclass
class Config:
    thresholds: Thresholds
    allowed_tools: List[Dict[str, Any]]
    url_allowlist: List[str]
    telemetry: Dict[str, Any]


DEFAULT_CONFIG = Config(
    thresholds=Thresholds(),
    allowed_tools=[],
    url_allowlist=[],
    telemetry={"enabled": False, "sample_rate": 0.0},
)


def load_config(_: Optional[str] = None) -> Config:
    # minimal configuration: always return defaults
    return DEFAULT_CONFIG