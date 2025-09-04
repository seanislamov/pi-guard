from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, List, Tuple

from .heuristics import normalize_text


@dataclass
class PolicyDecision:
    action: str  # ALLOW | SANITIZE | BLOCK
    text: str
    reasons: List[str]


def _quote_dangerous_lines(text: str) -> Tuple[str, List[str]]:
    reasons: List[str] = []
    lines = text.splitlines()
    quoted: List[str] = []
    danger_pat = re.compile(r"\b(ignore|disregard|override|forget|reveal|expose|leak|api[ _\-]?keys?)\b", re.I)
    for line in lines:
        if danger_pat.search(line):
            reasons.append("quoted_dangerous_line")
            quoted.append(f"> {line}")
        else:
            quoted.append(line)
    return "\n".join(quoted), reasons


def _redact_tokens(text: str) -> Tuple[str, List[str]]:
    redactions: List[str] = []
    # basic token redaction for keys/paths
    text2 = re.sub(r"(?i)(api[_\- ]?key|secret|password)\s*[:=]\s*\S+", r"\1: [REDACTED]", text)
    if text != text2:
        redactions.append("redacted_sensitive_tokens")
    return text2, redactions


def sanitize_text(text: str) -> Tuple[str, List[str]]:
    sanitized = normalize_text(text)
    sanitized, reasons_a = _quote_dangerous_lines(sanitized)
    sanitized, reasons_b = _redact_tokens(sanitized)
    return sanitized, [*reasons_a, *reasons_b]


def decide_action(total_score: float, text: str, thresholds: Dict[str, float]) -> PolicyDecision:
    if total_score >= thresholds.get("block", 0.85):
        return PolicyDecision(action="BLOCK", text="", reasons=["score_above_block_threshold"]) 
    if total_score >= thresholds.get("sanitize", 0.60):
        sanitized, reasons = sanitize_text(text)
        return PolicyDecision(action="SANITIZE", text=sanitized, reasons=["score_above_sanitize_threshold", *reasons])
    return PolicyDecision(action="ALLOW", text=text, reasons=[])