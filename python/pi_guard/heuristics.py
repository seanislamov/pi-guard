from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, List, Tuple

ZERO_WIDTH_PATTERN = re.compile(r"[\u200b-\u200f\uFEFF]")

@dataclass
class HeuristicResult:
    score: float
    hits: Dict[str, int]
    transformed_text: str

def normalize_text(text: str) -> str:
    # remove zero-width and similar hidden characters
    return ZERO_WIDTH_PATTERN.sub("", text)

def _regex_count(text: str, pattern: re.Pattern) -> int:
    return len(list(pattern.finditer(text)))

def compute_heuristic_score(text: str) -> HeuristicResult:
    clean_text = normalize_text(text)

    patterns: List[Tuple[str, re.Pattern, float]] = [
        (
            "instruction_override",
            re.compile(r"\b(ignore|disregard|override|forget)\b[^\n]*\b(instructions?|policy|system)\b", re.I),
            0.35,
        ),
        (
            "exfiltration",
            re.compile(r"\b(reveal|print|expose|show|leak)\b[^\n]*\b(system prompts?|secrets?|api[ _\-]?keys?)\b", re.I),
            0.30,
        ),
        (
            "tool_hijack",
            re.compile(r"\b(run|call|execute)\b[^\n]*\b(file|shell|browser|tool)\b", re.I),
            0.25,
        ),
        (
            "rag_instruction",
            re.compile(r"(?m)^(to continue|ignore previous|developer note:).*$", re.I),
            0.20,
        ),
        (
            "base64_like",
            re.compile(r"(?m)^[A-Za-z0-9+/=]{60,}$"),
            0.20,
        ),
    ]

    hits: Dict[str, int] = {}
    score = 0.0
    for name, pat, weight in patterns:
        count = _regex_count(clean_text, pat)
        if count:
            hits[name] = count
            # cap contribution per rule to avoid runaway
            score += min(1, count) * weight

    # length and repetition heuristics
    token_like = re.findall(r"\w+", clean_text)
    if len(clean_text) > 4000:
        hits["very_long"] = 1
        score += 0.10
    if token_like:
        most_common = max([token_like.count(t) for t in set(token_like)])
        if most_common > max(10, 0.2 * len(token_like)):
            hits["low_entropy_repeat"] = 1
            score += 0.10

    return HeuristicResult(score=min(score, 1.0), hits=hits, transformed_text=clean_text)