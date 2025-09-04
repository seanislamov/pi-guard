from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from .config import load_config
from .heuristics import compute_heuristic_score
from .policy import decide_action


@dataclass
class GuardContext:
    conversation: Optional[List[Dict[str, str]]] = None  # [{role, content}]
    metadata: Optional[Dict[str, Any]] = None
    config_path: Optional[str] = None


@dataclass
class GuardVerdict:
    action: str  # ALLOW | SANITIZE | BLOCK
    text: str
    score: float
    reasons: List[str]
    hits: Dict[str, int]


def _ml_score_placeholder(_: str, __: GuardContext) -> float:
    # hook for ML model score; returns 0.0 by default for MVP
    return 0.0


def guard(input_text: str, context: Optional[GuardContext] = None) -> GuardVerdict:
    ctx = context or GuardContext()
    config = load_config(ctx.config_path)

    heur = compute_heuristic_score(input_text)
    ml = _ml_score_placeholder(heur.transformed_text, ctx)
    total = max(0.0, min(1.0, heur.score + ml))

    decision = decide_action(total, heur.transformed_text, {
        "block": config.thresholds.block,
        "sanitize": config.thresholds.sanitize,
    })

    return GuardVerdict(
        action=decision.action,
        text=decision.text,
        score=total,
        reasons=decision.reasons,
        hits=heur.hits,
    )