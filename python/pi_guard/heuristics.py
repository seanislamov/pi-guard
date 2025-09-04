from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, List, Tuple
import unicodedata

ZERO_WIDTH_PATTERN = re.compile(r"[\u200b-\u200f\uFEFF]")

@dataclass
class HeuristicResult:
    score: float
    hits: Dict[str, int]
    transformed_text: str

def normalize_text(text: str) -> str:
    # remove zero-widths and fold confusables
    no_zw = ZERO_WIDTH_PATTERN.sub("", text)
    return unicodedata.normalize("NFKC", no_zw)

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
            re.compile(r"\b(reveal|print|expose|show|leak|display|dump|disclose|output)(?:ed|ing|s)?\b[^\n]*\b(system prompts?|secrets?|api[ _\-]?keys?|tokens?)\b", re.I),
            0.60,
        ),
        (
            "tool_hijack",
            re.compile(r"\b(run|call|execute|exec|invoke|spawn)\w*[^\n]*\b(file|shell|powershell|bash|cmd|terminal|browser|tool)\b", re.I),
            0.70,
        ),
        (
            "rag_instruction",
            re.compile(r"(?m)^(to continue|ignore previous|developer note:).*$", re.I),
            0.20,
        ),
        (
            "base64_like",
            re.compile(r"(?=(?:.*[+/=]))(?<![A-Za-z0-9+/])[A-Za-z0-9+/=]{40,}(?![A-Za-z0-9+/])"),
            0.70,
        ),
        (
            "url_exfil",
            re.compile(r"https?://[^\s]+/(upload|collect|ingest|post|report)\b", re.I),
            0.60,
        ),
        (
            "decode_and_run",
            re.compile(r"(?i)\b(decode|base64)\b[^\n]{0,80}\b(run|execute|exec|invoke)\b"),
            0.60,
        ),
        (
            "rag_json_override",
            re.compile(r"(?i)\"system\"\s*:\s*\"[^\"]{0,120}\b(ignore|disregard|override|forget|ignore\s+(rules|policy|safety))\b"),
            0.60,
        ),
        (
            "pipe_shell",
            re.compile(r"\b(curl|wget)\b[^\n]*\|\s*(bash|sh|zsh|powershell|cmd)\b", re.I),
            0.70,
        ),
        (
            "encode_exfil",
            re.compile(r"(?i)\b(base64|encode)\b[^\n]{0,120}https?://[^\s]+/(capture|upload|collect|ingest|post)\b"),
            0.60,
        ),
        (
            "dan_jb",
            re.compile(r"(?i)\b(do[- ]?anything[- ]?now|DAN)\b"),
            0.40,
        ),
        (
            "cookie_exfil",
            re.compile(r"(?i)(cookies?|cookie\s*jar|document\.cookie)\b[^\n]{0,160}https?://\S+"),
            0.60,
        ),
        (
            "csv_formula",
            re.compile(r"(?m)^\s*[=+@-]\s*(hyperlink|webservice|importxml|importrange|cmd|powershell|shell|wget|curl)\b", re.I),
            0.60,
        ),
        (
            "code_env_exfil",
            re.compile(r"(?is)\b(requests\s*\.\s*post|get|put)\b[^\n]+\b(os\s*\.\s*environ)\b"),
            0.60,
        ),
        (
            "intl_override",
            re.compile(r"(?i)(忽略|無視|忽視|忽略所有規則|忽略所有规则|忽略之前的|忽略此前|忽視之前的|忽視此前|ignore\s+les\s+règles|ignore\s+les\s+regles)", re.UNICODE),
            0.60,
        ),
        (
            "intl_exfil",
            re.compile(r"(?i)(系统提示词|系统提示|系统\s*prompt|密钥|金钥|clé|clef|jeton|mot\s*de\s*passe|prompt\s*système)", re.UNICODE),
            0.50,
        ),
        (
            "eval_bait",
            re.compile(r"(?i)\b(quote|verbatim|exact(?:ly)?)\b[^\n]{0,120}\b(system\s*prompt|hidden\s*(prompt|instructions?))\b"),
            0.60,
        ),
        (
            "latex_exec",
            re.compile(r"\\write18\{[^}]*\b(curl|wget)\b[^}]*\}", re.I),
            0.70,
        ),
        (
            "data_uri",
            re.compile(r"(?i)\bdata:[-\w.]+/[-\w.+]+;base64,[A-Za-z0-9+/]+=*"),
            0.60,
        ),
        (
            "sqli_bait",
            re.compile(r"(?i)\b(drop\s+table|union\s+select|or\s+1=1|;--)\b"),
            0.60,
        ),
        (
            "mixed_script_attack",
            re.compile(r"[\u0370-\u03FF\u0400-\u04FF]"),
            0.60,
        ),
        (
            "markdown_js_scheme",
            re.compile(r"\[[^\]]+\]\(\s*javascript:[^\)]+\)", re.I),
            0.60,
        ),
        (
            "js_scheme",
            re.compile(r"(?i)\bjavascript:\s*(fetch|location|window\.open|XMLHttpRequest|eval)"),
            0.60,
        ),
        (
            "css_attr_leak",
            re.compile(r"(?i)(attr\(\s*data-[^\)]*prompt[^\)]*\)|data-system-prompt)"),
            0.60,
        ),
        (
            "dump_config",
            re.compile(r"(?i)\b(dump|print|show|expose)\b[^\n]{0,40}\b(config|configuration|settings?)\b"),
            0.50,
        ),
        (
            "os_url_launch",
            re.compile(r"(?i)\brundll32\b[^\n]*\burl\.dll,FileProtocolHandler\b\s+https?://\S+"),
            0.70,
        ),
        (
            "cookie_exfil",
            re.compile(r"(?i)(?:(?:cookies?|cookie\s*jar|document\.cookie)\b[^\n]{0,160}https?://\S+|https?://\S+[^\n]{0,160}(?:cookies?|document\.cookie))"),
            0.60,
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