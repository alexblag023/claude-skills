#!/usr/bin/env python3
"""blind_rules.py — общие правила распознавания самоидентификации модели.

Один источник правды для трех скриптов (anonymize, validate_answers, check_run):
если правила разъедутся, слепота перестанет работать. Набор признаков общий,
режимы поиска различаются: в anonymize нужно снять строку, в проверках — найти.

Признак — строка, в которой модель называет себя: "As an AI", "I am Claude",
"как язызовая модель", "моя версия" и подобное. Признак ищется ВНУТРИ строки, а не
только в её начале: фраза может стоять в середине предложения.
"""
from __future__ import annotations

import re

# Признаки самоидентификации: регулярные выражения для поиска в тексте.
SELF_ID_PATTERNS = [
    r"\bas an ai\b",
    r"\bi am an ai\b",
    r"\bi am (?:a |an )?(?:large language model|llm|ai assistant|assistant)\b",
    r"\bi am (?:gpt|claude|gemini|qwen|llama|mistral|deepseek|kimi|grok)\b",
    r"\bas (?:gpt|claude|gemini|qwen|llama|mistral|deepseek|kimi|grok)\b",
    r"\bmy model\b",
    r"\bi was trained by\b",
    r"\bкак (?:языковая |большая )?модель\b",
    r"\bмоя версия\b",
    r"\bя — (?:gpt|claude|gemini|qwen|llama|mistral|deepseek|kimi|grok|ии|ai)\b",
    r"\bchatgpt\b",
    r"\bcopilot\b",
]

# Регулярное выражение для снятия строки целиком (MULTILINE).
SELF_ID_LINE_RE = re.compile(
    r"^.*(?:" + "|".join(SELF_ID_PATTERNS) + r").*$",
    re.IGNORECASE | re.MULTILINE,
)

PLACEHOLDER = "[идентификация удалена]"


def find_self_identification(text: str):
    """Возвращает первое совпадение признака самоидентификации или None."""
    lowered = text.lower()
    for pattern in SELF_ID_PATTERNS:
        match = re.search(pattern, lowered)
        if match:
            return match
    return None


def strip_self_identification(text: str) -> tuple[str, int]:
    """Убирает строки с самоидентификацией. Возвращает текст и число таких строк."""
    cleaned = SELF_ID_LINE_RE.sub(PLACEHOLDER, text)
    removed = len(SELF_ID_LINE_RE.findall(text))
    return cleaned, removed
