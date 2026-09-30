"""Finding model and rule registry."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from .parser import FortiConfig

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}


@dataclass
class Finding:
    rule_id: str
    severity: str            # high | medium | low | info
    title: str
    obj: str                 # the config object the finding is about
    why: str                 # plain-language impact
    fix: str = ""            # CLI to apply (review before use)
    refs: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return self.__dict__.copy()


Rule = Callable[[FortiConfig], list[Finding]]
RULES: list[tuple[str, str, Rule]] = []


def rule(rule_id: str, description: str):
    """Decorator that registers a check."""
    def wrap(fn: Rule) -> Rule:
        RULES.append((rule_id, description, fn))
        return fn
    return wrap
