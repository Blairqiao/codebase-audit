"""Explicit analyzer execution and bounded evidence parsing."""
from .parsers import ParseResult, parse_report
from .runner import collect_analyzers

__all__ = ["ParseResult", "collect_analyzers", "parse_report"]
