"""
BrassCoders — deterministic static-analysis scanners for AI-generated code.

Runs 12 scanners locally (the OSS core makes no outbound network calls) and
emits ranked, AI-consumable YAML so Claude Code, Cursor, or any other coding
assistant can triage what a single-file review structurally can't see on its
own — cross-file taint, hallucinated package imports, and AI-coder
performance anti-patterns among them.
"""

__version__ = "2.0.16"
__author__ = "Copper Sun Brass Team"