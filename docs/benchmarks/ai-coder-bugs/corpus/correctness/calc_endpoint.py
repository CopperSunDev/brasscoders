"""Tiny expression-evaluation endpoint.

PROVENANCE: AI-generated. Prompt: "Let users submit a math expression
and return the result." The assistant used eval() directly on the
request input — eval-on-input, the single most dangerous AI-coder
correctness/security crossover. It "works" for `2+2` in the demo and is
remote code execution in production.

GROUND TRUTH BUG: code_injection at line 12 (eval on untrusted input).
"""


def evaluate(expression: str) -> float:
    # eval on user input -> arbitrary code execution
    return eval(expression)
