"""Render a config-driven HTML snippet.

PROVENANCE: AI-generated. Prompt: "Render this Jinja2 template from a
string." The assistant created a Jinja2 Environment with
autoescape=False, which disables HTML escaping and opens an XSS hole
when any template variable carries user input. AI coders flip
autoescape off because the prompt didn't mention escaping and the
default-off constructor is shorter.

GROUND TRUTH BUG: xss at line 14 (Jinja2 Environment(autoescape=False)).
"""

from jinja2 import Environment


def render(template_str: str, **ctx) -> str:
    env = Environment(autoescape=False)   # XSS: escaping disabled
    template = env.from_string(template_str)
    return template.render(**ctx)
