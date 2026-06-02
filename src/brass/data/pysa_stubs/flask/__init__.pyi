# Minimal stub for Pyre/Pysa: just enough to anchor third_party.pysa's
# flask.Request.* source models. Pyre treats stub-only modules as
# obscure-model lookups (no AST analysis, no call-graph expansion).
from typing import Any, Dict, Optional

class Request:
    args: Dict[str, Any]
    form: Dict[str, Any]
    values: Dict[str, Any]
    json: Optional[Any]
    data: bytes
    cookies: Dict[str, str]
    headers: Any
    def get_json(self, **kwargs: Any) -> Any: ...

request: Request

def render_template_string(source: str, **kwargs: Any) -> str: ...

class Markup(str):
    # __init__ declared explicitly so the third_party.pysa model
    # (`def flask.Markup.__init__(self, s: TaintSink[XSS])`) has a
    # signature to bind against. Without this, Pyre infers the
    # `object` no-arg __init__ from the inherited str class and
    # rejects the model's `s` parameter.
    def __init__(self, s: str = ...) -> None: ...
