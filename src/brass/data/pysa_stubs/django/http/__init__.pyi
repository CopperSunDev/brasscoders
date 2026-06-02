from typing import Any, Dict

class HttpRequest:
    GET: Dict[str, Any]
    POST: Dict[str, Any]
    body: bytes
    COOKIES: Dict[str, str]
    headers: Any
