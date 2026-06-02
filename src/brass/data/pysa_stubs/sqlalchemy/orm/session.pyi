from typing import Any

class Session:
    def execute(self, statement: str, *args: Any, **kwargs: Any) -> Any: ...
