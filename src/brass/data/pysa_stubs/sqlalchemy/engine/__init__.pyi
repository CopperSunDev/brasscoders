from typing import Any

class Connection:
    def execute(self, statement: str, *args: Any, **kwargs: Any) -> Any: ...
