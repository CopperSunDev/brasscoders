from typing import Any

class QuerySet:
    def raw(self, raw_query: str, *args: Any, **kwargs: Any) -> Any: ...
