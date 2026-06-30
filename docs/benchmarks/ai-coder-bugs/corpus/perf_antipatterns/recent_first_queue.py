"""Most-recent-first activity feed.

PROVENANCE: AI-generated. Prompt: "Build a list where the newest item
is always first." The assistant reached for `list.insert(0, item)` in a
loop instead of `append` + reverse or a `collections.deque` — O(N^2)
because every insert shifts the entire list. Classic AI insert-at-zero
anti-pattern.

GROUND TRUTH BUG: list_insert_zero_loop at line 18 (the `feed.insert(0, ...)`).
"""

from typing import List


def build_feed(events: List[str]) -> List[str]:
    feed: List[str] = []
    for event in events:
        feed.insert(0, event)   # O(N^2): shifts all elements every insert
    return feed
