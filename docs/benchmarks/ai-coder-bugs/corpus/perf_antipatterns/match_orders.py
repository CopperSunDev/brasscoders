"""Naive order-matching across three collections.

PROVENANCE: AI-generated. Prompt: "Find every (customer, order, item)
combination where the ids line up." The assistant wrote three nested
loops — O(N^3) — instead of indexing by id with a dict. AI assistants
frequently emit triple-nested loops for join-shaped problems because
the nesting maps directly onto the natural-language description.

GROUND TRUTH BUG: excessive_nested_loops (3 levels) at line 19.
"""

from typing import List, Tuple


def match(customers: List[dict], orders: List[dict],
          items: List[dict]) -> List[Tuple]:
    matched = []
    for c in customers:
        for o in orders:
            for it in items:                       # 3-level nest -> O(N^3)
                if c["id"] == o["customer_id"] and o["id"] == it["order_id"]:
                    matched.append((c, o, it))
    return matched
