"""Minimal stdlib fixture for Pysa integration testing.

Plants one taint flow using ONLY stdlib sources/sinks so Pyre doesn't
need third-party type-stub resolution:

  - source: `sys.argv` (modeled in stdlib.pysa as UserControlled)
  - sink:   `sqlite3.Cursor.execute` (modeled in stdlib.pysa as SQL)

If brass's Pysa scanner is functional end-to-end, this fixture should
yield ≥1 SQL-injection finding (rule code 5001). Zero findings means
the stdlib model definitions failed to load — exactly the 2026-05-16
regression class where 8 model lines had stale `path:`/`source:`/etc.
named-parameter syntax that Pyre 0.9.25 silently drops.

A Flask-based fixture would be more representative but would require
adding the customer's site-packages to Pyre's search_path (Pyre then
fully analyzes site-packages → 4× analyzed-function count + 5+ min
runtime on a 3-file project, per a 2026-05-16 spike). Tracked
separately for a stub-only third-party support strategy.
"""

import sqlite3
import sys


def main() -> None:
    query = sys.argv[1]  # bundled source: sys.argv: TaintSource[UserControlled]
    conn = sqlite3.connect(":memory:")
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM users WHERE name='{query}'")  # bundled sink
    print(cur.fetchall())


if __name__ == "__main__":
    main()
