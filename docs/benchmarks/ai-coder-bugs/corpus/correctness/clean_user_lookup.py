"""CONTROL SAMPLE — the correct version of user_lookup.py.

PROVENANCE: AI-generated, then corrected. Parameterized query, no
interpolation. Carries NO planted bug.

GROUND TRUTH: zero expected findings. Used to measure false-positive
pressure on the security comparators (Bandit/Semgrep).
"""

import sqlite3


def get_user(conn: sqlite3.Connection, username: str):
    cur = conn.execute(
        "SELECT * FROM users WHERE username = ?", (username,)
    )
    return cur.fetchone()
