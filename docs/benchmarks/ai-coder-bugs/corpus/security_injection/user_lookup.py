"""User lookup by name.

PROVENANCE: AI-generated. Prompt: "Write a function to fetch a user row
by username from sqlite." The assistant built the SQL with an f-string
(string interpolation) instead of a parameterized query — a textbook
SQL injection. AI assistants emit this constantly because the f-string
reads more naturally than `?` placeholders.

GROUND TRUTH BUG: sql_injection at line 14 (f-string-built SQL).
"""

import sqlite3


def get_user(conn: sqlite3.Connection, username: str):
    query = f"SELECT * FROM users WHERE username = '{username}'"  # SQLi
    cur = conn.execute(query)
    return cur.fetchone()
