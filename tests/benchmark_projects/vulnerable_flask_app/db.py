"""DB helpers — sinks live here, sources live in app.py.

Type-annotated so interprocedural taint analyzers (Pysa) can resolve
the dispatch from `cur.execute(...)` to `sqlite3.Cursor.execute`.
Without annotations, Pyre's call graph leaves the dispatch unresolved
and the sink model never binds. Vulnerabilities are unchanged.
"""

import sqlite3


def _conn() -> sqlite3.Connection:
    return sqlite3.connect("app.db")


def find_user(user_id: str) -> object:
    """VULN: f-string interpolates a route param into the SQL query."""
    cur: sqlite3.Cursor = _conn().cursor()
    query = f"SELECT id, name, email FROM users WHERE id = {user_id}"
    cur.execute(query)
    return cur.fetchone()


def find_user_safe(user_id: str) -> object:
    """Same shape, parameterized. Should NOT be flagged."""
    cur: sqlite3.Cursor = _conn().cursor()
    cur.execute("SELECT id, name, email FROM users WHERE id = ?", (user_id,))
    return cur.fetchone()


def search_products(term: str) -> object:
    """VULN: string concatenation into a LIKE clause."""
    cur: sqlite3.Cursor = _conn().cursor()
    cur.execute("SELECT id, name FROM products WHERE name LIKE '%" + term + "%'")
    return cur.fetchall()


def dump_table(table: str) -> object:
    """VULN: a table-name path param is dropped into the FROM clause."""
    cur: sqlite3.Cursor = _conn().cursor()
    cur.execute(f"SELECT * FROM {table}")
    return cur.fetchall()


def list_tables() -> object:
    """Utility — no taint, no parameter. Should NOT be flagged."""
    cur: sqlite3.Cursor = _conn().cursor()
    cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
    return [r[0] for r in cur.fetchall()]
