"""Minimal Flask fixture for Pysa HTTP-framework integration test.

Plants one taint flow using bundled-stub Flask source + bundled stdlib
sink so the test proves the `data/pysa_stubs/` bundle is actually
wiring third_party.pysa's `flask.Request.args` source model into
Pyre's analysis:

  - source: `flask.Request.args.get(...)` (modeled in third_party.pysa,
            resolved via brass's bundled `data/pysa_stubs/flask`)
  - sink:   `sqlite3.Cursor.execute` (modeled in stdlib.pysa)

A `>=1` SQL-injection finding (rule code 5001) confirms the stub-only
search_path approach works end-to-end. Zero findings would mean Pyre
isn't loading the bundled flask stub, the third_party.pysa source
model isn't binding, or the stdlib SQL sink model regressed.
"""

from flask import request
import sqlite3


def search() -> list:
    q = request.args.get("q", "")  # ← bundled-stub Flask source
    conn = sqlite3.connect(":memory:")
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM items WHERE name='{q}'")  # ← stdlib sink
    return cur.fetchall()
