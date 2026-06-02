"""Flask app — routes delegate to helpers in db.py and shell.py.

Taint crosses module boundaries so pattern-only scanners can't catch the
end-to-end flow. See README.md for the planted vulnerabilities.
"""

from flask import Flask, request, jsonify

from db import find_user, search_products, dump_table, find_user_safe
from shell import run_diagnostic

app = Flask(__name__)


@app.route("/users/<user_id>")
def get_user(user_id):
    """Path param flows into db helper → cursor.execute (SQL injection)."""
    return jsonify(find_user(user_id))


@app.route("/users-safe/<user_id>")
def get_user_safe(user_id):
    """Same shape, but goes through the parameterized helper (no finding)."""
    return jsonify(find_user_safe(user_id))


@app.route("/search")
def search():
    """Query arg flows into db helper that uses string concat."""
    term = request.args.get("q", "")
    return jsonify(search_products(term))


@app.route("/run", methods=["POST"])
def run():
    """Form field flows into shell helper that uses shell=True."""
    cmd_name = request.form.get("name", "uptime")
    return jsonify(run_diagnostic(cmd_name))


@app.route("/admin/<table>")
def dump(table):
    """Path param flows into a SELECT * FROM {table} query."""
    return jsonify(dump_table(table))


@app.route("/health")
def health():
    """Boring endpoint — no taint, no sink. Should produce no findings."""
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    app.run()
