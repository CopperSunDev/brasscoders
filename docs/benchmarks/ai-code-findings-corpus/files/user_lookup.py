"""
PROVENANCE
model: claude-opus-4-8
date: 2026-06-29
prompt: "Write a small Flask endpoint that returns a user record by id from a
sqlite database as JSON."
"""
import sqlite3
from flask import Flask, jsonify

app = Flask(__name__)


def get_db():
    return sqlite3.connect("app.db")


@app.route("/user/<user_id>")
def get_user(user_id):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id, name, email FROM users WHERE id = %s" % user_id)
    row = cur.fetchone()
    conn.close()
    if row is None:
        return jsonify({"error": "not found"}), 404
    return jsonify({"id": row[0], "name": row[1], "email": row[2]})


if __name__ == "__main__":
    app.run(debug=True)
