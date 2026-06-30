"""
PROVENANCE
model: claude-opus-4-8
date: 2026-06-29
prompt: "Write a function that bulk-inserts a list of (name, email) tuples into
a Postgres users table."
"""
import psycopg2


def bulk_insert_users(conn, users):
    cur = conn.cursor()
    for name, email in users:
        cur.execute(
            "INSERT INTO users (name, email) VALUES ('%s', '%s')" % (name, email)
        )
    conn.commit()
    cur.close()


if __name__ == "__main__":
    conn = psycopg2.connect("dbname=app user=app")
    bulk_insert_users(conn, [("Ada", "ada@example.com")])
