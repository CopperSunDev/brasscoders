# vulnerable_flask_app

**Synthetic-but-realistic Flask app with known taint vulnerabilities.**

Permanent target in `scripts/benchmark_real_projects.py`. Unlike the
auto-generated `fixture-project`, this lives in git so the same exact source
flows are scanned on every run — useful for tracking interprocedural taint
coverage over time as the semgrep ruleset grows.

The point isn't to be a complete app. It's to exercise the cases where the
sink and the source live in different modules, so pattern-only scanners miss
the connection but taint-mode (semgrep) catches it.

## Planted vulnerabilities

| Route | File chain | Vuln | Expected severity |
|---|---|---|---|
| `GET /users/<user_id>` | `app.py` → `db.py:find_user` | SQL injection (f-string into `cursor.execute`) | CRITICAL |
| `GET /search` | `app.py` → `db.py:search_products` | SQL injection (concatenation) | CRITICAL |
| `POST /run` | `app.py` → `shell.py:run_diagnostic` | Command injection (`shell=True`) | CRITICAL |
| `GET /admin/<table>` | `app.py` → `db.py:dump_table` | SQL injection (table name interpolation) | CRITICAL |

All vulnerabilities are intentional. Do not "fix" them. They are the unit of
measurement.

## Not vulnerable

A handful of correctly-parameterized endpoints + utility code is included so
the precision metric isn't trivially 100% (every finding = real). If
semgrep starts reporting findings on these, the rules have a false-positive
regression.
