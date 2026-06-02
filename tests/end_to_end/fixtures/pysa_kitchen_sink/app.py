"""Kitchen-sink fixture exercising every source × sink shape brass models.

Each flow below uses ONE source (modeled in stdlib.pysa or the bundled
stubs that anchor third_party.pysa) flowing into ONE sink (modeled in
stdlib.pysa or third_party.pysa). All 10 flows should fire a distinct
Pysa finding when brass scans this file.

Counts the integration test expects:
  - At least 8 of 10 findings (allow some slack for Pyre version drift
    around obscure-model behavior on the stub-anchored sources).
  - Coverage across ≥4 distinct rule codes (SQL, Shell, RCE,
    Filesystem, SSRF, XSS).

This is the proof brass's Pysa scanner exercises its full bundled
model surface end-to-end. If a future bundled-model edit breaks one
of these flows, the integration test fails loudly with the source/sink
combo named in the assertion.
"""

import os
import pickle
import sqlite3
import subprocess
import sys
import urllib.request

from flask import request, render_template_string
from django.http import HttpRequest


# --- Flow 1: sys.argv (stdlib UserControlled) → sqlite3.execute (SQL) ---
def f1_argv_to_sql() -> None:
    q = sys.argv[1]
    conn = sqlite3.connect(":memory:")
    conn.cursor().execute(f"SELECT * FROM t WHERE n='{q}'")


# --- Flow 2: os.environ (stdlib UserControlled) → subprocess.run (Shell) ---
def f2_environ_to_subprocess() -> None:
    cmd = os.environ["USER_CMD"]
    subprocess.run(cmd, shell=True)


# --- Flow 3: sys.stdin (stdlib UserControlled) → os.system (Shell) ---
def f3_stdin_to_os_system() -> None:
    line = sys.stdin.readline()
    os.system(line)


# --- Flow 4: flask.Request.args (third-party UserControlled) → sqlite3.execute ---
def f4_flask_args_to_sql() -> None:
    q = request.args.get("q", "")
    sqlite3.connect(":memory:").cursor().execute(f"SELECT * FROM t WHERE n='{q}'")


# --- Flow 5: flask.Request.form (third-party UserControlled) → eval (RCE) ---
def f5_flask_form_to_eval() -> None:
    code = request.form.get("code", "")
    eval(code)


# --- Flow 6: flask.Request.json (third-party UserControlled) → pickle.loads (RCE) ---
def f6_flask_json_to_pickle() -> None:
    payload = request.json
    pickle.loads(payload)


# --- Flow 7: flask.Request.cookies (third-party UserControlled) → open (Filesystem) ---
def f7_flask_cookies_to_open() -> None:
    path = request.cookies.get("filename", "")
    with open(path) as fh:
        fh.read()


# --- Flow 8: flask.Request.args → urllib.urlopen (SSRF) ---
def f8_flask_args_to_urlopen() -> None:
    url = request.args.get("url", "")
    urllib.request.urlopen(url)


# --- Flow 9: flask.Request.form → render_template_string (XSS) ---
def f9_flask_form_to_template_string() -> None:
    template = request.form.get("template", "")
    render_template_string(template)


# --- Flow 10: django.HttpRequest.GET → subprocess.run (Shell) ---
# (Earlier draft used shutil.rmtree as the sink. Pyre 0.9.25 doesn't
# propagate taint into the attribute-syntax sink we have to use for
# shutil.rmtree -- the typeshed signature shape forces attribute
# syntax per stdlib.pysa, and the propagation isn't wired the same
# as a `def` sink. Tracked as a separate Pyre-model limitation.)
def f10_django_get_to_subprocess(req: HttpRequest) -> None:
    target = req.GET.get("target", "")
    subprocess.run(target, shell=True)
