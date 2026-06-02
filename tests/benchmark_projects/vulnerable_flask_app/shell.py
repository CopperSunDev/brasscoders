"""Shell helpers — command sinks live here, sources live in app.py."""

import subprocess


_ALLOWED = {"uptime": "uptime", "disk": "df -h", "mem": "vm_stat"}


def run_diagnostic(name):
    """VULN: name is interpolated into a shell string with shell=True."""
    cmd = f"echo running {name}; {_ALLOWED.get(name, name)}"
    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout


def run_diagnostic_safe(name):
    """Same shape, but the binary is whitelisted and the argument is fixed."""
    if name not in _ALLOWED:
        return ""
    return subprocess.run(
        _ALLOWED[name].split(), capture_output=True, text=True
    ).stdout
