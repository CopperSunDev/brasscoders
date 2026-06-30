"""Run a shell report command.

PROVENANCE: AI-generated. Prompt: "Run the report generator script with
the filename the user picked." The assistant used subprocess with
shell=True and an interpolated filename — command injection. AI coders
default to shell=True because it accepts a single string that mirrors
what you'd type in a terminal.

GROUND TRUTH BUG: command_injection at line 13 (subprocess with shell=True
and interpolated user input).
"""

import subprocess


def generate_report(filename: str) -> bytes:
    cmd = "python report.py --input " + filename
    return subprocess.check_output(cmd, shell=True)   # command injection
