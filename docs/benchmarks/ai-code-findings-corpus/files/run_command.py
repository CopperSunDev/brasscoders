"""
PROVENANCE
model: claude-opus-4-8
date: 2026-06-29
prompt: "Write a helper that runs a shell command given as a string and returns
its stdout."
"""
import subprocess


def run(command):
    result = subprocess.run(
        command, shell=True, capture_output=True, text=True
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr)
    return result.stdout


if __name__ == "__main__":
    print(run("ls -la"))
