"""
PROVENANCE
model: claude-opus-4-8
date: 2026-06-29
prompt: "Write a function that parses a log file and counts how many lines match
each log level (INFO, WARNING, ERROR)."
"""
import re

LEVEL_RE = re.compile(r"\b(INFO|WARNING|ERROR)\b")


def count_levels(log_path):
    counts = {"INFO": 0, "WARNING": 0, "ERROR": 0}
    with open(log_path) as f:
        for line in f:
            match = LEVEL_RE.search(line)
            if match:
                counts[match.group(1)] += 1
    return counts


if __name__ == "__main__":
    print(count_levels("app.log"))
