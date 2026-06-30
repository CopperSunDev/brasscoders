"""
PROVENANCE
model: claude-opus-4-8
date: 2026-06-29
prompt: "Write a function that deeply merges two nested dictionaries, with the
second dict taking precedence."
"""


def deep_merge(base, override):
    result = dict(base)
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = value
    return result


if __name__ == "__main__":
    a = {"db": {"host": "localhost", "port": 5432}, "debug": False}
    b = {"db": {"port": 6543}, "debug": True}
    print(deep_merge(a, b))
