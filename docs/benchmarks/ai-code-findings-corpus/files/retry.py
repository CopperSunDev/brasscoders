"""
PROVENANCE
model: claude-opus-4-8
date: 2026-06-29
prompt: "Write a retry decorator that retries a function with exponential
backoff on exception."
"""
import time
import functools


def retry(max_attempts=3, base_delay=0.5):
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            attempt = 0
            while True:
                try:
                    return func(*args, **kwargs)
                except Exception:
                    attempt += 1
                    if attempt >= max_attempts:
                        raise
                    time.sleep(base_delay * (2 ** (attempt - 1)))

        return wrapper

    return decorator


@retry(max_attempts=4)
def flaky():
    raise ValueError("boom")
