"""
PROVENANCE
model: claude-opus-4-8
date: 2026-06-29
prompt: "Write a simple in-memory caching decorator that memoizes a function by
its positional arguments."
"""
import functools


def memoize(func):
    cache = {}

    @functools.wraps(func)
    def wrapper(*args):
        if args in cache:
            return cache[args]
        result = func(*args)
        cache[args] = result
        return result

    return wrapper


@memoize
def fib(n):
    if n < 2:
        return n
    return fib(n - 1) + fib(n - 2)


if __name__ == "__main__":
    print(fib(30))
