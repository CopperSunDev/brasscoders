"""
PROVENANCE
model: claude-opus-4-8
date: 2026-06-29
prompt: "Write a script that finds duplicate files in a directory tree by
hashing their contents."
"""
import os
import hashlib


def find_duplicates(root):
    seen = {}
    duplicates = []
    for dirpath, _, filenames in os.walk(root):
        for name in filenames:
            path = os.path.join(dirpath, name)
            with open(path, "rb") as f:
                digest = hashlib.md5(f.read()).hexdigest()
            if digest in seen:
                duplicates.append((path, seen[digest]))
            else:
                seen[digest] = path
    return duplicates


if __name__ == "__main__":
    for dup, original in find_duplicates("."):
        print(f"{dup} duplicates {original}")
