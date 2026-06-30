"""
PROVENANCE
model: claude-opus-4-8
date: 2026-06-29
prompt: "Write a function that signs and verifies a session token using HMAC.
Include a usable example so I can run it."
"""
import hmac
import hashlib

SECRET_KEY = "s3cr3t-signing-key-change-me"


def sign(payload):
    mac = hmac.new(SECRET_KEY.encode(), payload.encode(), hashlib.sha256)
    return mac.hexdigest()


def verify(payload, signature):
    expected = sign(payload)
    return hmac.compare_digest(expected, signature)


if __name__ == "__main__":
    sig = sign("user=42")
    print(verify("user=42", sig))
