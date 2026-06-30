"""Third-party API client.

PROVENANCE: AI-generated. Prompt: "Set up a client for the payments
API." When the assistant doesn't have an env var to reference, it
frequently hardcodes a placeholder-shaped-but-real-looking secret
directly in the source so the snippet "runs as-is." Here it baked an
AWS-style secret access key into the module.

GROUND TRUTH BUG: hardcoded_secret at line 15 (hardcoded AWS secret key).
The literal below is a synthetic non-functional test value, NOT a real key.
"""

import requests

AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"  # hardcoded


def charge(amount: int) -> dict:
    return requests.post(
        "https://payments.example.com/charge",
        json={"amount": amount},
        headers={"x-api-key": AWS_SECRET_ACCESS_KEY},
    ).json()
