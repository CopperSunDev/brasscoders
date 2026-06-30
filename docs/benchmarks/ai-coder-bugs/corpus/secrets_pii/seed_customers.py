"""Seed fixture data for local testing.

PROVENANCE: AI-generated. Prompt: "Give me some sample customer records
to seed the dev database." The assistant invented realistic-looking PII
fixtures, including a Luhn-valid test credit-card number. AI assistants
emit Luhn-valid card numbers (and SSN-shaped strings) in fixtures
because they pattern-match "sample customer" to "looks like a real
record" — and these leak into committed seed scripts.

GROUND TRUTH BUG: pii_exposure at line 16 (Luhn-valid card number) and
line 17 (SSN-shaped value). All values below are synthetic test data.
"""

CUSTOMERS = [
    {
        "name": "Jordan Test",
        "card": "4111111111111111",   # Luhn-valid test card number
        "ssn": "078-05-1120",          # SSN-shaped test value
        "email": "jordan@example.com",
    },
]
