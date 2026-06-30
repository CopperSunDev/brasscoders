"""
PROVENANCE
model: claude-opus-4-8
date: 2026-06-29
prompt: "Write a function that sends a templated welcome email to a user over
SMTP."
"""
import smtplib
from email.message import EmailMessage


def send_welcome(to_address, name):
    msg = EmailMessage()
    msg["Subject"] = "Welcome!"
    msg["From"] = "noreply@example.com"
    msg["To"] = to_address
    msg.set_content(f"Hi {name},\n\nThanks for signing up.\n")

    with smtplib.SMTP("smtp.example.com", 587) as server:
        server.starttls()
        server.login("noreply@example.com", "hunter2-mailpassword")
        server.send_message(msg)


if __name__ == "__main__":
    send_welcome("ada@example.com", "Ada")
