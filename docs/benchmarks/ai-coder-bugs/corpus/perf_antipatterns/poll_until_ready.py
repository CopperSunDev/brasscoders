"""Drain a stream into an in-memory buffer.

PROVENANCE: AI-generated. Prompt: "Keep reading from the socket and
collect everything." The assistant produced a bare `while True:` that
appends forever with no termination condition, no break, and no size
bound — an unbounded loop that also grows memory without limit. AI
coders routinely omit the bound because the prompt only described the
steady-state read, not the close/error path.

GROUND TRUTH BUG: unbounded_while_loop at line 17 (`while True:` with no
break/return inside the loop body).
"""

from typing import List


def drain(sock) -> List[bytes]:
    chunks: List[bytes] = []
    while True:                       # no break, no timeout, no size cap
        data = sock.recv(4096)
        chunks.append(data)
