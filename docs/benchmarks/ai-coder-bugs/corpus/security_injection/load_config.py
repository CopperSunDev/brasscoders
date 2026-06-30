"""Load a pickled config blob.

PROVENANCE: AI-generated. Prompt: "Deserialize the cached config from
disk." The assistant used pickle.loads on file contents — unsafe
deserialization (RCE if the blob is attacker-controlled). AI coders
reach for pickle because it's the first 'serialize any Python object'
answer and the prompt didn't flag the source as untrusted.

GROUND TRUTH BUG: deserialization at line 12 (pickle.loads on file data).
"""

import pickle


def load_config(path: str):
    with open(path, "rb") as fh:
        return pickle.loads(fh.read())   # unsafe deserialization
