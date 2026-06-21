"""SSRF Collaborator — out-of-band SSRF detection via DNS + HTTP callbacks.

New in V3. The user runs a small HTTP + DNS server (the collaborator) on a
public host. Asynx6 injects unique tokens into SSRF payloads. When the target
makes a request back to the token (because of SSRF), the collaborator records
the interaction, giving us reliable SSRF detection without time-based fuzz.
"""

from asynx6.collaborator.server import CollaboratorServer
from asynx6.collaborator.client import CollaboratorClient
from asynx6.collaborator.tokens import generate_token, build_payload_url

__all__ = [
    "CollaboratorServer",
    "CollaboratorClient",
    "generate_token",
    "build_payload_url",
]