"""RFC 9421 signing, available with the `signing` extra."""
import base64
import hashlib
import re
import secrets
import time
from collections.abc import Callable

import httpx
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, utils

from .client import PreparedRequest, Signer

def create_signer(*, key_id: str, private_key: bytes, now: Callable[[], float] = time.time, nonce: Callable[[], str] = lambda: secrets.token_hex(16)) -> Signer:
    key = serialization.load_pem_private_key(private_key, password=None)
    if not isinstance(key, ed25519.Ed25519PrivateKey) and not (isinstance(key, ec.EllipticCurvePrivateKey) and isinstance(key.curve, ec.SECP256R1)):
        raise ValueError("Expected an Ed25519 or P-256 private key")
    if not key_id or re.search(r'["\\\r\n]', key_id):
        raise ValueError("Invalid key ID")

    def signer(request: PreparedRequest) -> dict[str, str]:
        headers = dict(request.headers)
        target = httpx.URL(request.url)
        path, _, query = target.raw_path.decode("ascii").partition("?")
        # The covered components UCP verifiers require: @authority and @path, not @target-uri.
        components = ["@method", "@authority", "@path"] + (["@query"] if query else []) + ["ucp-agent"]
        if request.idempotency_key:
            components.append("idempotency-key")
        if request.body is not None:
            digest = base64.b64encode(hashlib.sha256(request.body.encode()).digest()).decode()
            headers["content-digest"] = f"sha-256=:{digest}:"
            components += ["content-digest", "content-type"]
        signature_nonce = nonce()
        if re.search(r'["\\\r\n]', signature_nonce):
            raise ValueError("Invalid signature nonce")
        identifiers = " ".join(f'"{name}"' for name in components)
        # UCP derives the algorithm from the key; alg is not a Signature-Input parameter.
        parameters = f'({identifiers});created={int(now())};keyid="{key_id}";nonce="{signature_nonce}"'
        values = {"@method": request.method, "@authority": target.netloc.decode("ascii"), "@path": path, "@query": f"?{query}", **headers}
        lines = [f'"{name}": {values[name]}' for name in components]
        lines.append(f'"@signature-params": {parameters}')
        message = "\n".join(lines).encode()
        if isinstance(key, ed25519.Ed25519PrivateKey):
            signature = key.sign(message)
        else:
            r, s = utils.decode_dss_signature(key.sign(message, ec.ECDSA(hashes.SHA256())))
            signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
        result = {"signature-input": f"sig1={parameters}", "signature": "sig1=:" + base64.b64encode(signature).decode() + ":"}
        if request.body is not None:
            result["content-digest"] = headers["content-digest"]
        return result

    return signer
