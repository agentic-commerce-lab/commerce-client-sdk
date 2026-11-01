"""Verify both implementations with an independent RFC 9421 implementation."""
import base64
import hashlib
import json
from pathlib import Path
import subprocess
import unittest
from dataclasses import asdict
from datetime import timedelta
import requests
from http_message_signatures import HTTPMessageVerifier, HTTPSignatureKeyResolver, algorithms
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from agentic_commerce_ucp import PreparedRequest
from agentic_commerce_ucp.signing import create_signer

ROOT=Path(__file__).resolve().parents[1]
class Resolver(HTTPSignatureKeyResolver):
    def __init__(self,key):self.key=key
    def resolve_public_key(self,key_id):
        if key_id!='test-key':raise ValueError('unknown key')
        return self.key

class SignatureTests(unittest.TestCase):
    def test_independent_verifier_and_tamper_rejection(self):
        for algorithm,key in [(algorithms.ED25519,ed25519.Ed25519PrivateKey.generate()),(algorithms.ECDSA_P256_SHA256,ec.generate_private_key(ec.SECP256R1()))]:
            pem=key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption())
            for language in ('python','typescript'):
                for body in (None,'{"label":"Kaffee ☕"}'):
                    with self.subTest(algorithm=algorithm,language=language,body=body):
                        p=PreparedRequest('create_cart' if body else 'get_cart','POST' if body else 'GET','https://merchant.example/api/v2/carts/order%2F42',body,{'ucp-agent':'profile="https://agent.example/profile.json"',**({'content-type':'application/json','idempotency-key':'repeat-key'} if body else {})},'repeat-key' if body else None)
                        if language=='python':signed=create_signer(key_id='test-key',private_key=pem)(p)
                        else:
                            wire=asdict(p);wire['idempotencyKey']=wire.pop('idempotency_key')
                            if body is None:del wire['body']
                            signed=json.loads(subprocess.check_output(['node',str(ROOT/'tests/sign-typescript.mjs')],input=json.dumps({'privateKey':pem.decode(),'request':wire}).encode()))
                        request=requests.Request(p.method,p.url,headers={**p.headers,**signed},data=body.encode() if body else None).prepare()
                        verifier=HTTPMessageVerifier(signature_algorithm=algorithm,key_resolver=Resolver(key.public_key()))
                        verified=verifier.verify(request,max_age=timedelta(minutes=5))
                        self.assertEqual(verified[0].parameters['keyid'],'test-key')
                        self.assertNotIn('alg',verified[0].parameters)
                        # The covered components a UCP 2026-08-25 verifier requires for this request
                        required=['"@method"','"@authority"','"@path"','"ucp-agent"']+(['"idempotency-key"','"content-digest"','"content-type"'] if body else [])
                        self.assertEqual([name for name in verified[0].covered_components if name!='"@signature-params"'],required)
                        self.assertEqual(verified[0].covered_components['"@authority"'],'merchant.example')
                        self.assertEqual(verified[0].covered_components['"@path"'],'/api/v2/carts/order%2F42')
                        if body:
                            self.assertEqual(signed['content-digest'],'sha-256=:'+base64.b64encode(hashlib.sha256(body.encode()).digest()).decode()+':')
                            request.headers['content-type']='text/plain'
                            with self.assertRaises(Exception):verifier.verify(request)
                            request.headers['content-type']='application/json'
                        request.url='https://merchant.example/other'
                        with self.assertRaises(Exception):verifier.verify(request)

if __name__=='__main__':unittest.main(verbosity=2)
