import os
import time
import threading
import json
import base64
import urllib.request
import pytest
import jwt
from http.server import HTTPServer
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_pem_private_key,
)
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers

import main


def b64pad(s: str) -> bytes:
    # Pad base64url string and return bytes
    s = s + "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s.encode())


@pytest.fixture(scope="module")
def server():
    # Ensure DB and keys exist
    main.init_db()

    server = HTTPServer((main.hostName, main.serverPort), main.MyServer)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    # Give server time to start
    time.sleep(0.2)
    yield server
    server.shutdown()
    t.join(timeout=2)


def http_get(path: str) -> bytes:
    url = f"http://{main.hostName}:{main.serverPort}{path}"
    with urllib.request.urlopen(url, timeout=5) as r:
        return r.read()


def http_post(path: str) -> bytes:
    url = f"http://{main.hostName}:{main.serverPort}{path}"
    req = urllib.request.Request(url, method="POST")
    with urllib.request.urlopen(req, timeout=5) as r:
        return r.read()


def test_db_exists():
    # DB should be created in repo root path
    main.init_db()
    assert os.path.exists(main.REPO_ROOT_DB_PATH), "Database file does not exist"
    assert os.path.getsize(main.REPO_ROOT_DB_PATH) > 0


def test_jwks_contains_key(server):
    data = http_get('/.well-known/jwks.json')
    j = json.loads(data)
    assert "keys" in j and isinstance(j["keys"], list)
    assert len(j["keys"]) >= 0


def test_auth_returns_valid_jwt(server):
    token = http_post('/auth').decode('utf-8')
    hdr = jwt.get_unverified_header(token)
    kid = hdr.get('kid')
    assert kid is not None

    jwks = json.loads(http_get('/.well-known/jwks.json'))
    # Find matching key in JWKS
    key = None
    for k in jwks.get('keys', []):
        if k.get('kid') == str(kid):
            key = k
            break
    # If key not in jwks (possible if only expired keys exist), fall back to DB
    pub_pem = None
    if key:
        n = int.from_bytes(b64pad(key['n']), 'big')
        e = int.from_bytes(b64pad(key['e']), 'big')
        pub = RSAPublicNumbers(e, n).public_key()
        pub_pem = pub.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    else:
        # Try to get a valid key from DB
        rows = main.get_valid_keys()
        assert rows, "No valid keys available"
        kid_row, key_blob, _ = rows[0]
        priv = load_pem_private_key(key_blob, password=None)
        pub = priv.public_key()
        pub_pem = pub.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)

    payload = jwt.decode(token, pub_pem, algorithms=['RS256'])
    assert payload.get('user') == 'username'


def test_auth_expired_token_raises_expired(server):
    token = http_post('/auth?expired=1').decode('utf-8')
    hdr = jwt.get_unverified_header(token)
    kid = hdr.get('kid')
    # The expired token is signed with an expired key which won't be in JWKS.
    # Retrieve the expired private key from DB to get the public key for verification.
    key_blob, key_kid, _ = main.get_key(expired=True)
    assert key_blob is not None
    priv = load_pem_private_key(key_blob, password=None)
    pub = priv.public_key()
    pub_pem = pub.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)

    with pytest.raises(jwt.ExpiredSignatureError):
        jwt.decode(token, pub_pem, algorithms=['RS256'])
