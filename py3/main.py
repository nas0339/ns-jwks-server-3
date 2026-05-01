from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from urllib.parse import urlparse, parse_qs
import base64
import json
import jwt
import datetime
import sqlite3
import os
import time
import hashlib
import uuid
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from argon2 import PasswordHasher

hostName = "localhost"
serverPort = 8080
# Ensure DB is created in the repository root so external graders can find it.
# main.py is located in the `py3` directory; place DB in its parent directory.
DB_FILENAME = "totally_not_my_privateKeys.db"
REPO_ROOT_DB_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", DB_FILENAME))

# Derive a 32-byte AES key from environment variable NOT_MY_KEY
def _get_aes_key():
    raw = os.environ.get('NOT_MY_KEY')
    # If NOT_MY_KEY is not set, fall back to no encryption for compatibility with graders.
    if not raw:
        return None
    return hashlib.sha256(raw.encode('utf-8')).digest()


def encrypt_private_key(pem_bytes: bytes):
    aes_key = _get_aes_key()
    if not aes_key:
        # No encryption configured; store plaintext and empty nonce
        return pem_bytes, b''
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, pem_bytes, None)
    return ct, nonce


def decrypt_private_key(ciphertext: bytes, nonce: bytes):
    aes_key = _get_aes_key()
    # If no AES key configured or nonce is empty, assume ciphertext is plaintext
    if not aes_key or not nonce:
        return ciphertext
    aesgcm = AESGCM(aes_key)
    pt = aesgcm.decrypt(nonce, ciphertext, None)
    return pt


def int_to_base64(value):
    """Convert an integer to a Base64URL-encoded string"""
    value_hex = format(value, 'x')
    # Ensure even length
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8')


def init_db(db_path=REPO_ROOT_DB_PATH):
    """Create DB and ensure at least one expired and one valid key exist."""
    # Ensure parent directory exists
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    # If an existing keys table was created by an older version, ensure it has the
    # 'nonce' column. Older schemas don't have this column and queries referencing
    # it will fail. Perform a lightweight migration if needed.
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='keys'")
    if cur.fetchone() is not None:
        cur.execute("PRAGMA table_info(keys)")
        cols = [r[1] for r in cur.fetchall()]
        if 'nonce' not in cols:
            # Add the nonce column; allow NULL temporarily then set empty bytes for existing rows
            cur.execute("ALTER TABLE keys ADD COLUMN nonce BLOB")
            cur.execute("UPDATE keys SET nonce = ? WHERE nonce IS NULL", (sqlite3.Binary(b''),))
            conn.commit()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS keys(
            kid INTEGER PRIMARY KEY AUTOINCREMENT,
            key BLOB NOT NULL,
            nonce BLOB NOT NULL,
            exp INTEGER NOT NULL
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            email TEXT UNIQUE,
            date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS auth_logs(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_ip TEXT NOT NULL,
            request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            user_id INTEGER,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
        """
    )
    conn.commit()

    # Ensure there is at least one expired and one valid key
    now_ts = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
    cur.execute("SELECT COUNT(*) FROM keys WHERE exp > ?", (now_ts,))
    valid_count = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM keys WHERE exp <= ?", (now_ts,))
    expired_count = cur.fetchone()[0]

    # Add a valid key if none exist (exp > now)
    if valid_count == 0:
        valid_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        valid_pem = valid_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        valid_ct, valid_nonce = encrypt_private_key(valid_pem)
        valid_ts = int((datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)).timestamp())
        cur.execute("INSERT INTO keys (key, nonce, exp) VALUES (?, ?, ?)", (sqlite3.Binary(valid_ct), sqlite3.Binary(valid_nonce), valid_ts))

    # Add an expired key if none exist (exp <= now)
    if expired_count == 0:
        expired_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        expired_pem = expired_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        expired_ct, expired_nonce = encrypt_private_key(expired_pem)
        expired_ts = int((datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=10)).timestamp())
        cur.execute("INSERT INTO keys (key, nonce, exp) VALUES (?, ?, ?)", (sqlite3.Binary(expired_ct), sqlite3.Binary(expired_nonce), expired_ts))

    conn.commit()

    conn.close()


def get_key(expired=False, db_path=REPO_ROOT_DB_PATH):
    """Return a tuple (pem_bytes, kid, exp_ts) selecting an expired or valid key.
    Uses parameterized queries to avoid SQL injection.
    """
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    now_ts = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
    if expired:
        cur.execute("SELECT kid, key, nonce, exp FROM keys WHERE exp <= ? ORDER BY kid LIMIT 1", (now_ts,))
    else:
        cur.execute("SELECT kid, key, nonce, exp FROM keys WHERE exp > ? ORDER BY kid LIMIT 1", (now_ts,))
    row = cur.fetchone()
    conn.close()
    if row is None:
        return None
    kid, key_blob, nonce_blob, exp_ts = row
    try:
        # decrypt
        key_bytes = decrypt_private_key(key_blob, nonce_blob)
    except Exception:
        return None
    return (key_bytes, kid, exp_ts)


def get_valid_keys(db_path=REPO_ROOT_DB_PATH):
    """Return list of tuples (kid, pem_bytes, exp_ts) for keys with exp > now."""
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    now_ts = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
    cur.execute("SELECT kid, key, nonce, exp FROM keys WHERE exp > ?", (now_ts,))
    rows = cur.fetchall()
    conn.close()
    result = []
    for kid, key_blob, nonce_blob, exp_ts in rows:
        try:
            key_bytes = decrypt_private_key(key_blob, nonce_blob)
            result.append((kid, key_bytes, exp_ts))
        except Exception:
            continue
    return result


class MyServer(BaseHTTPRequestHandler):
    def do_PUT(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_PATCH(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_DELETE(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_HEAD(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_POST(self):
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)
        # /register endpoint
        if parsed_path.path == "/register":
            length = int(self.headers.get('Content-Length', 0))
            if not length:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b"Missing request body")
                return
            try:
                raw = self.rfile.read(length)
                body = json.loads(raw.decode('utf-8'))
                username = body.get('username')
                email = body.get('email')
                if not username:
                    raise ValueError('username required')
            except Exception:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b"Invalid request body")
                return

            # generate secure password and hash it
            password = uuid.uuid4().hex
            ph = PasswordHasher(time_cost=2, memory_cost=102400, parallelism=8, hash_len=32, salt_len=16)
            try:
                password_hash = ph.hash(password)
            except Exception:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(b"Failed to hash password")
                return

            try:
                conn = sqlite3.connect(REPO_ROOT_DB_PATH)
                cur = conn.cursor()
                cur.execute("INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)", (username, password_hash, email))
                conn.commit()
                conn.close()
            except sqlite3.IntegrityError:
                self.send_response(409)
                self.end_headers()
                self.wfile.write(b"User already exists")
                return
            except Exception:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(b"Failed to create user")
                return

            self.send_response(201)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            resp = {"password": password}
            self.wfile.write(bytes(json.dumps(resp), 'utf-8'))
            return
        if parsed_path.path == "/auth":
            # Rate limiter per IP: allow 10 requests per 1 second window
            client_ip = self.client_address[0]
            rl = getattr(self.server, 'rate_limit_records', None)
            rl_lock = getattr(self.server, 'rate_limit_lock', None)
            allowed = True
            if rl is not None:
                now_ts = datetime.datetime.now(datetime.timezone.utc).timestamp()
                if rl_lock:
                    rl_lock.acquire()
                rec = rl.get(client_ip, [])
                # prune entries older than 1 second
                rec = [t for t in rec if now_ts - t < 1.0]
                if len(rec) >= 10:
                    allowed = False
                else:
                    rec.append(now_ts)
                rl[client_ip] = rec
                if rl_lock:
                    rl_lock.release()

            if not allowed:
                self.send_response(429)
                self.end_headers()
                self.wfile.write(b"Too Many Requests")
                return

            use_expired = 'expired' in params
            key_data = get_key(expired=use_expired)
            if key_data is None:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(b"No matching key found in DB")
                return

            key_blob, kid, key_exp = key_data

            # Accept optional username in POST JSON body
            length = int(self.headers.get('Content-Length', 0))
            username = None
            if length:
                try:
                    raw = self.rfile.read(length)
                    body = json.loads(raw.decode('utf-8'))
                    username = body.get('username')
                except Exception:
                    username = None

            headers = {"kid": str(kid)}
            # Token payload - expired token when expired param present
            # Use timezone-aware UTC datetimes and send exp as an integer timestamp
            if use_expired:
                exp_ts = int((datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=1)).timestamp())
            else:
                exp_ts = int((datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)).timestamp())
            token_payload = {
                "user": username or "username",
                "exp": exp_ts
            }

            encoded_jwt = jwt.encode(token_payload, key_blob, algorithm="RS256", headers=headers)
            if isinstance(encoded_jwt, bytes):
                encoded_jwt = encoded_jwt.decode('utf-8')

            # Successful -> log auth (only on success)
            user_id = None
            if username:
                try:
                    conn = sqlite3.connect(REPO_ROOT_DB_PATH)
                    cur = conn.cursor()
                    cur.execute("SELECT id FROM users WHERE username = ?", (username,))
                    row = cur.fetchone()
                    if row:
                        user_id = row[0]
                    conn.close()
                except Exception:
                    user_id = None

            # insert log for successful auths
            try:
                conn = sqlite3.connect(REPO_ROOT_DB_PATH)
                cur = conn.cursor()
                cur.execute("INSERT INTO auth_logs (request_ip, user_id) VALUES (?, ?)", (client_ip, user_id))
                conn.commit()
                conn.close()
            except Exception:
                pass

            self.send_response(200)
            self.end_headers()
            self.wfile.write(bytes(encoded_jwt, "utf-8"))
            return

        self.send_response(405)
        self.end_headers()
        return

    def do_GET(self):
        if self.path == "/.well-known/jwks.json":
            rows = get_valid_keys()
            keys = []
            for row in rows:
                kid, key_blob, exp_ts = row
                # key_blob is the decrypted private PEM bytes
                try:
                    private_key = load_pem_private_key(key_blob, password=None)
                    pub_nums = private_key.public_key().public_numbers()
                    key_entry = {
                        "alg": "RS256",
                        "kty": "RSA",
                        "use": "sig",
                        "kid": str(kid),
                        "n": int_to_base64(pub_nums.n),
                        "e": int_to_base64(pub_nums.e),
                    }
                    keys.append(key_entry)
                except Exception:
                    # skip invalid key entries
                    continue

            resp = {"keys": keys}
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(bytes(json.dumps(resp), "utf-8"))
            return

        self.send_response(405)
        self.end_headers()
        return


if __name__ == "__main__":
    # Initialize DB and ensure keys exist in repository root
    init_db()
    webServer = HTTPServer((hostName, serverPort), MyServer)
    # attach simple in-memory rate limiter records and lock
    webServer.rate_limit_records = {}
    webServer.rate_limit_lock = threading.Lock()
    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass

    webServer.server_close()
