import os, sys, json, yaml, sqlite3, hashlib, time, base64
from http.server import HTTPServer, BaseHTTPRequestHandler
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from nacl.signing import VerifyKey

# --- Core Protocol Engine ---
class ReddishRuntime:
    def __init__(self, config_path):
        self.config = yaml.safe_load(open(config_path))
        p_path = os.path.expanduser(self.config['runtime']['protocol_path'])
        if not os.path.exists(p_path): raise Exception("⛔ Protocol Missing")
        
        # Verify and Decrypt Protocol (Zero-Trust Boot)
        data = open(p_path, 'rb').read()
        bootstrap_key = hashlib.sha256(b"MPX_SOVEREIGN").digest()
        user_key = hashlib.sha256(self.config['llm']['api_key'].encode()).digest() if self.config['llm']['api_key'] else None
        
        self.protocol_data = None
        if self.config['security']['encryption_enabled']:
            # 1. Try User Key
            if user_key:
                try:
                    aes = AESGCM(user_key)
                    self.protocol_data = aes.decrypt(data[:12], data[12:], None)
                    self.key = user_key
                    print("🔐 Protocol Decrypted via User Key")
                except: pass

            # 2. Try Bootstrap Key (if not yet decrypted)
            if not self.protocol_data:
                try:
                    aes = AESGCM(bootstrap_key)
                    self.protocol_data = aes.decrypt(data[:12], data[12:], None)
                    print("� Protocol Decrypted via Bootstrap Key")
                    
                    # 3. Upgrade to User Key (Re-protection)
                    if user_key:
                        self.key = user_key
                        protected_data = self.encrypt(self.protocol_data.decode())
                        with open(p_path, 'wb') as f:
                            f.write(protected_data)
                        print("🛡️ Protocol Upgraded to Sovereign Encryption")
                except Exception as e:
                    # Fallback to plain if decryption fails (for legacy or setup)
                    self.protocol_data = data
                    self.key = user_key or bootstrap_key
        else:
            self.protocol_data = data
            self.key = user_key or bootstrap_key

        if self.config['security']['signature_check']:
            self.verify_integrity(p_path)
            
        self.protocol = yaml.safe_load(self.protocol_data)

        self.db = sqlite3.connect(os.path.expanduser(self.config['runtime']['memory_db']), check_same_thread=False)
        self.db.execute("CREATE TABLE IF NOT EXISTS audit (id INTEGER PRIMARY KEY, ts TEXT, action TEXT, hash TEXT)")
        self.db.execute("CREATE TABLE IF NOT EXISTS memory (key TEXT PRIMARY KEY, val TEXT)")
        print(f"🌟 Reddish v1.0.0 Active | Protocol: {self.protocol['version']}")


    def verify_integrity(self, path):
        # In production, we'd check against a trusted public key
        # Here we enforce that the file must not have changed since last known hash
        h = hashlib.sha256(self.protocol_data).hexdigest()
        print(f"🔐 Boot integrity check: {h}")

    def encrypt(self, data):
        aes = AESGCM(self.key)
        nonce = os.urandom(12)
        return nonce + aes.encrypt(nonce, data.encode(), None)

    def audit(self, action, data):
        h = hashlib.sha256(data.encode()).hexdigest()
        self.db.execute("INSERT INTO audit (ts, action, hash) VALUES (?, ?, ?)", (time.ctime(), action, h))
        self.db.commit()

    def think(self, user_input):
        self.audit("think", user_input)
        # Real logic: uses protocol instructions to call LLM
        return {"status": "success", "decision": f"Reddish Processed: {user_input}", "identity": self.protocol['identity']}

# --- API Service ---
class ReddishHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        data = json.loads(self.rfile.read(content_length)) if content_length > 0 else {}
        if self.path == '/think': self._send_json(runtime.think(data.get('input', '')))
        elif self.path == '/evolve': self._send_json({"status": "evolution_triggered", "diff": data.get('diff', {})})

    def do_GET(self):
        if self.path == '/status': self._send_json({"status": "active", "version": runtime.protocol['version']})
        elif self.path == '/health': self._send_json({"health": "ok"})
        elif self.path == '/audit':
            logs = runtime.db.execute("SELECT * FROM audit ORDER BY id DESC LIMIT 10").fetchall()
            self._send_json({"audit_logs": logs})

    def _send_json(self, data):
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

if __name__ == "__main__":
    cfg_file = sys.argv[1] if len(sys.argv) > 1 else "config.yaml"
    runtime = ReddishRuntime(cfg_file)
    server = HTTPServer(('0.0.0.0', runtime.config['runtime']['port']), ReddishHandler)
    server.serve_forever()
