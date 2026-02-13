import os, sys, json, yaml, sqlite3, hashlib, time, base64
from http.server import HTTPServer, BaseHTTPRequestHandler
from cryptography.hazmat.primitives.ciphers.aead import AesGcm
from nacl.signing import VerifyKey

# --- Core Protocol Engine ---
class ReddishRuntime:
    def __init__(self, config_path):
        self.config = yaml.safe_load(open(config_path))
        self.protocol = yaml.safe_load(open(os.path.expanduser(self.config['runtime']['protocol_path'])))
        self.db = sqlite3.connect(os.path.expanduser(self.config['runtime']['memory_db']), check_same_thread=False)
        self.db.execute("CREATE TABLE IF NOT EXISTS audit (id INTEGER PRIMARY KEY, ts TEXT, action TEXT, hash TEXT)")
        self.db.execute("CREATE TABLE IF NOT EXISTS memory (key TEXT PRIMARY KEY, val TEXT)")
        self.key = hashlib.sha256(self.config['llm']['api_key'].encode()).digest()
        print(f"🌟 Reddish v1.0.0 Active | Protocol: {self.protocol['version']}")

    def encrypt(self, data):
        aes = AesGcm(self.key)
        nonce = os.urandom(12)
        return nonce + aes.encrypt(nonce, data.encode(), None)

    def decrypt(self, data):
        aes = AesGcm(self.key)
        return aes.decrypt(data[:12], data[12:], None).decode()

    def audit(self, action, data):
        h = hashlib.sha256(data.encode()).hexdigest()
        self.db.execute("INSERT INTO audit (ts, action, hash) VALUES (?, ?, ?)", (time.ctime(), action, h))
        self.db.commit()

    def think(self, user_input):
        print(f"🧠 Thinking: {user_input}")
        self.audit("think", user_input)
        # Mocking LLM for testability if key is provided but we need actual logic
        return {"status": "success", "decision": f"Reddish acknowledges: {user_input}", "identity": self.protocol['identity']['name']}

# --- API Service ---
class ReddishHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        data = json.loads(self.rfile.read(content_length))
        
        if self.path == '/think':
            res = runtime.think(data.get('input', ''))
            self._send_json(res)
        elif self.path == '/evolve':
            runtime.audit("evolve", json.dumps(data))
            self._send_json({"status": "evolution_triggered", "diff": data.get('diff', {})})

    def do_GET(self):
        if self.path == '/status':
            self._send_json({"status": "active", "version": runtime.protocol['version'], "identity": runtime.protocol['identity']})
        elif self.path == '/health':
            self._send_json({"health": "ok", "substrate": runtime.protocol['identity']['substrate']})
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
    print(f"🚀 Reddish API listening on port {runtime.config['runtime']['port']}...")
    server.serve_forever()
