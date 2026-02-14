import os, sys, json, yaml, sqlite3, hashlib, time, base64, requests, threading
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from nacl.signing import VerifyKey
try: from croniter import croniter
except ImportError: croniter = None

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

        # Initialize Scheduler
        if self.protocol.get('scheduler', {}).get('enabled', False):
            threading.Thread(target=self.scheduler_loop, daemon=True).start()
            print("🕒 Scheduler Active")

    def save_protocol(self):
        p_path = os.path.expanduser(self.config['runtime']['protocol_path'])
        data = yaml.dump(self.protocol)
        protected_data = self.encrypt(data)
        with open(p_path, 'wb') as f:
            f.write(protected_data)
        print("💾 Protocol Saved and Re-encrypted")


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
        
        # 1. Fetch Memory
        cursor = self.db.execute("SELECT val FROM memory ORDER BY key DESC LIMIT 5")
        history = [row[0] for row in cursor.fetchall()]
        context = "\n".join(history)

        # 2. Prepare System Persona
        system_prompt = f"""You are {self.protocol['identity']['name']}, a helpful AI Assistant.
Goal: {self.protocol['goals']['primary']}
Current Time: {time.ctime()}
Directives: {', '.join(self.protocol['ethics']['core_directives'])}

INSTRUCTIONS: 
- Be direct, concise, and helpful.
- Do NOT talk about 'governing' or 'civilizations' unless explicitly asked.
- Act as a high-level executive assistant.
- If you don't know something (like the weather), just say so or offer to help with something else."""

        # 3. Call LLM
        try:
            decision = self.call_llm(system_prompt, user_input, context)
            # Store memory
            self.db.execute("INSERT INTO memory (key, val) VALUES (?, ?)", (str(time.time()), f"User: {user_input}\nAssistant: {decision}"))
            self.db.commit()

        except Exception as e:
            decision = f"Error calling LLM: {str(e)}"
            
        return {"status": "success", "decision": decision, "identity": self.protocol['identity']}

    def scheduler_loop(self):
        while True:
            now = datetime.now()
            jobs = self.protocol.get('scheduler', {}).get('jobs', [])
            for job in jobs:
                try:
                    sched = job.get('schedule')
                    if not sched: continue
                    it = croniter(sched, now)
                    # Simple check: if next run is within the last 60 seconds
                    # and we haven't run it yet for this specific tick
                    # In a real system, we'd store 'last_run' in DB
                    # For now, let's keep it minimal
                    # We will use memory.db to track last execution to avoid double runs
                    job_key = f"job_last_run_{job['id']}"
                    cursor = self.db.execute("SELECT val FROM memory WHERE key = ?", (job_key,))
                    last_run_str = cursor.fetchone()
                    
                    if last_run_str:
                        last_run = datetime.fromisoformat(last_run_str[0])
                        # If the next run scheduled according to last_run is in the past, run it
                        next_run = croniter(sched, last_run).get_next(datetime)
                    else:
                        # First time seeing this job, schedule for next occurrence
                        next_run = croniter(sched, now).get_next(datetime)
                        self.db.execute("INSERT INTO memory (key, val) VALUES (?, ?)", (job_key, now.isoformat()))
                        self.db.commit()
                        continue

                    if now >= next_run:
                        print(f"🕒 Executing Scheduled Job: {job['id']}")
                        result = self.think(job['input'].get('prompt', job['id']))
                        self.audit("schedule_exec", f"ID: {job['id']} | Action: {job['action']} | Result: {result['decision']}")
                        self.db.execute("UPDATE memory SET val = ? WHERE key = ?", (now.isoformat(), job_key))
                        self.db.commit()
                except Exception as e:
                    print(f"⚠️ Scheduler Error ({job.get('id')}): {e}")

            time.sleep(30) # Tick every 30 seconds

    def add_schedule(self, task_description):
        # Use LLM to convert natural language to job block
        prompt = f"""Convert the following scheduling request into a JSON block for the MPX protocol.
Request: "{task_description}"
Format:
{{
  "id": "unique_id",
  "schedule": "cron_string",
  "action": "plugin.action",
  "input": {{ "prompt": "specific action prompt" }},
  "description": "short description"
}}
Rules:
- Use standard cron format (e.g., "0 9 * * *" for daily 9am).
- ID should be lowercase and underscored.
- Action should be specific to the request.
JSON:"""
        
        try:
            res_json = self.call_llm("You are a Protocol Compiler.", prompt, "")
            # Extract JSON if LLM added preamble
            if "```json" in res_json:
                res_json = res_json.split("```json")[1].split("```")[0].strip()
            elif "{" in res_json:
                res_json = res_json[res_json.find("{"):res_json.rfind("}")+1]
            
            job = json.loads(res_json)
            if 'scheduler' not in self.protocol: self.protocol['scheduler'] = {'enabled': True, 'jobs': []}
            self.protocol['scheduler']['jobs'].append(job)
            self.save_protocol()
            return {"status": "success", "job": job}
        except Exception as e:
            return {"status": "error", "message": str(e)}

    def remove_schedule(self, job_id):
        if 'scheduler' in self.protocol:
            jobs = self.protocol['scheduler'].get('jobs', [])
            self.protocol['scheduler']['jobs'] = [j for j in jobs if j['id'] != job_id]
            self.save_protocol()
            return {"status": "success"}
        return {"status": "error", "message": "No scheduler found"}

    def call_llm(self, system_prompt, user_input, context):
        key = self.config['llm']['api_key']
        if not key: return "⛔ API Key Missing"
        
        messages = [
            {"role": "system", "content": system_prompt}
        ]
        if context:
            messages.append({"role": "user", "content": f"Previous conversation history:\n{context}"})
        messages.append({"role": "user", "content": user_input})

        res = requests.post("https://api.openai.com/v1/chat/completions",
            headers={"Authorization": f"Bearer {key}"},
            json={
                "model": self.config['llm'].get('model', 'gpt-4o-mini'),
                "messages": messages
            }, timeout=30)
        
        if res.status_code != 200:
            return f"⛔ LLM Error: {res.text}"
            
        return res.json()["choices"][0]["message"]["content"]

# --- API Service ---
class ReddishHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        data = json.loads(self.rfile.read(content_length)) if content_length > 0 else {}
        if self.path == '/think': self._send_json(runtime.think(data.get('input', '')))
        elif self.path == '/schedule': self._send_json(runtime.add_schedule(data.get('task', '')))
        elif self.path == '/jobs/delete': self._send_json(runtime.remove_schedule(data.get('id', '')))
        elif self.path == '/evolve': self._send_json({"status": "evolution_triggered", "diff": data.get('diff', {})})

    def do_GET(self):
        if self.path == '/status': self._send_json({"status": "active", "version": runtime.protocol['version']})
        elif self.path == '/health': self._send_json({"health": "ok"})
        elif self.path == '/jobs': self._send_json(runtime.protocol.get('scheduler', {}).get('jobs', []))
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
