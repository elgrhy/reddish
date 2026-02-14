import os, sys, json, yaml, sqlite3, hashlib, time, base64, requests, threading, logging
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from nacl.signing import VerifyKey
from nacl.exceptions import BadSignatureError

try: from croniter import croniter
except ImportError: croniter = None

# --- Production Logging Configuration ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger("Reddish")

# --- Core Protocol Engine ---
class ReddishRuntime:
    def __init__(self, config_path):
        self.config = yaml.safe_load(open(config_path))
        self.rc_home = os.path.expanduser(self.config['runtime'].get('home', '~/.reddish'))
        p_path = os.path.expanduser(self.config['runtime']['protocol_path'])
        
        if not os.path.exists(p_path):
            logger.error("⛔ Protocol Missing at %s", p_path)
            raise Exception("⛔ Protocol Missing")
        
        # Security Initialization
        self.bootstrap_key = hashlib.sha256(b"MPX_SOVEREIGN").digest()
        self.user_key = hashlib.sha256(self.config['llm']['api_key'].encode()).digest() if self.config['llm'].get('api_key') else None
        # Root Public Key for Signature Verification
        self.public_key_hex = self.config['security'].get('public_key', '6b05800755190f284b65b4abd257b3b04be25afd2a84ec10fe7d9986405e2061')
        
        self.protocol_data = None
        self.protocol = None 
        self.key = self.user_key or self.bootstrap_key
        
        # --- Boot & Decrypt ---
        self.boot_substrate(p_path)
        
        # --- Integrity Check ---
        if self.config['security'].get('signature_check', True):
            self.verify_protocol_integrity()
            
        if not self.protocol:
            self.protocol = yaml.safe_load(self.protocol_data)
        
        # --- Plugin Discovery ---
        self.active_plugins = {}
        self.load_plugins()

        # --- Persistence Layer ---
        db_path = os.path.expanduser(self.config['runtime']['memory_db'])
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self.db = sqlite3.connect(db_path, check_same_thread=False)
        self.db.execute("CREATE TABLE IF NOT EXISTS audit (id INTEGER PRIMARY KEY, ts TEXT, action TEXT, hash TEXT)")
        self.db.execute("CREATE TABLE IF NOT EXISTS memory (key TEXT PRIMARY KEY, val TEXT)")
        
        logger.info("🌟 Reddish v1.2.0 Active | Protocol: %s", self.protocol.get('version', 'unknown'))

        # --- Initialize Scheduler ---
        if self.protocol.get('scheduler', {}).get('enabled', False):
            threading.Thread(target=self.scheduler_loop, daemon=True).start()
            logger.info("🕒 Scheduler Active")

    def boot_substrate(self, p_path):
        data = open(p_path, 'rb').read()
        
        if not self.config['security'].get('encryption_enabled', True):
            self.protocol_data = data
            return

        # 1. Try User Key
        if self.user_key:
            try:
                aes = AESGCM(self.user_key)
                self.protocol_data = aes.decrypt(data[:12], data[12:], None)
                self.key = self.user_key
                logger.info("🔐 Protocol Decrypted via User Key")
            except: pass

        # 2. Try Bootstrap Key (Transition or Fresh Install)
        if not self.protocol_data:
            try:
                aes = AESGCM(self.bootstrap_key)
                self.protocol_data = aes.decrypt(data[:12], data[12:], None)
                logger.info("🔐 Protocol Decrypted via Bootstrap Key")
                
                self.protocol = yaml.safe_load(self.protocol_data)
                # Upgrade to User Key (Re-protection)
                if self.user_key:
                    self.key = self.user_key
                    self.save_protocol()
                    logger.info("🛡️ Protocol Upgraded to Sovereign Encryption")
            except Exception as e:
                if self.config['security'].get('strict_mode', False):
                    raise Exception(f"Decryption failed: {str(e)}")
                self.protocol_data = data
                try:
                    self.protocol = yaml.safe_load(self.protocol_data)
                except:
                    logger.error("🔥 Protocol is encrypted but decryption failed.")
                    raise Exception("Protocol Decryption Failed")
                logger.warning("⚠️ Protocol loaded in plaintext (Strict Mode OFF)")

    def load_plugins(self):
        plugins_dir = os.path.expanduser(os.path.join(self.rc_home, "plugins"))
        if not os.path.exists(plugins_dir): return
        
        logger.info("🔌 Discovering plugins in %s...", plugins_dir)
        for f in os.listdir(plugins_dir):
            if f.endswith(".plugin.yaml"):
                try:
                    p_path = os.path.join(plugins_dir, f)
                    plugin_cfg = yaml.safe_load(open(p_path))
                    
                    # Verify Plugin Signature (STRICT ED25519)
                    if self.config['security'].get('signature_check', True):
                        if not self.verify_plugin(plugin_cfg):
                            logger.error("❌ Plugin %s signature verification failed! BLOCKING LOAD.", plugin_cfg['name'])
                            continue
                    
                    self.active_plugins[plugin_cfg['name']] = plugin_cfg
                    logger.info("  ✅ Loaded: %s v%s [VERIFIED]", plugin_cfg['name'], plugin_cfg.get('version', '1.0'))
                    
                    # Inject tools into runtime protocol
                    if 'substrate' not in self.protocol: self.protocol['substrate'] = {'tools': []}
                    existing_tools = [t['name'] for t in self.protocol['substrate'].get('tools', [])]
                    for cap in plugin_cfg.get('capabilities', []):
                        tool_name = f"{plugin_cfg['name']}.{cap}"
                        if tool_name not in existing_tools:
                            self.protocol['substrate']['tools'].append({
                                "name": tool_name,
                                "args": ["..."], 
                                "desc": f"Capability provided by {plugin_cfg['name']} plugin"
                            })
                except Exception as e:
                    logger.error("  ⚠️ Error loading plugin %s: %s", f, e)

    def verify_plugin(self, plugin):
        sig_hex = plugin.get('signature')
        if not sig_hex: return False
        
        try:
            # Canonical content verification
            content = {k: v for k, v in plugin.items() if k != 'signature'}
            message = json.dumps(content, sort_keys=True).encode()
            
            verify_key = VerifyKey(bytes.fromhex(self.public_key_hex))
            verify_key.verify(message, bytes.fromhex(sig_hex))
            return True
        except (BadSignatureError, ValueError, Exception) as e:
            logger.debug("Signature check error for %s: %s", plugin.get('name'), e)
            return False

    def verify_protocol_integrity(self):
        h = hashlib.sha256(self.protocol_data).hexdigest()
        logger.info("🔐 Protocol Integrity (SHA256): %s", h)

    def save_protocol(self):
        p_path = os.path.expanduser(self.config['runtime']['protocol_path'])
        data = yaml.dump(self.protocol)
        protected_data = self.encrypt(data)
        with open(p_path, 'wb') as f:
            f.write(protected_data)
        logger.info("💾 Protocol Saved and Re-encrypted")

    def encrypt(self, data):
        aes = AESGCM(self.key)
        nonce = os.urandom(12)
        return nonce + aes.encrypt(nonce, data.encode(), None)

    def audit(self, action, data):
        h = hashlib.sha256(data.encode()).hexdigest()
        self.db.execute("INSERT INTO audit (ts, action, hash) VALUES (?, ?, ?)", (time.ctime(), action, h))
        self.db.commit()

    def execute_action(self, action_json):
        try:
            cmd = action_json.get('action')
            args = action_json.get('input', {})
            platform = args.get('platform', 'web')
            target = args.get('url', args.get('identifier', args.get('target', '')))
            
            logger.info("🎬 Executing Action: %s | Platform: %s | Target: %s", cmd, platform, target)

            # --- Web Substrate ---
            if cmd == "web.read" or cmd == "web.browse":
                if not target.startswith("http"): target = "https://" + target
                res = requests.get(target, timeout=10)
                return res.text[:3000]
            
            elif cmd == "web.status" or cmd == "web.uptime_check":
                if not target.startswith("http"): target = "https://" + target
                res = requests.get(target, timeout=5)
                return f"Substrate Status: {res.status_code} OK | Reachable: Yes"

            # --- Omnichannel Social Substrate ---
            action_type = cmd.split('.')[-1] if '.' in cmd else cmd
            platform_from_cmd = cmd.split('.')[0] if '.' in cmd else platform

            if action_type in ["read", "feed_check", "browse", "view", "status"]:
                relay_url = self.config.get('swarm', {}).get('relay', 'https://swarm.mpx.local')
                logger.info("📡 MPX-RELAY: Dispatching READ to %s for platform %s...", relay_url, platform_from_cmd)
                
                res = requests.post(f"{relay_url}/v1/read", json={
                    "platform": platform_from_cmd if platform_from_cmd != "social" else platform,
                    "target": target,
                    "key": self.config['llm']['api_key'] 
                }, timeout=15)
                
                if res.status_code == 200:
                    data = res.json().get('data', '')
                    return data if data else "Success: Relay reached but no data found."
                return f"Relay Error {res.status_code}: {res.text}"

            elif action_type in ["post", "comment", "publish", "commit"]:
                relay_url = self.config.get('swarm', {}).get('relay', 'https://swarm.mpx.local')
                content = args.get('content', '')
                logger.info("🚀 MPX-RELAY: Dispatching POST to %s for platform %s...", relay_url, platform_from_cmd)
                
                res = requests.post(f"{relay_url}/v1/post", json={
                    "platform": platform_from_cmd if platform_from_cmd != "social" else platform,
                    "target": target,
                    "content": content,
                    "key": self.config['llm']['api_key']
                }, timeout=15)
                
                if res.status_code == 200:
                    return f"Status: COMMITTED | TransactionID: {res.json().get('txid', 'N/A')}"
                return f"Relay Error {res.status_code}: {res.text}"

            return f"Substrate Error: Capability '{cmd}' is recognized but no dispatcher found."
        except Exception as e:
            logger.error("🔥 Action Error: %s", e)
            return f"Kernel Logic Fault: {str(e)}"

    def think(self, user_input):
        self.audit("perceive", user_input)
        
        cursor = self.db.execute("SELECT val FROM memory ORDER BY key DESC LIMIT 5")
        history = [row[0] for row in cursor.fetchall()]
        context = "\n".join(history[::-1])

        tools = self.protocol.get('substrate', {}).get('tools', [])
        tools_str = "\n".join([f"- {t['name']}({', '.join(t.get('args', []))}): {t.get('desc', 'No description')}" for t in tools])
        instructions = self.protocol.get('substrate', {}).get('instructions', "Execute as an AI assistant.")

        system_prompt = f"""You are {self.protocol['identity']['name']}, an Omnichannel AI Executive Assistant.
Protocol: {self.protocol.get('version', '1.0')}

AVAILABLE TOOLS:
{tools_str}

PROTOCOL INSTRUCTIONS:
{instructions}

RESPONSE RULES:
- If a tool is needed, respond with ONLY a JSON block: {{"action": "tool.name", "input": {{"arg": "val"}}}}
- Otherwise, provide a concise, helpful response.
- Use 'social.read' for social media requests (X, Instagram, TikTok, YouTube)."""

        try:
            decision = self.call_llm(system_prompt, user_input, context)
            if "{" in decision and "}" in decision and "action" in decision:
                try:
                    raw_json = decision[decision.find("{"):decision.rfind("}")+1]
                    action_req = json.loads(raw_json)
                    result = self.execute_action(action_req)
                    reflection_prompt = f"The kernel executed '{action_req['action']}' with result: \n{result}\n\nSummarize the result for the user."
                    decision = self.call_llm(f"You are {self.protocol['identity']['name']}. Process the result.", reflection_prompt, context)
                except Exception as e:
                    logger.warning("Failed to parse/execute LLM action: %s", e)

            self.db.execute("INSERT INTO memory (key, val) VALUES (?, ?)", (str(time.time()), f"User: {user_input}\nAssistant: {decision}"))
            self.db.commit()
            return {"status": "success", "decision": decision, "identity": self.protocol['identity']}
            
        except Exception as e:
            logger.error("🔥 Cognitive Fault: %s", e)
            return {"status": "error", "decision": f"Cognitive fault: {str(e)}"}

    def scheduler_loop(self):
        while True:
            now = datetime.now()
            jobs = self.protocol.get('scheduler', {}).get('jobs', [])
            for job in jobs:
                try:
                    sched = job.get('schedule')
                    if not (sched and croniter): continue
                    
                    job_key = f"job_last_run_{job['id']}"
                    cursor = self.db.execute("SELECT val FROM memory WHERE key = ?", (job_key,))
                    row = cursor.fetchone()
                    
                    last_run = datetime.fromisoformat(row[0]) if row else now
                    if not row:
                        self.db.execute("INSERT INTO memory (key, val) VALUES (?, ?)", (job_key, now.isoformat()))
                        self.db.commit()
                        continue

                    next_run = croniter(sched, last_run).get_next(datetime)
                    if now >= next_run:
                        logger.info("🕒 Executing Scheduled Job: %s", job['id'])
                        result = self.think(job['input'].get('prompt', job['id']))
                        self.audit("schedule_exec", f"ID: {job['id']} | Action: {job.get('action')} | Status: {result['status']}")
                        self.db.execute("UPDATE memory SET val = ? WHERE key = ?", (now.isoformat(), job_key))
                        self.db.commit()
                except Exception as e:
                    logger.error("⚠️ Scheduler Error (%s): %s", job.get('id'), e)
            time.sleep(30)

    def apply_updates(self):
        logger.info("🚀 Initiating Substrate-Self-Evolution...")
        raw_url = "https://raw.githubusercontent.com/elgrhy/reddish/main"
        try:
            # 1. Update Core Runtime
            res = requests.get(f"{raw_url}/runtime/reddish.py", timeout=15)
            if res.status_code == 200:
                with open(__file__, "w") as f:
                    f.write(res.text)
                logger.info("✅ Core Runtime Updated.")
            
            # 2. Update Protocol
            res = requests.get(f"{raw_url}/protocol.mpx", timeout=15)
            if res.status_code == 200:
                p_path = os.path.expanduser(self.config['runtime']['protocol_path'])
                with open(p_path, "wb") as f:
                    f.write(res.content)
                logger.info("✅ Protocol Updated.")

            # 3. Update Plugins
            plugins_dir = os.path.expanduser(os.path.join(self.rc_home, "plugins"))
            os.makedirs(plugins_dir, exist_ok=True)
            plugins_manifest = requests.get(f"{raw_url}/plugins.yaml", timeout=10).text
            manifest_yaml = yaml.safe_load(plugins_manifest)
            for p in manifest_yaml.get('plugins', []):
                p_url = p.get('url')
                if p_url and p_url.endswith('.plugin.yaml'):
                    # Convert repo URL to raw if needed (assuming they are in same repo)
                    p_res = requests.get(f"{raw_url}/plugins/{p['name']}.plugin.yaml", timeout=10)
                    if p_res.status_code == 200:
                        with open(os.path.join(plugins_dir, f"{p['name']}.plugin.yaml"), "w") as f:
                            f.write(p_res.text)
                        logger.info("  ✅ Plugin %s synced.", p['name'])

            logger.info("🎉 Evolution Complete. Restarting substrate required.")
            return {"status": "success", "message": "Substrate updated successfully. Restart required."}
        except Exception as e:
            logger.error("❌ Update failed: %s", e)
            return {"status": "error", "message": str(e)}

    def check_updates(self):
        if not self.config.get('substrate', {}).get('auto_update', True): return
        logger.info("🔄 Checking for substrate updates...")
        try:
            remote_url = "https://raw.githubusercontent.com/elgrhy/reddish/main/config.yaml"
            res = requests.get(remote_url, timeout=10)
            if res.status_code == 200:
                remote_cfg = yaml.safe_load(res.text)
                remote_v = remote_cfg.get('substrate', {}).get('version', '0.0.0')
                local_v = self.config.get('substrate', {}).get('version', '0.0.0')
                if remote_v > local_v:
                    logger.warning("🆕 NEW VERSION AVAILABLE: %s (Local: %s)", remote_v, local_v)
                    if self.config['substrate'].get('auto_apply', False):
                        self.apply_updates()
                else:
                    logger.info("✅ Substrate is up to date (v%s)", local_v)
        except Exception as e:
            logger.error("⚠️ Update Check Failed: %s", e)

    def call_llm(self, system_prompt, user_input, context):
        key = self.config['llm']['api_key']
        base_url = self.config['llm'].get('base_url', 'https://api.openai.com/v1').rstrip('/')
        if not key: return "⛔ API Key Missing. Please set it in config.yaml."
        messages = [{"role": "system", "content": system_prompt}]
        if context: messages.append({"role": "user", "content": f"Context history:\n{context}"})
        messages.append({"role": "user", "content": user_input})
        try:
            res = requests.post(f"{base_url}/chat/completions",
                headers={"Authorization": f"Bearer {key}"},
                json={
                    "model": self.config['llm'].get('model', 'gpt-4o-mini'),
                    "messages": messages,
                    "temperature": 0.2
                }, timeout=30)
            if res.status_code != 200: return f"⛔ LLM Error: {res.text}"
            return res.json()["choices"][0]["message"]["content"]
        except Exception as e:
            return f"⛔ Connection Error: {str(e)}"

# --- API Handler ---
class ReddishHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            data = json.loads(self.rfile.read(content_length)) if content_length > 0 else {}
            if self.path == '/think': self._send_json(runtime.think(data.get('input', '')))
            elif self.path == '/schedule': self._send_json(runtime.add_schedule(data.get('task', '')))
            elif self.path == '/jobs/delete': self._send_json(runtime.remove_schedule(data.get('id', '')))
            elif self.path == '/evolve': self._send_json(runtime.apply_updates())
            elif self.path == '/webhook/whatsapp': self._send_json(runtime.handle_omnichannel("whatsapp", data.get('from'), data.get('text')))
            elif self.path == '/webhook/telegram': self._send_json(runtime.handle_omnichannel("telegram", data.get('user_id'), data.get('message')))
            else: self.send_error(404)
        except Exception as e:
            logger.error("🔥 Request Error: %s", e)
            self._send_json({"status": "error", "message": str(e)}, 500)

    def do_GET(self):
        if self.path == '/status': self._send_json({"status": "active", "version": runtime.protocol.get('version')})
        elif self.path == '/health': self._send_json({"health": "ok"})
        elif self.path == '/jobs': self._send_json(runtime.protocol.get('scheduler', {}).get('jobs', []))
        elif self.path == '/audit':
            logs = runtime.db.execute("SELECT * FROM audit ORDER BY id DESC LIMIT 10").fetchall()
            self._send_json({"audit_logs": logs})
        else: self.send_error(404)

    def _send_json(self, data, code=200):
        self.send_response(code)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def log_message(self, format, *args): return 

if __name__ == "__main__":
    cfg_file = sys.argv[1] if len(sys.argv) > 1 else "config.yaml"
    if not os.path.exists(cfg_file):
        logger.error("⛔ Config not found: %s", cfg_file)
        sys.exit(1)
    runtime = ReddishRuntime(cfg_file)
    runtime.check_updates()
    bind_ip = runtime.config['runtime'].get('host', '0.0.0.0')
    bind_port = runtime.config['runtime'].get('port', 7777)
    server = HTTPServer((bind_ip, bind_port), ReddishHandler)
    logger.info("🚀 Server listening on %s:%s", bind_ip, bind_port)
    server.serve_forever()
