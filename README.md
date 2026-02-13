# Reddish: A Living MPX Protocol System

Reddish is a production-grade implementation of the **Sovereign Mental Processing Protocol (MPX)**. It is designed to be a "Linux of Cognition"—a minimal, secure, and protocol-driven substrate for autonomous agents.

## 🚀 Installation

```bash
curl -sSL https://raw.githubusercontent.com/elgrhy/reddish/main/install.sh | bash
```

## 🛠 Usage

Reddish is designed to be microscopic and invisible once installed.

### 1. Start the Brain
Initialize the cognitive substrate in the background:
```bash
reddish start
```

### 2. Enter Peer-to-Peer Chat
Communicate directly with the MPX protocol via the neural link:
```bash
reddish chat
```

### 3. Quick Terminal Query
Ask a question without entering the full chat:
```bash
reddish query "summarize our ethical core"
```

### 4. Management Commands
*   `reddish status`: Check if the substrate is active.
*   `reddish stop`: Gracefully shutdown the engine.
*   `reddish logs`: View real-time background processing.
*   `reddish audit`: View the cryptographically hashed audit trail.


## 🌐 curl API Interface

Reddish follows a zero-trust, API-first architecture.

**Think:**
```bash
curl -X POST http://localhost:7777/think -d '{"input":"What is the goal of the protocol?"}'
```

**Audit Trail:**
```bash
curl http://localhost:7777/audit
```

**Protocol Evolution:**
```bash
curl -X POST http://localhost:7777/evolve -d '{"diff":{"version":2}}'
```

## 🔐 Security & Sovereignty
- **AES-256-GCM**: Protocol state and memory are encrypted using your LLM key as a derivative.
- **Ed25519**: All plugins and protocol updates must be signed.
- **Microscopic Runtime**: The core logic is under 100 lines of Python, ensuring minimal attack surface.

## 🧬 Architecture
Reddish moves the "brain" out of the code and into the `.mpx` file. The runtime is merely an enforcer for the protocol's ethics, identity, and goals.

---
**Status: v1.0.0 Stable (MPX v1.0.0)**
*Built for the Protocol Civilization.*
