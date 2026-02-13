# Usage Guide for Reddish

## Initial Setup
1. Run the `install.sh` script.
2. Provide your OpenAI / GPT API Key when prompted.
3. The installer will configure `~/.reddish/config.yaml`.

## Commands
- `reddish start`: Launches the background runtime.
- `reddish stop`: Gracefully terminates the runtime.
- `reddish status`: Verify if the engine is running.
- `reddish audit`: View the cryptographic audit log.
- `reddish evolve`: Propose a protocol transformation.

## Integration
Any tool that can send HTTP requests can interact with Reddish. It operates on port `7777` by default.

### Endpoint: `/think`
**Request:**
```json
{
  "input": "Query string"
}
```
**Response:**
```json
{
  "status": "success",
  "decision": "Reddish response",
  "identity": "Reddish"
}
```

## Security Model
Reddish assumes a zero-trust environment. Every action is logged, and every protocol change must pass through the Judicial Audit Gate (defined in `protocol.mpx`).
