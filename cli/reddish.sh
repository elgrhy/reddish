#!/usr/bin/env bash
# =====================================================
# Reddish CLI: Sovereign Interface
# =====================================================

RC_HOME="$HOME/.reddish"
BINARY="python3 $HOME/.reddish/reddish.py"
PID_FILE="$RC_HOME/reddish.pid"
PORT=7777

function start() {
    if [ -f "$PID_FILE" ]; then
        PID=$(cat "$PID_FILE")
        if kill -0 "$PID" 2>/dev/null; then
            echo "⛔ Reddish is already running (PID: $PID)"
            exit 1
        else
            echo "⚠️ Found stale PID file. Cleaning up..."
            rm "$PID_FILE"
        fi
    fi
    echo "🚀 Starting Reddish substrate..."
    nohup $BINARY "$RC_HOME/config.yaml" > "$RC_HOME/logs/runtime.log" 2>&1 &
    echo $! > "$PID_FILE"
    sleep 1
    echo "✅ Reddish started (PID: $(cat "$PID_FILE"))"
}

function stop() {
    if [ ! -f "$PID_FILE" ]; then
        echo "⛔ Reddish is not running."
        exit 1
    fi
    PID=$(cat "$PID_FILE")
    echo "🛑 Stopping Reddish (PID: $PID)..."
    kill "$PID" 2>/dev/null || echo "Process $PID already stopped."
    rm "$PID_FILE"
    echo "✅ Reddish stopped."
}

function status() {
    if [ -f "$PID_FILE" ]; then
        PID=$(cat "$PID_FILE")
        if kill -0 "$PID" 2>/dev/null; then
            echo -e "🟢 Reddish is \033[32mACTIVE\033[0m (PID: $PID)"
            return 0
        fi
    fi
    echo -e "🔴 Reddish is \033[31mINACTIVE\033[0m"
    return 1
}

function query() {
    local INPUT="$*"
    if [ -z "$INPUT" ]; then
        echo "Usage: reddish query \"your question\""
        exit 1
    fi
    curl -s -X POST "http://localhost:$PORT/think" \
         -H "Content-Type: application/json" \
         -d "{\"input\": \"$INPUT\"}" | jq -r '.decision'
}

function chat() {
    echo -e "🌟 \033[1mReddish Neural Link Established\033[0m"
    echo "Type 'exit' or 'quit' to close the link."
    echo "------------------------------------------"
    while true; do
        printf "\033[34mYou > \033[0m"
        read -r USER_INPUT
        if [[ "$USER_INPUT" == "exit" || "$USER_INPUT" == "quit" ]]; then
            echo "🔌 Link closed."
            break
        fi
        printf "\033[31mReddish > \033[0m"
        curl -s -X POST "http://localhost:$PORT/think" \
             -H "Content-Type: application/json" \
             -d "{\"input\": \"$USER_INPUT\"}" | jq -r '.decision'
    done
}

function logs() {
    tail -f "$RC_HOME/logs/runtime.log"
}

case "$1" in
    start) start ;;
    stop) stop ;;
    status) status ;;
    chat) chat ;;
    query) shift; query "$@" ;;
    logs) logs ;;
    audit) curl -s "http://localhost:$PORT/audit" | jq . ;;
    evolve) curl -s -X POST "http://localhost:$PORT/evolve" -d '{"diff":{"op":"improve"}}' | jq . ;;
    *) echo "Usage: reddish {start|stop|status|chat|query|audit|logs|evolve}" ;;
esac

