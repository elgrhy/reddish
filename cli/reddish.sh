#!/usr/bin/env bash
# =====================================================
# Reddish CLI: Sovereign Interface
# =====================================================

RC_HOME="$HOME/.reddish"
BINARY="python3 $HOME/.reddish/reddish.py"
PID_FILE="$RC_HOME/reddish.pid"

function welcome() {
    echo "🌟 Welcome to Reddish — a living MPX protocol system."
}

function start() {
    if [ -f "$PID_FILE" ]; then
        echo "⛔ Reddish is already running (PID: $(cat $PID_FILE))"
        exit 1
    fi
    echo "🚀 Starting Reddish substrate..."
    nohup $BINARY "$RC_HOME/config.yaml" > "$RC_HOME/logs/runtime.log" 2>&1 &
    echo $! > "$PID_FILE"
    echo "✅ Reddish started (PID: $(cat $PID_FILE))"
}

function stop() {
    if [ ! -f "$PID_FILE" ]; then
        echo "⛔ Reddish is not running."
        exit 1
    fi
    PID=$(cat $PID_FILE)
    echo "🛑 Stopping Reddish (PID: $PID)..."
    kill $PID
    rm "$PID_FILE"
    echo "✅ Reddish stopped."
}

function status() {
    if [ -f "$PID_FILE" ]; then
        echo "🟢 Reddish is ACTIVE (PID: $(cat $PID_FILE))"
    else
        echo "🔴 Reddish is INACTIVE"
    fi
}

function audit() {
    curl -s http://localhost:7777/audit | jq .
}

function evolve() {
    echo "🌌 Triggering Epistemic Evolution..."
    curl -s -X POST http://localhost:7777/evolve -d '{"diff":{"op":"improve"}}' | jq .
}

case "$1" in
    start) start ;;
    stop) stop ;;
    status) status ;;
    audit) audit ;;
    evolve) evolve ;;
    *) echo "Usage: reddish {start|stop|status|audit|evolve}" ;;
esac
