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

function schedule() {
    local TASK="$*"
    if [ -z "$TASK" ]; then
        echo "Usage: reddish schedule \"Post to X every day at 9am\""
        exit 1
    fi
    echo "🧠 Parsing intent and scheduling..."
    curl -s -X POST "http://localhost:$PORT/schedule" \
         -H "Content-Type: application/json" \
         -d "{\"task\": \"$TASK\"}" | jq .
}

function list_jobs() {
    echo "📋 Active Scheduled Jobs"
    echo "------------------------------------------"
    curl -s "http://localhost:$PORT/jobs" | jq -r '.[] | "ID: \(.id) | Schedule: \(.schedule) | Action: \(.action)\nDesc: \(.description)\n"'
}

function cancel_job() {
    local ID=$1
    if [ -z "$ID" ]; then
        echo "Usage: reddish cancel job_id"
        exit 1
    fi
    echo "🛑 Canceling job $ID..."
    curl -s -X POST "http://localhost:$PORT/jobs/delete" \
         -H "Content-Type: application/json" \
         -d "{\"id\": \"$ID\"}" | jq .
}

function upgrade() {
    echo "🆕 Checking for Reddish core updates..."
    curl -sSL https://raw.githubusercontent.com/elgrhy/reddish/main/install.sh | bash
    echo "✅ Upgrade process completed."
}

function set_llm() {
    local URL=$1
    local KEY=$2
    if [ -z "$URL" ]; then
        echo "Usage: reddish set-llm <base_url> [api_key]"
        echo "Example (Ollama): reddish set-llm http://localhost:11434/v1"
        exit 1
    fi
    echo "⚙️ Updating LLM Configuration..."
    if [[ "$OSTYPE" == "darwin"* ]]; then
        sed -i '' "s|base_url: \".*\"|base_url: \"$URL\"|" "$RC_HOME/config.yaml"
        if [ -n "$KEY" ]; then sed -i '' "s|api_key: \".*\"|api_key: \"$KEY\"|" "$RC_HOME/config.yaml"; fi
    else
        sed -i "s|base_url: \".*\"|base_url: \"$URL\"|" "$RC_HOME/config.yaml"
        if [ -n "$KEY" ]; then sed -i "s|api_key: \".*\"|api_key: \"$KEY\"|" "$RC_HOME/config.yaml"; fi
    fi
    echo "✅ LLM updated. Restart reddish to apply."
}

case "$1" in
    start) start ;;
    stop) stop ;;
    status) status ;;
    chat) chat ;;
    query) shift; query "$@" ;;
    schedule) shift; schedule "$@" ;;
    jobs) list_jobs ;;
    cancel) shift; cancel_job "$@" ;;
    upgrade) upgrade ;;
    set-llm) shift; set_llm "$@" ;;
    logs) logs ;;
    audit) curl -s "http://localhost:$PORT/audit" | jq . ;;
    evolve) curl -s -X POST "http://localhost:$PORT/evolve" -d '{"diff":{"op":"improve"}}' | jq . ;;
    *) echo "Usage: reddish {start|stop|status|chat|query|schedule|jobs|cancel|upgrade|set-llm|audit|logs|evolve}" ;;
esac

