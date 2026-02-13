#!/usr/bin/env bash
echo "🧪 Testing curl API interface..."
res=$(curl -s http://localhost:7777/health)
if [[ "$res" == *"ok"* ]]; then
    echo "✅ API Health Check Passed."
else
    echo "❌ API Unreachable or Error."
    exit 1
fi
