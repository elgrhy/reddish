#!/usr/bin/env bash
echo "🧪 Testing Protocol Integrity..."
if [ -f "$HOME/.reddish/protocol.mpx" ]; then
    echo "✅ Protocol found."
else
    echo "❌ Protocol missing."
    exit 1
fi
