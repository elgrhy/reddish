#!/usr/bin/env bash
echo "🧪 Testing Plugin Loading..."
COUNT=$(ls $HOME/.reddish/plugins/*.yaml | wc -l)
if [ "$COUNT" -ge 5 ]; then
    echo "✅ $COUNT plugins verified."
else
    echo "❌ Plugins missing ($COUNT/5)."
    exit 1
fi
