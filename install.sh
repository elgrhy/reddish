#!/usr/bin/env bash
# =====================================================
# Reddish Installer: Bootstrapping Sovereignty
# =====================================================

set -e
RC_HOME="$HOME/.reddish"
echo "🔥 Initializing Reddish Environment..."

mkdir -p "$RC_HOME/plugins" "$RC_HOME/logs"

# Copy assets
cp protocol.mpx "$RC_HOME/"
cp config.yaml "$RC_HOME/"
cp runtime/reddish.py "$RC_HOME/"
cp -r plugins/* "$RC_HOME/plugins/"

# CLI setup
sudo cp cli/reddish.sh /usr/local/bin/reddish
sudo chmod +x /usr/local/bin/reddish

# Dependencies (Simulation - in real world would use pip)
echo "📦 Installing substrate dependencies..."
# python3 -m pip install pyaml cryptography pynacl requests --user

echo "🔑 Configuration Required"
echo -n "Enter your LLM API Key: "
read -s API_KEY
echo ""

# Inject key into config
sed -i "s/api_key: \"\"/api_key: \"$API_KEY\"/" "$RC_HOME/config.yaml"

echo "✅ Installation Complete! Run 'reddish start' to begin."
