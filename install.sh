#!/usr/bin/env bash
# =====================================================
# Reddish Installer: Bootstrapping Sovereignty
# =====================================================

set -e
REPO="elgrhy/reddish"
RAW="https://raw.githubusercontent.com/$REPO/main"
RC_HOME="$HOME/.reddish"

echo "🔥 Initializing Reddish Environment..."

mkdir -p "$RC_HOME/plugins" "$RC_HOME/logs"

# Helper to fetch file (local or remote)
fetch_file() {
    local src=$1
    local dest=$2
    if [ -f "$src" ]; then
        cp "$src" "$dest"
    else
        curl -sSL "$RAW/$src" -o "$dest"
    fi
}

# 1. Download Core Assets
echo "⬇ Fetching core subscription..."
fetch_file "protocol.mpx" "$RC_HOME/protocol.mpx"
if [ ! -f "$RC_HOME/config.yaml" ]; then
    fetch_file "config.yaml" "$RC_HOME/config.yaml"
fi

# 2. Download Runtime
fetch_file "runtime/reddish.py" "$RC_HOME/reddish.py"

# 3. Download Plugins
echo "⬇ Synchronizing plugins..."
PLUGINS=("audit.plugin.yaml" "core.plugin.yaml" "evolution.plugin.yaml" "security.plugin.yaml" "swarm.plugin.yaml")
for plugin in "${PLUGINS[@]}"; do
    if [ -f "plugins/$plugin" ]; then
        cp "plugins/$plugin" "$RC_HOME/plugins/$plugin"
    else
        curl -sSL "$RAW/plugins/$plugin" -o "$RC_HOME/plugins/$plugin"
    fi
done

# 4. CLI Setup
echo "⬇ Configuring CLI..."
if [ -f "cli/reddish.sh" ]; then
    sudo cp cli/reddish.sh /usr/local/bin/reddish
else
    sudo curl -sSL "$RAW/cli/reddish.sh" -o /usr/local/bin/reddish
fi
sudo chmod +x /usr/local/bin/reddish

# Dependencies (Simulation - in real world would use pip)
echo "📦 Installing substrate dependencies..."
# python3 -m pip install pyaml cryptography pynacl requests --user

echo "🔑 Configuration Required"
echo -n "Enter your LLM API Key: "
read -s API_KEY
echo ""

# Inject key into config
# Handle both GNU and macOS sed
if [[ "$OSTYPE" == "darwin"* ]]; then
    sed -i '' "s/api_key: \"\"/api_key: \"$API_KEY\"/" "$RC_HOME/config.yaml"
else
    sed -i "s/api_key: \"\"/api_key: \"$API_KEY\"/" "$RC_HOME/config.yaml"
fi

echo "✅ Installation Complete! Run 'reddish start' to begin."
