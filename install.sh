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
fetch_file "plugins.yaml" "$RC_HOME/plugins.yaml"

PLUGINS=("audit.plugin.yaml" "core.plugin.yaml" "evolution.plugin.yaml" "security.plugin.yaml" "swarm.plugin.yaml" "telegram.plugin.yaml" "whatsapp.plugin.yaml")
for plugin in "${PLUGINS[@]}"; do
    if [ -f "plugins/$plugin" ]; then
        cp "plugins/$plugin" "$RC_HOME/plugins/$plugin"
    else
        curl -sSL "$RAW/plugins/$plugin" -o "$RC_HOME/plugins/$plugin" 2>/dev/null || true
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

# Dependencies
echo "📦 Installing substrate dependencies..."
python3 -m pip install cryptography pyyaml requests pynacl --user --quiet

# 5. Configuration (Interactive Prompt)
echo -e "\n🌟 \033[1mWELCOME TO REDDISH\033[0m — Bootstrapping Sovereign Mental Protocol"
echo "---------------------------------------------------------"
echo "🔑 Configuration Required"

API_KEY=""
while [ -z "$API_KEY" ]; do
    printf "Enter your LLM API Key (hidden): "
    # Redirect stdin to TTY to ensure it works even when piped from curl
    read -rs API_KEY < /dev/tty
    if [ -z "$API_KEY" ]; then
        echo -e "\n⛔ API Key cannot be empty. Please try again."
    fi
done
echo -e "\n✅ Key accepted."

# Inject key into config
# Use | as delimiter to handle potential / or & in keys
if [[ "$OSTYPE" == "darwin"* ]]; then
    sed -i '' "s|api_key: \".*\"|api_key: \"$API_KEY\"|" "$RC_HOME/config.yaml"
else
    sed -i "s|api_key: \".*\"|api_key: \"$API_KEY\"|" "$RC_HOME/config.yaml"
fi

echo -e "\n🎉 \033[32mInstallation Complete!\033[0m"
echo "👉 Run 'reddish start' to begin your sovereign session."
echo "---------------------------------------------------------"


