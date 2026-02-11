#!/bin/bash
read -p "Install folder (default: ~/Screen_Switcher): " -r TARGET
TARGET="${TARGET:-$HOME/Screen_Switcher}"
mkdir -p "$TARGET" && cd "$TARGET" || exit 1

/Applications/Python\ 3.11/Install\ Certificates.command 2>/dev/null || true
python3 -m venv .venv
source .venv/bin/activate

pip install --upgrade pip
pip install pyobjc

curl -L "https://raw.githubusercontent.com/youraverageazurecosplay-png/Screen_Switcher/refs/heads/main/Main" -o Main

# create updater
cat > update.sh << 'EOF'
#!/bin/bash
cd "$(dirname "$0")" || exit 1
source .venv/bin/activate 2>/dev/null || true
curl -L "https://raw.githubusercontent.com/youraverageazurecosplay-png/Screen_Switcher/refs/heads/main/Main" -o Main
echo "Screen Switcher updated."
EOF
chmod +x update.sh

# create double-clickable runner
cat > "Run_Screen_Switcher.command" << 'EOF'
#!/bin/bash
cd "$(dirname "$0")" || exit 1
source .venv/bin/activate 2>/dev/null || true
python Main
EOF

chmod +x "Run_Screen_Switcher.command"

echo
echo "Installed in: $TARGET"
echo "To run it, just double-click 'Run_Screen_Switcher.command' in Finder."
echo "To update later, run './update.sh' in Terminal from that folder."
