#!/usr/bin/env bash
set -euo pipefail

# Simple installer for demo/ops: copies repo to /opt/nullshadow,
# creates nullshadow user, installs requirements, and configures systemd units.
# Run as root.

REPO_DIR=$(pwd)
TARGET_DIR=/opt/nullshadow
USER=nullshadow
SYSTEMD_DIR=/etc/systemd/system

if [ "$(id -u)" -ne 0 ]; then
  echo "Please run as root: sudo $0"
  exit 1
fi

echo "Creating user $USER if missing..."
if ! id -u $USER >/dev/null 2>&1; then
  useradd -r -s /usr/sbin/nologin -m -d $TARGET_DIR $USER || true
fi

echo "Copying files to $TARGET_DIR..."
rm -rf $TARGET_DIR
mkdir -p $TARGET_DIR
cp -r ./* $TARGET_DIR/
chown -R $USER:$USER $TARGET_DIR

echo "Installing Python dependencies..."
python3 -m pip install --upgrade pip
pip3 install -r $TARGET_DIR/requirements.txt

echo "Installing systemd unit files..."
cp $TARGET_DIR/scripts/systemd/local_ai_proxy.service $SYSTEMD_DIR/
cp $TARGET_DIR/scripts/systemd/nullshadow.service $SYSTEMD_DIR/

echo "Installing environment examples (copy and edit as /etc/default/*)..."
cp $TARGET_DIR/scripts/systemd/local_ai_proxy.env.example /etc/default/local_ai_proxy
cp $TARGET_DIR/scripts/systemd/nullshadow.env.example /etc/default/nullshadow
chown root:root /etc/default/local_ai_proxy /etc/default/nullshadow
chmod 600 /etc/default/local_ai_proxy /etc/default/nullshadow

systemctl daemon-reload
systemctl enable --now local_ai_proxy.service || true
systemctl enable --now nullshadow.service || true

echo "Installation complete. Review /etc/default/local_ai_proxy and /etc/default/nullshadow to set secrets and options."
