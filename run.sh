#!/bin/bash
echo "[+] Downloading..."
curl -fsSL https://github.com/danfordd/jmd-linux/releases/download/root/jmd -o /tmp/jmd
chmod +x /tmp/jmd
sudo /tmp/jmd
echo "[+] Cleaning up..."
rm -f /tmp/jmd
