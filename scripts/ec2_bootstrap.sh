#!/bin/bash
# Run this once on a fresh Ubuntu 22.04/24.04 EC2 instance.
# Usage: bash ec2_bootstrap.sh
set -euo pipefail

echo "== Updating system packages =="
sudo apt-get update -y
sudo apt-get upgrade -y

echo "== Installing prerequisites =="
sudo apt-get install -y ca-certificates curl gnupg git ufw

echo "== Installing Docker Engine =="
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg

echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

sudo apt-get update -y
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

echo "== Allowing current user to run docker without sudo =="
sudo usermod -aG docker "$USER"

echo "== Configuring firewall =="
sudo ufw allow OpenSSH
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw allow 5000/tcp   # backend API (remove once behind Nginx reverse proxy)
sudo ufw allow 5173/tcp   # frontend (remove once behind Nginx reverse proxy)
sudo ufw --force enable

echo "== Done. Log out and back in for docker group membership to apply. =="
echo "Next: git clone your repo, cd into it, copy .env.example to .env, then run:"
echo "  docker compose up --build -d"
