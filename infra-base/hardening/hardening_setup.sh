#!/usr/bin/env bash
# Hardening setup script for Ubuntu LTS / Debian Host (§8.1)
set -euo pipefail

echo "=========================================="
echo "Starting Host Hardening Setup..."
echo "=========================================="

# Ensure script is run as root
if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    echo "ERROR: This script must be run as root." >&2
    exit 1
fi

# 1. Update system and enable auto security updates
echo "[+] Configuring package manager and updates..."
apt-get update
apt-get install -y unattended-upgrades update-notifier-common chrony auditd ufw
dpkg-reconfigure -plow unattended-upgrades

# 2. Configure SSH security
echo "[+] Hardening SSH configuration..."
SSH_CONFIG="/etc/ssh/sshd_config.d/hardening.conf"
mkdir -p "$(dirname "$SSH_CONFIG")"
cat <<EOF > "$SSH_CONFIG"
# SSH Security Hardening settings
PasswordAuthentication no
PermitRootLogin no
PubkeyAuthentication yes
MaxAuthTries 3
ClientAliveInterval 300
ClientAliveCountMax 2
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
EOF
if systemctl is-active --quiet ssh; then
    systemctl restart ssh
else
    systemctl restart sshd
fi

# 3. Configure Chrony for reliable NTP (crucial for JWT/TOTP)
echo "[+] Enabling and starting Chrony NTP daemon..."
systemctl enable --now chrony

# 4. Configure auditd rules
echo "[+] Configuring auditd security rules..."
AUDIT_RULES="/etc/audit/rules.d/hardening.rules"
cat <<EOF > "$AUDIT_RULES"
# First delete all rules
-D

# Buffer size
-b 8192

# Fail closed on audit log fullness
-f 2

# Watch system configuration changes
-w /etc/passwd -p wa -k passwd_changes
-w /etc/shadow -p wa -k shadow_changes
-w /etc/group -p wa -k group_changes
-w /etc/sudoers -p wa -k sudoers_changes

# Watch syscalls for execution of new binaries
-a always,exit -F arch=b64 -S execve -k exec_log
-a always,exit -F arch=b32 -S execve -k exec_log

# Lock audit configuration (reboot required to unlock)
-e 2
EOF
service auditd restart

# 5. Configure Firewall (ufw)
echo "[+] Configuring UFW rules..."
# Reset firewall to default
ufw --force reset

# Set default policies (Deny-by-default on both incoming and outgoing)
ufw default deny incoming
ufw default deny outgoing

# Allow incoming HTTP/S (proxy)
ufw allow proto tcp from any to any port 80 comment 'Allow HTTP'
ufw allow proto tcp from any to any port 443 comment 'Allow HTTPS'

# Allow incoming SSH (restrict in production to WireGuard or specific admin IPs)
ufw allow proto tcp from any to any port 22 comment 'Allow SSH'

# Outgoing Allowlist (§4.4)
# DNS resolution
ufw allow out proto udp to any port 53 comment 'Allow DNS'
ufw allow out proto tcp to any port 53 comment 'Allow DNS'

# NTP sync
ufw allow out proto udp to any port 123 comment 'Allow NTP'

# HTTPS for package updates and ClamAV signatures (or narrow down to specific domains)
ufw allow out proto tcp to any port 443 comment 'Allow Outbound HTTPS'
ufw allow out proto tcp to any port 80 comment 'Allow Outbound HTTP'

# Allow outbound traffic to Postgres and Redis databases
ufw allow out proto tcp to any port 5432 comment 'Allow Outbound Postgres'
ufw allow out proto tcp to any port 6379 comment 'Allow Outbound Redis'

# Enable firewall
ufw --force enable
ufw status verbose

echo "=========================================="
echo "Host Hardening Completed Successfully!"
echo "=========================================="
