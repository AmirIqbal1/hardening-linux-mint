#!/usr/bin/env bash
set -Eeuo pipefail

# Linux Mint / Ubuntu Desktop Hardening Script
# Target: Linux Mint 22.x and Ubuntu 24.04 LTS desktops
# Safe baseline hardening, with optional server/SSH hardening.

LOGFILE="/var/log/mint_hardening.log"
BACKUP_DIR="/root/mint-hardening-backups/$(date +%Y%m%d-%H%M%S)"
APPLY_LYNIS_BASELINE=false
SERVER_MODE=false
HARDEN_SSH=false
DRY_RUN=false

usage() {
  cat <<USAGE
Usage: sudo ./mint_hardening.sh [options]

Options:
  --apply-lynis-baseline   Apply safe extra changes commonly suggested by Lynis
  --server-mode            Apply stricter server-style changes, including optional service disabling
  --harden-ssh             Harden SSH if OpenSSH server is installed
  --dry-run                Show what would run without changing the system
  -h, --help               Show this help

Examples:
  sudo ./mint_hardening.sh
  sudo ./mint_hardening.sh --apply-lynis-baseline
  sudo ./mint_hardening.sh --server-mode --harden-ssh --apply-lynis-baseline
USAGE
}

for arg in "$@"; do
  case "$arg" in
    --apply-lynis-baseline) APPLY_LYNIS_BASELINE=true ;;
    --server-mode) SERVER_MODE=true ;;
    --harden-ssh) HARDEN_SSH=true ;;
    --dry-run) DRY_RUN=true ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $arg"; usage; exit 1 ;;
  esac
done

if [[ "${EUID}" -ne 0 ]]; then
  echo "Please run as root: sudo $0"
  exit 1
fi

mkdir -p "$(dirname "$LOGFILE")" "$BACKUP_DIR"
exec > >(tee -a "$LOGFILE") 2>&1

run() {
  echo "+ $*"
  if [[ "$DRY_RUN" == false ]]; then
    "$@"
  fi
}

backup_file() {
  local file="$1"
  if [[ -f "$file" ]]; then
    local dest="$BACKUP_DIR${file}"
    mkdir -p "$(dirname "$dest")"
    cp -a "$file" "$dest"
    echo "Backed up $file to $dest"
  fi
}

write_file() {
  local file="$1"
  local mode="${2:-0644}"
  backup_file "$file"
  if [[ "$DRY_RUN" == false ]]; then
    cat > "$file"
    chmod "$mode" "$file"
  else
    cat >/dev/null
  fi
}

require_ubuntu_mint() {
  if [[ -r /etc/os-release ]]; then
    . /etc/os-release
    echo "Detected: ${PRETTY_NAME:-unknown}"
    case "${ID:-}" in
      linuxmint|ubuntu) ;;
      *) echo "Warning: this script is intended for Linux Mint/Ubuntu. Continuing carefully." ;;
    esac
  fi
}

section() { echo; echo "==== $* ===="; }

require_ubuntu_mint

section "Repair dpkg and update packages"
run dpkg --configure -a
run apt update
run apt upgrade -y

section "Install security packages"
run apt install -y \
  ufw \
  fail2ban \
  unattended-upgrades \
  apt-listchanges \
  needrestart \
  auditd \
  apparmor \
  apparmor-profiles \
  apparmor-utils \
  libpam-pwquality \
  lynis \
  rkhunter \
  clamav \
  debsums

section "Enable automatic updates"
run apt install -y unattended-upgrades
run dpkg-reconfigure -f noninteractive unattended-upgrades || true
write_file /etc/apt/apt.conf.d/20auto-upgrades 0644 <<'AUTOUPGRADES'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
AUTOUPGRADES

section "Configure UFW firewall"
run ufw default deny incoming
run ufw default allow outgoing
if systemctl list-unit-files | grep -q '^ssh\.service'; then
  run ufw limit OpenSSH || run ufw limit 22/tcp
fi
run ufw --force enable

section "Configure Fail2Ban"
write_file /etc/fail2ban/jail.local 0644 <<'FAIL2BAN'
[DEFAULT]
bantime = 1h
findtime = 10m
maxretry = 5
backend = systemd

[sshd]
enabled = true
port = ssh
maxretry = 3
FAIL2BAN
run systemctl enable --now fail2ban
run systemctl restart fail2ban

section "Configure AppArmor and auditd"
run systemctl enable --now apparmor
run aa-enforce /etc/apparmor.d/* || true
run systemctl enable --now auditd || true

section "Password quality policy"
write_file /etc/security/pwquality.conf 0644 <<'PWQUALITY'
minlen = 12
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
retry = 3
difok = 3
PWQUALITY

section "Safe sysctl hardening"
write_file /etc/sysctl.d/99-mint-hardening.conf 0644 <<'SYSCTL'
# Network hardening
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1

# Kernel hardening
kernel.randomize_va_space = 2
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.yama.ptrace_scope = 1
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2
SYSCTL
run sysctl --system

section "SSH hardening"
if [[ "$HARDEN_SSH" == true ]]; then
  if [[ -f /etc/ssh/sshd_config ]]; then
    backup_file /etc/ssh/sshd_config
    write_file /etc/ssh/sshd_config.d/99-mint-hardening.conf 0644 <<'SSHCONF'
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
X11Forwarding no
MaxAuthTries 3
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2
SSHCONF
    run sshd -t
    run systemctl restart ssh || run systemctl restart sshd
  else
    echo "OpenSSH server not installed. Skipping SSH hardening."
  fi
else
  echo "Skipping SSH hardening. Use --harden-ssh if this machine has SSH keys set up."
fi

section "Lynis safe baseline fixes"
if [[ "$APPLY_LYNIS_BASELINE" == true ]]; then
  # These are safe desktop-friendly changes that Lynis often recommends.
  write_file /etc/profile.d/99-mint-hardening-umask.sh 0644 <<'UMASK'
# More private default permissions for newly created files/folders.
umask 027
UMASK

  write_file /etc/systemd/coredump.conf.d/99-mint-hardening.conf 0644 <<'COREDUMP'
[Coredump]
Storage=none
ProcessSizeMax=0
COREDUMP

  mkdir -p /etc/systemd/journald.conf.d
  write_file /etc/systemd/journald.conf.d/99-mint-hardening.conf 0644 <<'JOURNALD'
[Journal]
Storage=persistent
Compress=yes
SystemMaxUse=512M
MaxFileSec=1month
JOURNALD

  run systemctl daemon-reload
  run systemctl restart systemd-journald
  run systemctl mask ctrl-alt-del.target || true

  # Safer home directory permissions without breaking the desktop.
  for home in /home/*; do
    [[ -d "$home" ]] || continue
    run chmod 750 "$home" || true
  done
else
  echo "Skipping automatic Lynis baseline fixes. Use --apply-lynis-baseline to enable them."
fi

section "Server-mode extras"
if [[ "$SERVER_MODE" == true ]]; then
  for svc in avahi-daemon cups bluetooth; do
    if systemctl list-unit-files | grep -q "^${svc}\.service"; then
      run systemctl disable --now "$svc" || true
    fi
  done
else
  echo "Skipping server-mode service disabling. This is recommended for normal Mint desktops."
fi

section "RKHunter setup"
run rkhunter --update || true
run rkhunter --propupd || true

section "Final security audits"
run lynis audit system --quick || true
run rkhunter --check --sk --rwo || true

section "Complete"
echo "Linux Mint / Ubuntu hardening complete."
echo "Log file: $LOGFILE"
echo "Backups: $BACKUP_DIR"
echo
 echo "Recommended next commands:"
echo "  sudo lynis audit system"
echo "  sudo ufw status verbose"
echo "  systemctl status fail2ban --no-pager"
