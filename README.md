# Linux Mint Hardening Script

A safer hardening script for **Linux Mint 22.x** and **Ubuntu 24.04 LTS** desktops.

Linux Mint 22.x is based on Ubuntu 24.04, so this script targets the Ubuntu 24.04 package base.

## What it does

- Updates the system
- Installs common security tools
- Enables UFW firewall
- Enables Fail2Ban
- Enables AppArmor
- Enables auditd
- Enables unattended upgrades
- Applies safe sysctl hardening
- Sets password quality rules
- Runs Lynis audit
- Runs RKHunter checks
- Creates backups before changing config files
- Logs everything to `/var/log/mint_hardening.log`

## Safe by default

By default, the script avoids changes that commonly break normal desktop use.

It does **not** disable Bluetooth, printing, Avahi, or SSH unless you ask it to.

## Usage

Clone the repo:

```bash
git clone https://github.com/AmirIqbal1/hardening-debian.git
cd hardening-debian
```

Make the script executable:

```bash
chmod +x mint_hardening.sh
```

Run the safe desktop baseline:

```bash
sudo ./mint_hardening.sh
```

Run with safe Lynis-style fixes applied automatically:

```bash
sudo ./mint_hardening.sh --apply-lynis-baseline
```

For a server/headless machine:

```bash
sudo ./mint_hardening.sh --server-mode --harden-ssh --apply-lynis-baseline
```

Preview without changing anything:

```bash
sudo ./mint_hardening.sh --dry-run
```

## Options

| Option | What it does |
|---|---|
| `--apply-lynis-baseline` | Applies safe extra changes commonly suggested by Lynis |
| `--server-mode` | Disables desktop/network convenience services such as CUPS, Avahi and Bluetooth |
| `--harden-ssh` | Applies stricter SSH settings if OpenSSH server is installed |
| `--dry-run` | Shows commands without making changes |

## Important note about Lynis

Lynis is an auditing tool, not a one-click automatic fixer. This script applies a safe baseline that commonly improves Lynis results, but it deliberately does not blindly apply every Lynis suggestion.

Some Lynis recommendations can break desktop usability, printing, local networking, Bluetooth, or SSH access.

## Logs and backups

Log file:

```bash
/var/log/mint_hardening.log
```

Backups:

```bash
/root/mint-hardening-backups/
```

## Recommended checks after running

```bash
sudo lynis audit system
sudo ufw status verbose
systemctl status fail2ban --no-pager
systemctl status apparmor --no-pager
```
