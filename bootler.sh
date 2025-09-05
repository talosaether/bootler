#!/usr/bin/env bash
# ============================================================================
# vm-deploy-merge.sh — Bootstrap a fresh Ubuntu VM for GitHub repository deployment
# ============================================================================
# Usage:
#   sudo ./vm-deploy-merge.sh \
#     --repo owner/repo \
#     [--project-dir /opt/project] \
#     [--server-name example.com] \
#     [--upstream-port 8000]
#
# Environment (optional):
#   GITHUB_TOKEN       Personal access token for non-interactive gh auth
#   SSH_KEY_EMAIL      Email comment for generated SSH key
#
# Notes:
# - Script is idempotent where reasonable and safe to re-run.
# - Uses SSH for git operations. If GITHUB_TOKEN is present and has
#   appropriate scopes, the script will attempt to upload the SSH key.
# - Installs Docker, Python, Node (via nvm), gh, Terraform, and common tools.
# - Configures UFW after allowing SSH to avoid lockout.
# - Provides optional Nginx reverse proxy with parameterized upstream.
# ============================================================================

# Strict shell settings with error context
set -Eeuo pipefail
IFS=$'\n\t'
# Include the failing command for easier debugging
trap 'echo "[ERROR] line ${LINENO}: \"${BASH_COMMAND}\" exited with $?" >&2' ERR
umask 027
export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_MODE=a   # auto-restart services during upgrades, no prompts
# Prevent locale warnings on minimal cloud images (pip/gh/apt output)
export LC_ALL=C.UTF-8
export LANG=C.UTF-8
# Optional verbose tracing
[[ "${DEBUG:-0}" = "1" ]] && set -x

# -------------------------- Logging -----------------------------------------
log()     { echo "[INFO]  $(date +'%Y-%m-%d %H:%M:%S') $*"; }
warn()    { echo "[WARN]  $*"; }
error()   { echo "[ERROR] $*" >&2; }
success() { echo "[OK]    $*"; }

# -------------------------- Config ------------------------------------------
REPO=""
PROJECT_DIR="/opt/project"
SERVER_NAME="_"           # Use a real hostname or domain for TLS later
UPSTREAM_PORT="8000"       # Upstream app port for reverse proxy
SSH_KEY_EMAIL="${SSH_KEY_EMAIL:-dev@example.com}"
OPEN_DEV_PORTS=0           # Only open 3000/8000 if explicitly requested
SSH_PORT=22                # SSH port for UFW allow (override with --ssh-port)
BRANCH=""                  # Optional branch/tag to clone
SSH_HARDEN=0               # Optional: disable SSH password auth
SWAP_MB=0                  # Optional: create swapfile of N MB if none
F2B_TRUSTED_IPS="${F2B_TRUSTED_IPS:-}"  # Optional: fail2ban whitelist (space-separated)

# -------------------------- Helpers -----------------------------------------
require_root() {
  if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
    error "Run as root (use sudo)."; exit 1
  fi
}

# Resolve a reasonable target user and home robustly
TARGET_USER="${SUDO_USER:-${USER:-root}}"
# Cross-platform home directory resolution
if command -v getent >/dev/null 2>&1; then
  TARGET_HOME="$(getent passwd "$TARGET_USER" | cut -d: -f6 || true)"
elif [[ "$TARGET_USER" == "root" ]]; then
  TARGET_HOME="/root"
else
  TARGET_HOME="/home/$TARGET_USER"
fi
[[ -n "$TARGET_HOME" ]] || TARGET_HOME="/root"

run_as() { sudo -u "$TARGET_USER" -H bash -lc "$*"; }

# Tiny retry wrapper for flaky networks/mirrors (with backoff + logging)
retry() {
  local n=0 max=5 delay=3
  until "$@"; do
    n=$((n+1))
    if [[ $n -ge $max ]]; then
      error "retry: command failed after ${max} attempts: $*"
      return 1
    fi
    warn "retry: attempt $n failed for: $* (sleep ${delay}s)"
    sleep $delay
    delay=$((delay*2))
  done
}
apt_update_once() { retry apt-get update -y; }
apt_install() { retry apt-get install -y --no-install-recommends "$@"; }
# curl helper that benefits from retry()
curl_retry() { retry curl -fsSL "$@"; }

# -------------------------- OS guardrail ------------------------------------
check_os() {
  if [[ -r /etc/os-release ]]; then
    . /etc/os-release
    if [[ "${ID:-}" != "ubuntu" ]]; then
      error "This script targets Ubuntu. Detected: ${ID:-unknown}"
      error "Bootler is designed to bootstrap fresh Ubuntu VMs (22.04/24.04 LTS)"
      error "Please run this script on an Ubuntu system or use it as a reference for other distros"
      exit 1
    fi
  else
    error "/etc/os-release missing; cannot verify OS"
    error "This script requires Ubuntu. Please run on a supported Ubuntu system."
    exit 1
  fi
}

# -------------------------- Arg parsing --------------------------------------
parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --repo)        REPO="$2"; shift 2;;
      --project-dir) PROJECT_DIR="$2"; shift 2;;
      --server-name) SERVER_NAME="$2"; shift 2;;
      --upstream-port) UPSTREAM_PORT="$2"; shift 2;;
      --branch)      BRANCH="$2"; shift 2;;
      --ssh-port)    SSH_PORT="$2"; shift 2;;
      --open-dev-ports) OPEN_DEV_PORTS=1; shift 1;;
      --ssh-hardening) SSH_HARDEN=1; shift 1;;
      --swap-mb)     SWAP_MB="$2"; shift 2;;
      --fail2ban-trusted) F2B_TRUSTED_IPS="$2"; shift 2;;
      -h|--help)
        cat <<USAGE
Usage: sudo ./bootler.sh --repo owner/repo [options]
  --repo owner/repo       GitHub slug (required)
  --project-dir DIR       Project directory (default: /opt/project)
  --server-name NAME      Public hostname or domain for reverse proxy (default: _)
  --upstream-port N       Upstream app port (default: 8000)
  --branch NAME           Branch or tag to clone (default: repo default)
  --ssh-port N            SSH port to allow through UFW (default: 22)
  --open-dev-ports        Also allow 3000 and 8000 via UFW (default: off)
  --ssh-hardening         Disable SSH password logins (requires key present)
  --swap-mb N             Create swapfile of N MB if no swap exists (default: 0)
  --fail2ban-trusted STR  Space-separated IPs/CIDRs to whitelist in fail2ban
USAGE
        exit 0;;
      *) error "Unknown option: $1"; exit 1;;
    esac
  done
  if [[ -z "$REPO" ]]; then error "--repo owner/repo is required"; exit 1; fi
}

# -------------------------- System Preparation ------------------------------
update_system() {
  log "Updating system packages..."
  apt_update_once
  retry apt-get full-upgrade -y
  success "System packages updated"
}

install_build_tools() {
  log "Installing essential build tools..."
  apt_install build-essential curl wget git ca-certificates unzip gnupg lsb-release jq yq tree vim nano openssh-client ufw
  success "Build tools installed"
}

install_python() {
  log "Installing Python 3 and pipx..."
  apt_install python3 python3-pip python3-venv python3-dev pipx || true
  if ! command -v pipx >/dev/null 2>&1; then
    python3 -m pip install -U pip pipx
  fi
  run_as 'pipx ensurepath' || true
  # Create symlink for python command (idempotent)
  ln -sf /usr/bin/python3 /usr/bin/python
  success "Python 3 and pip installed"
}

install_nodejs() {
  log "Installing Node.js via nvm for $TARGET_USER..."
  retry run_as 'export NVM_DIR="$HOME/.nvm"; mkdir -p "$NVM_DIR"; \
    if [[ ! -s "$NVM_DIR/nvm.sh" ]]; then curl -fsSL https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.7/install.sh | bash; fi; \
    . "$NVM_DIR/nvm.sh"; nvm install --lts; \
    nvm alias default "lts/*"; \
    corepack enable || true; \
    corepack prepare pnpm@latest --activate || true; \
    node -v && npm -v && pnpm -v || true'
  success "Node.js installed"
}

install_docker() {
  log "Installing Docker engine and compose..."
  apt_install ca-certificates gnupg
  install -m 0755 -d /etc/apt/keyrings
  if [[ ! -f /etc/apt/keyrings/docker.gpg ]]; then
    curl_retry https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    chmod a+r /etc/apt/keyrings/docker.gpg
  fi
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(. /etc/os-release; echo $VERSION_CODENAME) stable" \
    > /etc/apt/sources.list.d/docker.list
  apt_update_once
  apt_install docker-ce docker-ce-cli containerd.io docker-compose-plugin
  usermod -aG docker "$TARGET_USER" || true
  systemctl enable --now docker
  success "Docker installed"
}

install_terraform() {
  log "Installing Terraform..."
  install -m 0755 -d /etc/apt/keyrings
  if [[ ! -f /etc/apt/keyrings/hashicorp.gpg ]]; then
    curl_retry https://apt.releases.hashicorp.com/gpg | gpg --dearmor -o /etc/apt/keyrings/hashicorp.gpg
    chmod a+r /etc/apt/keyrings/hashicorp.gpg
  fi
  echo "deb [signed-by=/etc/apt/keyrings/hashicorp.gpg] https://apt.releases.hashicorp.com $(. /etc/os-release; echo $VERSION_CODENAME) main" \
    > /etc/apt/sources.list.d/hashicorp.list
  apt_update_once
  apt_install terraform
  success "Terraform installed"
}

# -------------------------- Development Tools -------------------------------
install_neovim() {
  log "Installing Neovim..."
  apt_install neovim
  success "Neovim installed"
}

install_github_cli() {
  log "Installing GitHub CLI..."
  install -m 0755 -d /etc/apt/keyrings
  if [[ ! -f /etc/apt/keyrings/githubcli.gpg ]]; then
    curl_retry -o /etc/apt/keyrings/githubcli.gpg https://cli.github.com/packages/githubcli-archive-keyring.gpg
    chmod go+r /etc/apt/keyrings/githubcli.gpg
  fi
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/githubcli.gpg] https://cli.github.com/packages stable main" \
    > /etc/apt/sources.list.d/github-cli.list
  apt_update_once
  apt_install gh
  success "GitHub CLI installed"
}

# -------------------------- Security & Auth ---------------------------------
ensure_ssh_key_and_known_hosts() {
  log "Ensuring SSH key and known_hosts..."
  install -d -m 700 "$TARGET_HOME/.ssh"
  chown -R "$TARGET_USER:$TARGET_USER" "$TARGET_HOME/.ssh"
  if [[ ! -f "$TARGET_HOME/.ssh/id_ed25519" ]]; then
    run_as "ssh-keygen -t ed25519 -C '$SSH_KEY_EMAIL' -f ~/.ssh/id_ed25519 -N ''"
    success "Generated SSH key for $TARGET_USER"
  else
    warn "SSH key already exists; skipping generation"
  fi
  # add github.com host key once, not every run
  if ! ssh-keygen -F github.com -f "$TARGET_HOME/.ssh/known_hosts" >/dev/null 2>&1; then
    ssh-keyscan -H github.com >> "$TARGET_HOME/.ssh/known_hosts" 2>/dev/null || true
  fi
  chown "$TARGET_USER:$TARGET_USER" "$TARGET_HOME/.ssh/known_hosts" || true
  # enforce private key perms just in case
  [[ -f "$TARGET_HOME/.ssh/id_ed25519" ]] && chmod 600 "$TARGET_HOME/.ssh/id_ed25519" || true
  chmod 644 "$TARGET_HOME/.ssh/id_ed25519.pub" 2>/dev/null || true
  success "SSH known_hosts updated"
}

setup_github_auth() {
  log "Setting up GitHub authentication (SSH protocol)..."
  if run_as 'gh auth status >/dev/null 2>&1'; then
    success "GitHub authentication already configured"
    return 0
  fi
  if [[ -n "${GITHUB_TOKEN:-}" ]]; then
    run_as "echo '$GITHUB_TOKEN' | gh auth login --hostname github.com --git-protocol ssh --with-token && gh config set git_protocol ssh"
    success "GitHub authentication configured with token"
  else
    if [[ -t 0 ]]; then
      warn "GITHUB_TOKEN not set; interactive login will prompt"
      run_as "gh auth login --hostname github.com --git-protocol ssh && gh config set git_protocol ssh"
    else
      warn "No TTY and no GITHUB_TOKEN; skipping gh interactive login"
    fi
  fi
  # Force SSH for submodules and any hardcoded https://github.com URLs
  run_as "git config --global url.'ssh://git@github.com/'.insteadOf 'https://github.com/'" || true
  run_as "git config --global url.'git@github.com:'.insteadOf 'https://github.com/'" || true
}

upload_ssh_key_to_github() {
  if [[ -n "${GITHUB_TOKEN:-}" ]]; then
    log "Attempting to upload SSH public key to GitHub via gh..."
    local pub="$TARGET_HOME/.ssh/id_ed25519.pub"
    if [[ -f "$pub" ]]; then
      local title; title="$(hostname)-$(date +%F)"
      run_as "gh ssh-key add '$pub' --title '$title'" || warn "Failed to add SSH key via gh; check token scopes"
      success "GitHub SSH key upload attempted"
    else
      warn "Public key not found; skipping upload"
    fi
  else
    warn "GITHUB_TOKEN not set; cannot auto-upload SSH key. Public key is at $TARGET_HOME/.ssh/id_ed25519.pub"
  fi
}

install_git_lfs() {
  log "Installing Git LFS..."
  apt_install git-lfs || true
  run_as "git lfs install --skip-repo" || true
  success "Git LFS installed"
}

smoke_test_github_ssh() {
  log "Verifying GitHub SSH access..."
  if run_as 'ssh -o StrictHostKeyChecking=accept-new -T git@github.com || true' 2>&1 | grep -qi "successfully authenticated"; then
    success "GitHub SSH OK"
  else
    warn "GitHub SSH handshake not confirmed. On first connect this can be normal; try again after login."
  fi
}

setup_firewall() {
  log "Configuring UFW..."
  apt_install ufw
  # Enable UFW logging for rate-limit visibility (low noise)
  ufw logging low || true
  # Ensure IPv6 is actually filtered too
  if [[ -f /etc/default/ufw ]]; then
    sed -ri 's/^IPV6=.*/IPV6=yes/' /etc/default/ufw || true
  fi
  ufw default deny incoming || true
  ufw default allow outgoing || true
  # Rate-limit SSH to reduce brute forcing
  if [[ "$SSH_PORT" -eq 22 ]]; then
    ufw limit OpenSSH || true
  else
    ufw limit "${SSH_PORT}/tcp" || true
  fi
  ufw allow 80,443/tcp || true
  if [[ "$OPEN_DEV_PORTS" -eq 1 ]]; then
    ufw allow 3000,8000/tcp || true
  fi
  ufw --force enable || true
  success "Firewall configured"
}

# -------------------------- Project Setup -----------------------------------
clone_repository() {
  log "Cloning repository $REPO..."
  install -d -o "$TARGET_USER" -g "$TARGET_USER" -m 750 "$PROJECT_DIR"
  # Create project bin directory for user scripts
  install -d -o "$TARGET_USER" -g "$TARGET_USER" -m 750 "$PROJECT_DIR/bin"
  local repo_dir="$PROJECT_DIR/${REPO##*/}"
  if [[ -d "$repo_dir/.git" ]]; then
    log "Repository exists; pulling latest..."
    run_as "cd '$repo_dir' && git fetch --prune --filter=blob:none && git pull --ff-only"
  else
    # Prefer gh; fall back to raw git over SSH if gh stumbles. Respect --branch if set.
    if [[ -n "$BRANCH" ]]; then
      run_as "cd '$PROJECT_DIR' && ( gh repo clone '$REPO' -- --depth 1 --no-tags --filter=blob:none -b '$BRANCH' \
        || git clone --depth 1 --no-tags --filter=blob:none -b '$BRANCH' git@github.com:$REPO.git )"
    else
      run_as "cd '$PROJECT_DIR' && ( gh repo clone '$REPO' -- --depth 1 --no-tags --filter=blob:none \
        || git clone --depth 1 --no-tags --filter=blob:none git@github.com:$REPO.git )"
    fi
  fi
  # Initialize submodules if present
  if [[ -f "$repo_dir/.gitmodules" ]]; then
    run_as "cd '$repo_dir' && git -c submodule.fetchJobs=4 submodule update --init --recursive --depth 1 --recommend-shallow" \
      || warn "Submodules failed to init"
  fi
  success "Repository ready at $repo_dir"
}

setup_deployment_env() {
  log "Setting up environment file..."
  local repo_dir="$PROJECT_DIR/${REPO##*/}"
  if [[ -f "$repo_dir/.env.example" && ! -f "$repo_dir/.env" ]]; then
    cp "$repo_dir/.env.example" "$repo_dir/.env"
    warn "Created .env from .env.example; review and edit as needed"
    chown "$TARGET_USER:$TARGET_USER" "$repo_dir/.env" || true
    chmod 640 "$repo_dir/.env" || true
  elif [[ ! -f "$repo_dir/.env" ]]; then
    warn "No .env.example found; consider creating $repo_dir/.env"
  else
    log ".env already present; leaving in place"
    # ensure sane perms on existing file
    chown "$TARGET_USER:$TARGET_USER" "$repo_dir/.env" 2>/dev/null || true
    chmod 640 "$repo_dir/.env" 2>/dev/null || true
  fi
  success "Environment file step completed"
}

setup_cicd_secrets() {
  log "Configuring CI/CD secrets..."
  warn "CI/CD secrets configuration requires manual setup per platform"
  success "CI/CD secrets step completed"
}

# -------------------------- Build & Verify ----------------------------------
test_deployment_pipeline() {
  log "Testing deployment pipeline..."
  local repo_dir="$PROJECT_DIR/${REPO##*/}"

  # Python project bootstrap
  if [[ -f "$repo_dir/requirements.txt" || -f "$repo_dir/pyproject.toml" ]]; then
    run_as "cd '$repo_dir' && python3 -m venv .venv && . .venv/bin/activate && pip install -U pip setuptools wheel && { [[ -f requirements.txt ]] && pip install -r requirements.txt || true; } && { [[ -f pyproject.toml ]] && pip install . || true; }"
  fi

  # Node project bootstrap
  if [[ -f "$repo_dir/package.json" ]]; then
    run_as "cd '$repo_dir' && if command -v pnpm >/dev/null 2>&1; then pnpm install --frozen-lockfile; else npm ci --no-audit --no-fund || npm install --no-audit --no-fund; fi && (npm run -s build --if-present || pnpm run -s build --if-present || true)"
  fi

  # Run tests if available
  if [[ -f "$repo_dir/Makefile" ]] && grep -q "test" "$repo_dir/Makefile"; then
    run_as "cd '$repo_dir' && make test" || warn "Tests failed, continuing..."
  fi

  success "Deployment pipeline tested"
}

# -------------------------- Monitoring & Logging ----------------------------
setup_monitoring() {
  log "Installing basic monitoring and logrotate policy..."
  apt_install htop iotop
  # Ensure logs directory exists and is writable by the target user
  install -d -o "$TARGET_USER" -g "$TARGET_USER" -m 750 "$PROJECT_DIR/logs"
  cat >/etc/logrotate.d/project <<EOF
$PROJECT_DIR/logs/*.log {
    daily
    missingok
    rotate 7
    compress
    delaycompress
    notifempty
    su $TARGET_USER $TARGET_USER
    create 0640 $TARGET_USER $TARGET_USER
}
EOF
  success "Monitoring and logrotate configured"
}

limit_journald() {
  log "Tuning systemd-journald size/retention..."
  install -d -m 0755 /etc/systemd/journald.conf.d
  cat >/etc/systemd/journald.conf.d/limits.conf <<'EOF'
[Journal]
SystemMaxUse=200M
SystemMaxFileSize=20M
MaxRetentionSec=7day
EOF
  systemctl restart systemd-journald || true
  success "journald limits applied (200M cap, 7d retention)"
}

configure_docker_daemon() {
  log "Hardening Docker daemon defaults (logs, live-restore)..."
  install -d -m 0755 /etc/docker
  if [[ ! -f /etc/docker/daemon.json ]]; then
    cat >/etc/docker/daemon.json <<'JSON'
{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "50m",
    "max-file": "3"
  },
  "live-restore": true
}
JSON
  else
    warn "/etc/docker/daemon.json exists; not overwriting. Ensure log rotation is configured."
  fi
  systemctl reload docker || systemctl restart docker || true
  success "Docker daemon defaults applied"
}

# -------------------------- Optional Enhancements ---------------------------
install_additional_tools() {
  log "Installing additional tools..."
  apt_install zip
  success "Additional tools installed"
}

setup_timesyncd() {
  log "Ensuring system time sync (systemd-timesyncd)..."
  if systemctl list-unit-files | grep -q '^systemd-timesyncd.service'; then
    systemctl enable --now systemd-timesyncd || true
    success "Time sync active"
  else
    warn "systemd-timesyncd not available; skipping"
  fi
}

setup_swap_if_missing() {
  if [[ "${SWAP_MB:-0}" -gt 0 ]] && ! swapon --show | grep -q '^'; then
    log "Creating ${SWAP_MB}M swapfile..."
    fallocate -l "${SWAP_MB}M" /swapfile || dd if=/dev/zero of=/swapfile bs=1M count="${SWAP_MB}"
    chmod 600 /swapfile
    mkswap /swapfile
    swapon /swapfile
    cp /etc/fstab /etc/fstab.bak
    grep -q '/swapfile' /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab
    success "Swapfile created and enabled"
  else
    log "Swap present or SWAP_MB=0; skipping swapfile creation"
  fi
}

ssh_hardening() {
  log "Applying SSH daemon hardening..."
  if [[ -f "$TARGET_HOME/.ssh/id_ed25519.pub" ]]; then
    install -d -m 0755 /etc/ssh/sshd_config.d
    cat >/etc/ssh/sshd_config.d/99-hardening.conf <<'EOF'
PasswordAuthentication no
PermitRootLogin prohibit-password
PubkeyAuthentication yes
EOF
    # If user opted for a custom SSH port, set it here in a dedicated drop-in.
    if [[ "${SSH_PORT:-22}" -ne 22 ]]; then
      echo "Port ${SSH_PORT}" >/etc/ssh/sshd_config.d/10-port.conf
    fi
    sshd -t && (systemctl reload sshd || systemctl reload ssh) || warn "sshd reload failed; check config"
    success "SSH hardening applied (password auth disabled)"
  else
    warn "SSH hardening requested but no public key at $TARGET_HOME/.ssh/id_ed25519.pub; skipped"
  fi
}

setup_unattended_upgrades() {
  log "Setting up unattended-upgrades for security patches..."
  apt_install unattended-upgrades
  
  # Configure automatic security updates
  if command -v pro >/dev/null 2>&1 && pro status --format json 2>/dev/null | grep -q '"attached": *true'; then
    cat >/etc/apt/apt.conf.d/50unattended-upgrades <<'EOF'
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}-security";
    "${distro_id}ESMApps:${distro_codename}-apps-security";
    "${distro_id}ESM:${distro_codename}-infra-security";
};

Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
EOF
  else
    cat >/etc/apt/apt.conf.d/50unattended-upgrades <<'EOF'
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}-security";
};
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
EOF
  fi
  
  # Enable automatic updates (correct APT periodic keys)
  cat >/etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
EOF
  
  systemctl enable unattended-upgrades
  systemctl start unattended-upgrades
  success "Unattended upgrades configured for security patches"
}

setup_fail2ban() {
  log "Setting up fail2ban for SSH protection..."
  apt_install fail2ban
  
  # Create fail2ban configuration
  cat >/etc/fail2ban/jail.local <<EOF
[DEFAULT]
bantime  = 1h
findtime = 10m
maxretry = 3
backend  = systemd
ignoreip = 127.0.0.1/8 ::1 ${F2B_TRUSTED_IPS}

[sshd]
enabled = true
port    = $SSH_PORT
filter  = sshd
logpath = %(sshd_log)s
EOF
  
  systemctl enable fail2ban
  systemctl start fail2ban
  success "Fail2ban configured for SSH protection"
}

setup_shell_customization() {
  log "Setting up shell quality-of-life for $TARGET_USER..."
  local rc="$TARGET_HOME/.bashrc"
  if ! grep -q "# Custom aliases (vm-deploy)" "$rc" 2>/dev/null; then
    # Expand PROJECT_DIR now, keep \$PATH literal for login-time expansion
    cat >>"$rc" <<EOF

# Custom aliases (vm-deploy)
alias ll='ls -alF'
alias la='ls -A'
alias l='ls -CF'
alias ..='cd ..'
alias ...='cd ../..'
alias grep='grep --color=auto'

# Project bin on PATH
export PATH="\$PATH:${PROJECT_DIR}/bin"
EOF
  fi
  chown "$TARGET_USER:$TARGET_USER" "$rc" || true
  success "Shell customization updated"
}

install_database_clients() {
  log "Installing database clients..."
  apt_install postgresql-client
  # default-mysql-client isn't present on some releases; fall back sensibly
  apt_install default-mysql-client || \
    apt_install mysql-client || apt_install mariadb-client
  success "Database clients installed"
}

setup_reverse_proxy() {
  log "Installing and configuring Nginx reverse proxy..."
  apt_install nginx
  # Put the upgrade map in http{} via conf.d so Connection header is correct
  cat >/etc/nginx/conf.d/upgrade_map.conf <<'EOF'
map $http_upgrade $connection_upgrade {
    default upgrade;
    ''      close;
}
EOF
  cat >/etc/nginx/sites-available/default <<EOF
server {
    listen 80 default_server;
    listen [::]:80 default_server;

    server_name $SERVER_NAME;
    server_tokens off;

    # Static root (optional)
    root /var/www/html;
    index index.html index.htm;

    location / {
        try_files \$uri \$uri/ @app;
    }

    location @app {
        proxy_pass http://127.0.0.1:$UPSTREAM_PORT/;
        proxy_http_version 1.1;
        client_max_body_size 20m;
        proxy_buffering off;
        proxy_set_header Cache-Control "no-cache";
        proxy_set_header X-Forwarded-Host \$host;
        proxy_set_header X-Forwarded-Port \$server_port;
        proxy_set_header X-Forwarded-Server \$host;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection \$connection_upgrade;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_connect_timeout 5s;
        proxy_read_timeout 60s;
        proxy_send_timeout 60s;
    }
}
EOF
  nginx -t
  systemctl enable --now nginx
  systemctl reload nginx
  success "Nginx reverse proxy configured (server_name=$SERVER_NAME upstream=$UPSTREAM_PORT)"
}

# -------------------------- Main --------------------------------------------
main() {
  log "Starting VM Zero-to-Deploy setup..."
  parse_args "$@"
  check_os
  require_root

  # System Preparation
  update_system
  install_build_tools
  install_python
  install_nodejs
  install_docker
  install_terraform
  configure_docker_daemon
  
  # Development Tools
  install_neovim
  install_github_cli
  install_additional_tools
  install_git_lfs

  # Security & Authentication
  ensure_ssh_key_and_known_hosts
  setup_github_auth
  upload_ssh_key_to_github
  smoke_test_github_ssh
  setup_firewall
  
  # Project Setup
  clone_repository
  setup_deployment_env
  setup_cicd_secrets
  test_deployment_pipeline
  
  # Monitoring & Logging
  setup_monitoring
  limit_journald
  setup_timesyncd
  
  # Optional Enhancements
  setup_shell_customization
  install_database_clients
  setup_reverse_proxy
  
  # Security Hardening
  setup_unattended_upgrades
  setup_fail2ban
  setup_swap_if_missing
  if [[ "$SSH_HARDEN" -eq 1 ]]; then
    ssh_hardening
  else
    log "SSH hardening disabled (use --ssh-hardening to enable)"
  fi
  
  success "Setup completed. Repository: $PROJECT_DIR/${REPO##*/}"
  warn "If this is your first run, log out and back in so docker group membership applies to $TARGET_USER."
  if [[ "$SERVER_NAME" == "_" ]]; then
    ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
    log "Next steps: configure .env, start your app on port $UPSTREAM_PORT, and verify via http://${ip:-<your-ip>}/"
  else
    log "Next steps: configure .env, start your app on port $UPSTREAM_PORT, and verify via http://${SERVER_NAME}/"
  fi

  # Optional: free some space from package caches
  apt-get autoremove -y >/dev/null 2>&1 || true
  apt-get clean >/dev/null 2>&1 || true
}

main "$@"

