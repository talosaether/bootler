#!/usr/bin/env bash
# ============================================================================
# bootler.sh — Harden and configure a fresh Ubuntu VM for application deployment
# ============================================================================
# Usage:
#   sudo ./bootler.sh \
#     [--project-dir /opt/project] \
#     [--server-name example.com] \
#     [--upstream-port 8000]
#
# Environment (optional):
#   SSH_KEY_EMAIL      Email comment for generated SSH key
#
# Notes:
# - Script is idempotent where reasonable and safe to re-run.
# - Installs Docker, Python, Node (via nvm), Terraform, and common tools.
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
PROJECT_DIR="/opt/project"
SERVER_NAME="_"           # Use a real hostname or domain for TLS later
UPSTREAM_PORT="8000"       # Upstream app port for reverse proxy
SSH_KEY_EMAIL="${SSH_KEY_EMAIL:-dev@example.com}"
OPEN_DEV_PORTS=0           # Only open 3000/8000 if explicitly requested
SSH_PORT=22                # SSH port for UFW allow (override with --ssh-port)
SSH_HARDEN=0               # Optional: disable SSH password auth
SWAP_MB=0                  # Optional: create swapfile of N MB if none
F2B_TRUSTED_IPS="${F2B_TRUSTED_IPS:-}"  # Optional: fail2ban whitelist (space-separated)

# Neovim & Dotfiles Configuration
NVIM_VERSION="${NVIM_VERSION:-0.10.2}"           # Neovim version to install
NVIM_INSTALL_METHOD="${NVIM_INSTALL_METHOD:-appimage}"  # Installation method: appimage
DOTFILES_REPO="${DOTFILES_REPO:-}"               # Optional: dotfiles repository URL
DOTFILES_METHOD="${DOTFILES_METHOD:-stow}"       # Dotfiles method: stow or copy
DOTFILES_PACKAGES="${DOTFILES_PACKAGES:-}"       # Space-separated list of packages for stow
DOTFILES_REF="${DOTFILES_REF:-}"                 # Optional: git reference (branch/tag)
DOTFILES_STOW_FLAGS="${DOTFILES_STOW_FLAGS:-}"   # Additional flags for stow

# TMUX Configuration
TMUX_PLUGIN_MANAGER_PATH="${TMUX_PLUGIN_MANAGER_PATH:-$HOME/.tmux/plugins}"  # TPM path
TMUX_INSTALL_TPM="${TMUX_INSTALL_TPM:-1}"                                    # Install TPM by default

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
      --project-dir) PROJECT_DIR="$2"; shift 2;;
      --server-name) SERVER_NAME="$2"; shift 2;;
      --upstream-port) UPSTREAM_PORT="$2"; shift 2;;
      --ssh-port)    SSH_PORT="$2"; shift 2;;
      --open-dev-ports) OPEN_DEV_PORTS=1; shift 1;;
      --ssh-hardening) SSH_HARDEN=1; shift 1;;
      --swap-mb)     SWAP_MB="$2"; shift 2;;
      --fail2ban-trusted) F2B_TRUSTED_IPS="$2"; shift 2;;
      -h|--help)
        cat <<USAGE
Usage: sudo ./bootler.sh [options]
  --project-dir DIR       Project directory (default: /opt/project)
  --server-name NAME      Public hostname or domain for reverse proxy (default: _)
  --upstream-port N       Upstream app port (default: 8000)
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
  apt_install build-essential curl wget git ca-certificates unzip gnupg lsb-release jq yq tree vim nano openssh-client ufw tmux
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

# -------------------------- Dotfiles Helpers and Functions --------------
clone_update_repo() {
  local url="$1" dest="$2" ref="${3:-}"
  if [[ -d "$dest/.git" ]]; then
    git -C "$dest" fetch --tags --prune origin || true
    if [[ -n "$ref" ]]; then
      git -C "$dest" checkout -q "$ref" || true
      git -C "$dest" pull --ff-only || true
    else
      git -C "$dest" checkout -q "$(git -C "$dest" symbolic-ref --short HEAD 2>/dev/null || echo main)" || true
      git -C "$dest" pull --ff-only || true
    fi
  else
    if [[ -n "$ref" ]]; then
      git clone --depth 1 --branch "$ref" "$url" "$dest" || git clone "$url" "$dest"
    else
      git clone --depth 1 "$url" "$dest" || git clone "$url" "$dest"
    fi
  fi
}

setup_dotfiles() {
  if [[ -z "${DOTFILES_REPO:-}" ]]; then
    warn "No dotfiles repository specified; skipping dotfiles setup"
    return 0
  fi

  log "Setting up dotfiles from ${DOTFILES_REPO}${DOTFILES_REF:+ (ref $DOTFILES_REF)}"
  
  local dots_dir="$TARGET_HOME/.dotfiles"
  clone_update_repo "${DOTFILES_REPO}" "${dots_dir}" "${DOTFILES_REF:-}"
  chown -R "$TARGET_USER:$TARGET_USER" "${dots_dir}"
  
  local method="${DOTFILES_METHOD:-stow}"
  
  if [[ "${method}" == "stow" ]]; then
    if ! command -v stow >/dev/null 2>&1; then
      warn "stow not found; installing stow"
      apt_install stow
    fi
    
    if ! command -v stow >/dev/null 2>&1; then
      warn "stow installation failed; falling back to copy method"
      method="copy"
    fi
  fi

  if [[ "${method}" == "stow" && -n "${DOTFILES_PACKAGES:-}" ]]; then
    log "Using stow method for dotfiles packages: ${DOTFILES_PACKAGES} (with destructive overwrite)"
    run_as "cd '${dots_dir}' && for pkg in ${DOTFILES_PACKAGES}; do [[ -d \"\$pkg\" ]] || continue; echo '[*] stow \$pkg'; stow --restow ${DOTFILES_STOW_FLAGS:-} -t '${TARGET_HOME}' \"\$pkg\"; done"
  elif [[ "${method}" == "copy" ]]; then
    log "Using copy method for dotfiles (with destructive overwrite)"
    run_as "cp -rf '${dots_dir}/.' '${TARGET_HOME}/'" || true
  else
    warn "No dotfiles packages specified for stow method; skipping dotfiles application"
  fi
  
  success "Dotfiles setup completed"
}

# -------------------------- Development Tools -------------------------------
install_neovim() {
  log "Installing Neovim v${NVIM_VERSION} via ${NVIM_INSTALL_METHOD}..."
  
  # Check if already installed with correct version
  if command -v nvim >/dev/null 2>&1; then
    if nvim --version | head -n1 | grep -q "NVIM v${NVIM_VERSION}"; then
      warn "Neovim v${NVIM_VERSION} already installed; skipping"
      return 0
    else
      warn "Different Neovim version detected: $(nvim --version | head -n1)"
      log "Proceeding with v${NVIM_VERSION} installation"
    fi
  fi
  
  if [[ "${NVIM_INSTALL_METHOD}" == "appimage" ]]; then
    # Install via AppImage (x86_64 only)
    if [[ "$(uname -m)" != "x86_64" ]]; then
      error "AppImage method only supports x86_64 architecture. Current: $(uname -m)"
      warn "Falling back to package manager installation"
      apt_install neovim
      success "Neovim installed via package manager"
      return 0
    fi
    
    log "Downloading Neovim AppImage v${NVIM_VERSION}..."
    curl_retry -o /tmp/nvim.appimage \
      "https://github.com/neovim/neovim/releases/download/v${NVIM_VERSION}/nvim.appimage"
    
    chmod +x /tmp/nvim.appimage
    
    log "Extracting AppImage..."
    cd /tmp && /tmp/nvim.appimage --appimage-extract >/dev/null
    
    # Move to opt and create symlink
    mv squashfs-root "/opt/nvim-v${NVIM_VERSION}"
    ln -sf "/opt/nvim-v${NVIM_VERSION}/usr/bin/nvim" /usr/local/bin/nvim
    
    # Clean up
    rm -f /tmp/nvim.appimage
    
    # Verify installation
    if nvim --version | head -n1 | grep -q "NVIM v${NVIM_VERSION}"; then
      success "Neovim v${NVIM_VERSION} installed via AppImage"
    else
      error "Neovim installation verification failed"
      exit 1
    fi
  else
    error "Unsupported NVIM_INSTALL_METHOD: ${NVIM_INSTALL_METHOD}"
    warn "Falling back to package manager installation"
    apt_install neovim
    success "Neovim installed via package manager"
  fi
  
  # Install minimal config (will be overwritten by dotfiles if present)
  install -d -m 700 "$TARGET_HOME/.config"
  chown -R "$TARGET_USER:$TARGET_USER" "$TARGET_HOME/.config"
  
  log "Installing minimal Neovim configuration"
  run_as "mkdir -p ~/.config/nvim"
  run_as "cat > ~/.config/nvim/init.lua" <<'NVIM'
vim.o.number = true
vim.o.relativenumber = true
vim.o.termguicolors = true
vim.o.expandtab = true
vim.o.shiftwidth = 2
vim.o.tabstop = 2
NVIM
  success "Minimal Neovim configuration installed"
}

install_tmux() {
  log "Setting up TMUX with TPM..."
  
  # Ensure tmux is installed (should be from build tools)
  if ! command -v tmux >/dev/null 2>&1; then
    warn "TMUX not found; installing via apt"
    apt_install tmux
  fi
  
  # Set up TMUX plugin manager path for target user
  local tmux_plugin_path="$TARGET_HOME/.tmux/plugins"
  
  if [[ "${TMUX_INSTALL_TPM}" -eq 1 ]]; then
    log "Installing TMUX Plugin Manager (TPM)..."
    run_as "mkdir -p '${tmux_plugin_path}'"
    
    if [[ ! -x "${tmux_plugin_path}/tpm/tpm" ]]; then
      run_as "git clone --depth 1 https://github.com/tmux-plugins/tpm '${tmux_plugin_path}/tpm'" || true
      success "TPM installed at ${tmux_plugin_path}/tpm"
    else
      warn "TPM already installed; skipping"
    fi
  fi
  
  success "TMUX setup completed (TPM installed, configuration will be provided by dotfiles)"
}

# Install minimal tmux config as fallback if dotfiles don't provide one
install_tmux_fallback_config() {
  # Only install fallback if no tmux config exists and no dotfiles repo is configured
  if [[ -z "${DOTFILES_REPO:-}" ]] && [[ ! -f "$TARGET_HOME/.tmux.conf" ]] && [[ ! -f "$TARGET_HOME/.config/tmux/tmux.conf" ]]; then
    log "Installing minimal TMUX fallback configuration (no dotfiles configured)"
    run_as "mkdir -p ~/.config/tmux"
    run_as "cat > ~/.config/tmux/tmux.conf" <<'TMUX'
# Basic settings
set -g mouse on
set -g history-limit 10000
set -g base-index 1
set -g pane-base-index 1
set -g renumber-windows on

# Vim-like pane navigation
bind -n C-h select-pane -L
bind -n C-j select-pane -D
bind -n C-k select-pane -U
bind -n C-l select-pane -R

# Environment variables to preserve
set -g update-environment "SSH_AUTH_SOCK SSH_AGENT_PID SSH_CONNECTION SSH_CLIENT USER HOME PATH"

# TPM plugins (if TPM is installed)
set -g @plugin 'tmux-plugins/tpm'
set -g @plugin 'tmux-plugins/tmux-sensible'

# Initialize TMUX plugin manager (keep this line at the very bottom of tmux.conf)
run '~/.tmux/plugins/tpm/tpm'
TMUX
    # Create symlink for backward compatibility
    run_as "ln -sf ~/.config/tmux/tmux.conf ~/.tmux.conf"
    success "Minimal TMUX fallback configuration installed"
  else
    log "TMUX configuration exists or will be provided by dotfiles; skipping fallback"
  fi
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



install_git_lfs() {
  log "Installing Git LFS..."
  apt_install git-lfs || true
  run_as "git lfs install --skip-repo" || true
  success "Git LFS installed"
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
setup_project_directory() {
  log "Setting up project directory..."
  install -d -o "$TARGET_USER" -g "$TARGET_USER" -m 750 "$PROJECT_DIR"
  # Create project bin directory for user scripts
  install -d -o "$TARGET_USER" -g "$TARGET_USER" -m 750 "$PROJECT_DIR/bin"
  success "Project directory ready at $PROJECT_DIR"
}



# -------------------------- Build & Verify ----------------------------------

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
        proxy_pass http://127.0.0.1:$UPSTREAM_PORT;
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
  install_tmux
  setup_dotfiles
  install_tmux_fallback_config
  install_additional_tools
  install_git_lfs

  # Security & Authentication
  ensure_ssh_key_and_known_hosts
  setup_firewall
  
  # Project Setup
  setup_project_directory
  
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
  
  success "Setup completed. Project directory: $PROJECT_DIR"
  warn "If this is your first run, log out and back in so docker group membership applies to $TARGET_USER."
  if [[ "$SERVER_NAME" == "_" ]]; then
    # Cross-platform IP detection
    if command -v hostname >/dev/null 2>&1 && hostname -I >/dev/null 2>&1; then
      ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
    elif command -v ip >/dev/null 2>&1; then
      ip="$(ip route get 1.1.1.1 2>/dev/null | awk '{print $7; exit}')"
    else
      ip="<your-ip>"
    fi
    log "Next steps: deploy your application to port $UPSTREAM_PORT and verify via http://${ip}/"
  else
    log "Next steps: deploy your application to port $UPSTREAM_PORT and verify via http://${SERVER_NAME}/"
  fi

  # Optional: free some space from package caches
  apt-get autoremove -y >/dev/null 2>&1 || true
  apt-get clean >/dev/null 2>&1 || true
}

main "$@"
