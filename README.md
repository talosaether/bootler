# Bootler

_The one-command **Linux VM hardening script** that transforms a fresh Ubuntu VM into a secure, production-ready host._  
It installs the common development stack (Docker, Node, Python, Terraform, nginx), hardens the system (UFW, fail2ban, unattended security upgrades), sets up monitoring and logging, and prepares the environment for application deployment.

> Script filename in this repo: **`bootler.sh`**

---

## ✨ What Bootler does

- Updates and primes Ubuntu (22.04/24.04 LTS friendly)
- Installs: **Docker** (+ compose plugin, log rotation), **Node LTS** (via nvm + pnpm), **Python 3** (+ pipx), **Terraform**, **Neovim** (pinned version via AppImage + minimal config), **Git LFS**, DB clients
- Security: **UFW** (with sane defaults), **fail2ban** for SSH, **unattended-upgrades**, optional **SSH password disable**, optional **swapfile**
- SSH: generates **SSH key** for secure access
- Observability/hygiene: **journald** size caps, **logrotate** for app logs, **systemd-timesyncd**
- Environment: creates **project directory** structure with proper permissions
- Dotfiles: optional **dotfiles repository cloning** with stow or copy methods
- Reverse proxy: configures **nginx** to forward to your app on a configurable upstream port (WebSocket-safe)

---

## 🚀 Getting started

### 1) Prereqs
- Fresh Ubuntu server (22.04/24.04) with sudo/root

### 2) Run it

```bash
# clone the Bootler repo
git clone git@github.com:<you>/bootler.git
cd bootler
chmod +x bootler.sh

# minimally:
sudo ./bootler.sh

# typical:
sudo ./bootler.sh \
  --server-name example.com \
  --project-dir /opt/project \
  --upstream-port 8000 \
  --ssh-hardening \
  --swap-mb 2048 \
  --fail2ban-trusted "203.0.113.4 2001:db8::/32"
```

When it finishes, Bootler will print the "next steps" and a URL to test:
- If you used `--server-name example.com`: `http://example.com/`
- If you left the default `_`: `http://<server-ip>/`

> **Note:** After the first run, log out/in so your user picks up the `docker` group membership.

---

## 🧰 Parameters reference

### CLI flags

| Flag | Type | Default | What it does |
|---|---:|---|---|
| `--project-dir` | path | `/opt/project` | Where your application and `logs/` will live. Bootler also creates `/opt/project/bin` for your scripts. |
| `--server-name` | hostname | `_` | nginx `server_name`. Use `_` for "any host" (handy for first boot or IP-only). |
| `--upstream-port` | int | `8000` | Port your app listens on locally; nginx proxies to `127.0.0.1:<port>`. |
| `--ssh-port` | int | `22` | Port to allow in UFW and configure in fail2ban. |
| `--open-dev-ports` | flag | _off_ | Also open TCP **3000** and **8000** in UFW (development convenience). |
| `--ssh-hardening` | flag | _off_ | Disables password auth in SSHD (requires an existing public key). |
| `--swap-mb` | int | `0` | Creates a swapfile of N MB if no swap is present (e.g., `--swap-mb 2048`). |
| `--fail2ban-trusted` | quoted string | _(empty)_ | Space-separated IPs/CIDRs whitelisted in fail2ban `ignoreip` (e.g., `"1.2.3.4 2001:db8::/32"`). |

### Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `SSH_KEY_EMAIL` | `dev@example.com` | Comment for the generated `~/.ssh/id_ed25519` key. |
| `F2B_TRUSTED_IPS` | _(unset)_ | Alternative to the `--fail2ban-trusted` flag. |
| `DEBUG` | `0` | Set to `1` to enable `set -x` shell tracing for verbose logs. |
| `NVIM_VERSION` | `0.10.2` | Neovim version to install via AppImage. |
| `NVIM_INSTALL_METHOD` | `appimage` | Installation method for Neovim (currently only `appimage`). |
| `DOTFILES_REPO` | _(unset)_ | Optional URL of dotfiles repository to clone and apply. |
| `DOTFILES_METHOD` | `stow` | Method to apply dotfiles: `stow` (symlinks) or `copy` (direct copy). |
| `DOTFILES_PACKAGES` | _(unset)_ | Space-separated list of packages for stow method. |
| `DOTFILES_REF` | _(unset)_ | Optional git reference (branch/tag) for dotfiles repo. |
| `DOTFILES_STOW_FLAGS` | _(unset)_ | Additional flags to pass to stow command. |

---

## 🧩 High-level function overview

Bootler is organized into small, idempotent functions you can skim or run independently if you ever need to.

### System prep
- `require_root()` – Exits unless running with root privileges.
- `check_os()` – Ensures the host is Ubuntu.
- `update_system()` – `apt update` + `full-upgrade` with safe retries.
- `install_build_tools()` – Installs base packages (curl, git, jq, yq, vim, …).

### Runtimes & tooling
- `install_python()` – Installs Python 3, venv, pipx; symlinks `python` → `python3`.
- `install_nodejs()` – Installs Node LTS via **nvm** for the target user; enables **corepack** + **pnpm**.
- `install_docker()` – Installs Docker Engine + compose plugin; enables service; adds user to `docker` group.
- `install_terraform()` – Installs HashiCorp Terraform from official apt repo.
- `install_neovim()` – Installs Neovim via AppImage (pinned version) with minimal configuration.
- `setup_dotfiles()` – Clones and applies dotfiles repository using stow or copy method.
- `install_git_lfs()` – Installs Git LFS and runs `git lfs install`.
- `install_database_clients()` – Installs Postgres + MySQL/MariaDB client tools.

### Security, auth & network
- `ensure_ssh_key_and_known_hosts()` – Creates `~/.ssh/id_ed25519` if missing; pins `github.com` host key.
- `setup_firewall()` – Enables UFW (IPv4/IPv6), allows 80/443 and your SSH port, optional dev ports, rate-limits SSH, turns on low-noise logging.
- `setup_unattended_upgrades()` – Enables security auto-updates (with Ubuntu Pro ESM detection if attached).
- `setup_fail2ban()` – Sets sane SSH bans (systemd backend), honors your trusted IPs, matches your `--ssh-port`.
- `ssh_hardening()` – (Optional) Disables SSH password auth via `sshd_config.d/99-hardening.conf` and reloads sshd.

### Project setup
- `setup_project_directory()` – Creates `PROJECT_DIR` with proper permissions and structure.

### Observability & hygiene
- `setup_monitoring()` – Installs htop/iotop; ensures `${PROJECT_DIR}/logs`; adds logrotate policy for `logs/*.log`.
- `limit_journald()` – Caps systemd-journal to 200MB (20MB per file) and 7-day retention.
- `setup_timesyncd()` – Ensures `systemd-timesyncd` is enabled (time sync).
- `configure_docker_daemon()` – Writes `/etc/docker/daemon.json` with json-file rotation and `live-restore`.
- `setup_reverse_proxy()` – Installs nginx; sets a default site that proxies `/` to `127.0.0.1:$UPSTREAM_PORT` with WebSocket upgrade support and forwarded headers.
- `setup_swap_if_missing()` – Creates and enables a swapfile if `--swap-mb` > 0 and the system has no swap.

---

## 📦 What gets installed & configured (at a glance)

- **Paths & files**
  - `${PROJECT_DIR}/` (project directory with proper permissions)
  - `${PROJECT_DIR}/logs/` (logrotate-managed)
  - `${PROJECT_DIR}/bin/` (on `PATH` via .bashrc snippet)
  - `/etc/logrotate.d/project`
  - `/etc/systemd/journald.conf.d/limits.conf`
  - `/etc/docker/daemon.json`
  - `/etc/nginx/conf.d/upgrade_map.conf`, `/etc/nginx/sites-available/default`
  - `/etc/fail2ban/jail.local`
  - `/etc/apt/apt.conf.d/50unattended-upgrades`, `/etc/apt/apt.conf.d/20auto-upgrades`
  - `/etc/ssh/sshd_config.d/99-hardening.conf` _(only with `--ssh-hardening`)_
  - `/swapfile` _(only with `--swap-mb`)_

- **Firewall**
  - Default deny inbound; allow outbound
  - Allow TCP **80/443** + your **SSH port**
  - Optional allow **3000/8000** (`--open-dev-ports`)
  - SSH rate-limit enabled

- **nginx**
  - `server_name` from `--server-name` (or `_`)
  - Proxies to `http://127.0.0.1:$UPSTREAM_PORT/`
  - Websocket upgrade headers
  - Forwarded `X-Forwarded-*` headers

---

## 🧪 Verifying your app

1. Start your app to listen on the chosen upstream port (default **8000**) on **127.0.0.1**.
2. Hit the server in a browser:
   - With a hostname: `http://example.com/`
   - Without one: `http://<server-ip>/`
3. Check logs if needed:
   - Your app logs: `${PROJECT_DIR}/logs/*.log` (rotated daily)
   - nginx: `journalctl -u nginx --no-pager | tail -n 200`
   - UFW: `sudo ufw status verbose`
   - fail2ban: `sudo fail2ban-client status sshd`

---

## 🛡️ Idempotency & safety

- The script is designed to be **safe to re-run**; it checks for existing keys, existing config files, and won’t clobber customized files like `/etc/docker/daemon.json` if they already exist.
- Network operations use a retry wrapper for flaky mirrors.
- `set -Eeuo pipefail` and an error trap show the failing command + line for easier debugging.
- `DEBUG=1` enables shell tracing during a run.

---

## 🧯 Troubleshooting

- **Docker commands require sudo?** Log out/in or `newgrp docker` to refresh your group membership.
- **nginx shows 502**: ensure your app is listening on `127.0.0.1:$UPSTREAM_PORT`. Try `curl -i 127.0.0.1:8000`.
- **Port conflicts**: change `--upstream-port` or stop the process already listening on that port.
- **SSH hardening**: only enable `--ssh-hardening` if you have a working public key on the server.
- **UFW lockout fear**: Bootler always allows your SSH port and enables UFW last; if you changed the SSH port manually, re-run with `--ssh-port <port>`.

---

## 📜 Example invocations

**Production-ish:**

```bash
sudo ./bootler.sh \
  --server-name app.acme.com \
  --upstream-port 8080 \
  --ssh-port 22 \
  --ssh-hardening \
  --swap-mb 4096 \
  --fail2ban-trusted "198.51.100.10 2001:db8::/48"
```

**Dev box with open ports:**

```bash
sudo ./bootler.sh \
  --open-dev-ports \
  --server-name _
```

**With dotfiles setup:**

```bash
sudo DOTFILES_REPO="https://github.com/username/dotfiles.git" \
     DOTFILES_PACKAGES="nvim zsh git" \
     ./bootler.sh \
  --server-name example.com \
  --upstream-port 3000
```

---

## 📄 License

MIT — do what you want, be excellent to each other.

---

## ❤️ Credits

Built as a **Linux VM hardening script** for getting from zero-to-secure on a clean Ubuntu host with sensible defaults and minimal fuss.

