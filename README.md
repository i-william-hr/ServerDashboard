# 🖥️ ServerDashboard

### Simple Web Interface to Monitor Your Linux Servers via SSH

ServerDashboard is a lightweight Python web app that provides a clean and mobile-friendly interface to monitor Linux servers and their services — using only SSH and a few basic system packages.  

- Data updates automatically every **300 seconds** (via SSH).  
- The web interface refreshes every **120 seconds**.  
- Designed for both **desktop** and **mobile** (iPhone / Android with high-resolution screens).  
- Tested as `root` in `screen`, but can run (not install) under any user with access to SSH keys and ports >1024.  

---

## ⚙️ Automatic Installation (Recommended)

Run this on your master node:

```bash
wget https://raw.githubusercontent.com/i-william-hr/ServerDashboard/refs/heads/main/server_status.py
python3 server_status.py --install-master
```

Then follow the steps:

1. Copy your SSH key to all slave servers manually (as prompted).
2. Add slaves to `servers.json`.
3. Run:
   ```bash
   python3 server_status.py --install-slaves
   ```
4. Adjust the `.env` file if necessary.  
   No manual script edits are required.

> If **no user/password** or **token** is set in `.env` or environment variables, **public access** will be enabled.

---

## 🛠️ Manual Installation

1. **Clone the repository**  
   Copy this repo or just the `.py` and `.json` files.

2. **Master requirements**  
   ```bash
   apt update && apt install -y python3-venv python3-pip openssh-client    python3-paramiko python3-flask-httpauth python3-waitress
   ```
   If some Python packages fail to install globally, create a virtual environment (see comments in the `.py` file).

3. **Slave requirements**  
   ```bash
   apt update
   apt install -y virt-what net-tools netcat-openbsd openssl
   apt install -y mysql-client || apt install -y mariadb-client-compat
   ```
   > One of the MySQL client packages may fail depending on distro — that’s expected.

4. **Configuration options**  
   Choose one of:
   - **Option 1:** Use `.env` file (recommended).  
   - **Option 2:** Use environment variables.  
   - **Option 3:** Hardcode settings in the script.

   Priority order: **ENV vars → `.env` → script defaults**

5. **SSH setup**  
   Generate a key and deploy it to slaves:
   ```bash
   ssh-keygen
   ```
   Default private key path: `/root/.ssh/id_ed25519` (for `ssh-keygen` without args).

6. **Authentication behavior**
   - If `.env` or ENV vars define `USER`/`PASSWORD`, password auth is used.
   - If `SECRET_TOKEN` is set, **token-based auth** is used.
   - If nothing is configured, dashboard defaults to **public access**.
   - If no `.env` and no ENV vars exist, **hardcoded fallback credentials** apply.

---

## ➕ Add Servers Interactively

You can now add servers easily using the new `--add-server` option:

```bash
python3 server_status.py --add-server
```

This interactive command:
- Prompts you for the server name, IP/hostname, SSH user, and country code. Only name and IP/hostname are mandatory if SSH runs on port 22.
- Adds the new entry automatically to your `servers.json`.
- Optionally offers to **copy your public SSH key** to the new server for passwordless access.

---

## ▶️ Startup

Run the server (ideally inside `screen` or `tmux`):

```bash
python3 server_status.py --start
```

The app will display:
- The dashboard URL  
- The authentication method used (password or token)

If token authentication is enabled, the token will appear directly in the URL.

---

## 📊 Features

**System Overview**
- Ping latency
- Uptime
- Load average (with color-coded status)
- Host type (VM/Dedicated + VM type)
- Pending apt updates
- Network In/Out traffic (Mbit)
- OS version and kernel version
- CPU model, cores, and frequency
- Memory usage (with visual bar and color indicator)
- Disk usage (with visual bar)
- Top 5 processes by **CPU%** and **Memory% / MB**
- Logged-in users with IP or terminal info

**Service Monitoring**
- Auto-detects running services and ports:
  - Nginx  
  - MySQL / MariaDB  
  - ZNC  
  - SSH  
  - Python web apps (e.g. AppleHealthDashboard)
- Displays all configured **Nginx domains**, ports, and **SSL validity**
- Lists all **reverse proxies** and their backend targets

---

### 🧩 Notes

- Designed for Debian/Ubuntu systems.
- Master ideally should be Ubuntu 24 or Debian 12+.
- Works with any SSH-accessible Linux host.
- Minimal dependencies and no agents required.
