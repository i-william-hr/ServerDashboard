"""
Server Status - single-file Flask webapp (sample tailored)

What it does
- Runs on the Waitress production WSGI server.
- Binds to all IPs by default, for security reasons change to 127.0.0.1 and use a reverse proxy like Nginx.
- Protects the web UI with two methods:
  1. HTTP Basic Authentication (user: user, pass: pass).
  2. A secret token in the URL (e.g., ?auth=YOUR_TOKEN) for easy access from bookmarks.
- Includes a demo mode (?demo) to obfuscate sensitive server names and IPs for screenshots.
- pings each server and shows latency (ms).
- connects via SSH to collect: Server Type, OS, Kernel, uptime, load, CPU, RAM, disk, network usage, top processes, users, updates, service status, and Nginx configuration details.
- Automatically creates a daily cron job on remote hosts to check for updates.
- Displays usage bars and threshold-based colors (green/yellow/red) for key metrics.
- Caches results for 10 minutes (override via CACHE_TTL).
- Dark UI, shows country flags via 2‑letter ISO code, displays a favicon, and has a refresh countdown timer.
- manual Purge/Refresh button.

Install on the dashboard host (Debian/Ubuntu):
  Use the built-in installer: "sudo python3 server.py --install-master"
  Alternatively, manually install:
  sudo apt update && sudo apt install -y openssh-client python3 python3-venv python3-pip python3-paramiko python3-flask-httpauth python3-waitress

Install on ALL REMOTE servers:
  Use the built-in installer: "sudo python3 server.py --install-slaves"
  Alternatively, manually install:
  sudo apt update && sudo apt install -y virt-what; sudo apt install -y net-tools; sudo apt install -y netcat-openbsd; sudo apt install -y openssl; sudo apt install -y mysql-client; sudo apt install -y mariadb-client-compat

Run:
  python3 server.py --start

Env vars:
  SECRET_TOKEN (default token)
  SSH_KEY_PATH (default /root/.ssh/id_ed25519)
  CACHE_TTL (default 300)
  BIND_HOST (default 0.0.0.0)
  BIND_PORT (default 8889)

servers.json format:
  The only required fields are "name" and "host".
  If not provided, "user" defaults to "root" and "port" defaults to 22.
  The "country" field for the flag is optional.

"""

import sys
import subprocess
import json
import os
import time
import threading
import re
from functools import wraps
from typing import Union, Tuple
import urllib.request

# Lazy load flask and webserver components only when needed
try:
    from flask import Flask, jsonify, request, render_template_string, send_from_directory
    from flask_httpauth import HTTPBasicAuth
    from waitress import serve
    import paramiko
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False


# --- Main Configuration ---
def load_env_file():
    env = {}
    env_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env')
    if os.path.exists(env_file):
        with open(env_file, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                if '=' in line:
                    key, value = line.split('=', 1)
                    # Strip comments from the value
                    value = value.split('#', 1)[0].strip()
                    env[key.strip()] = value
    return env

ENV_CONFIG = load_env_file()

APP_DIR = os.path.dirname(os.path.abspath(__file__))
SERVERS_FILE = os.path.join(APP_DIR, 'servers.json')
SSH_KEY_PATH = ENV_CONFIG.get('SSH_KEY_PATH', os.environ.get('SSH_KEY_PATH', '/root/.ssh/id_ed25519'))
CACHE_TTL = int(ENV_CONFIG.get('CACHE_TTL', os.environ.get('CACHE_TTL', '300')))
SSH_CONNECT_TIMEOUT = 5
PING_COUNT = 1
SECRET_TOKEN = ENV_CONFIG.get('SECRET_TOKEN', os.environ.get('SECRET_TOKEN', 'token'))
BIND_HOST = ENV_CONFIG.get('BIND_HOST', os.environ.get('BIND_HOST', '0.0.0.0'))
BIND_PORT = int(ENV_CONFIG.get('BIND_PORT', os.environ.get('BIND_PORT', '8889')))
PANEL_USER = ENV_CONFIG.get('PANEL_USER', 'user')
PANEL_PASS = ENV_CONFIG.get('PANEL_PASS', 'pass')

_cache = {}
_cache_lock = threading.Lock()

if FLASK_AVAILABLE:
    app = Flask(__name__)
    auth = HTTPBasicAuth()
    app.config['TEMPLATES_AUTO_RELOAD'] = True

    # --- Authentication Setup ---
    # If PANEL_USER and PANEL_PASS are both empty, the users dict will be empty, allowing public access if the token is also disabled.
    users = {}
    if PANEL_USER and PANEL_PASS:
        users = {
            PANEL_USER: PANEL_PASS
        }

    @auth.verify_password
    def verify_password(username, password):
        if username in users and users.get(username) == password:
            return username

    def combined_auth_required(func):
        """Custom decorator to allow URL token OR Basic Auth."""
        @wraps(func)
        def decorated_view(*args, **kwargs):
            use_token_auth = SECRET_TOKEN and SECRET_TOKEN != "token"
            
            # 1. Check for token auth
            if use_token_auth and request.args.get('auth') == SECRET_TOKEN:
                return func(*args, **kwargs)
            
            # 2. Check for demo mode
            if 'demo' in request.args:
                return func(*args, **kwargs)
                
            # 3. Check if any user/pass auth is configured
            if not users:
                # No users configured, check if token auth is also disabled
                if not use_token_auth:
                    return func(*args, **kwargs) # Public access
                else:
                    # Token auth is the ONLY method, but no valid token was provided.
                    return ('Unauthorized: Access requires a valid token.', 403)
            
            # 4. Fall back to standard HTTP Basic Auth
            return auth.login_required(func)(*args, **kwargs)
        return decorated_view
# --------------------------


def load_servers():
    try:
        with open(SERVERS_FILE, 'r') as f:
            # Remove comments from JSON file before parsing
            content = ''.join(line for line in f if not line.strip().startswith('//'))
            return json.loads(content)
    except Exception:
        return []


def get_flag_emoji(cc: str) -> str:
    if not cc or len(cc) != 2:
        return ''
    base = 0x1F1E6
    return ''.join(chr(base + ord(c) - ord('A')) for c in cc.upper())


def ping_host(host: str) -> Tuple[bool, Union[float, None]]:
    """Pings a host and returns (is_online, latency_ms)."""
    try:
        res = subprocess.run(
            ['ping', '-c', str(PING_COUNT), '-W', '1', host],
            capture_output=True, text=True, check=False
        )
        if res.returncode == 0:
            match = re.search(r"time=([\d.]+)\s*ms", res.stdout)
            if match:
                return True, float(match.group(1))
            match = re.search(r"rtt min/avg/max/mdev = .*?/([\d.]+)/", res.stdout)
            if match:
                return True, float(match.group(1))
            return True, None
        return False, None
    except Exception:
        return False, None


def ssh_run_command(host, user, port, key_path, cmd):
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(hostname=host, port=port, username=user, key_filename=key_path, timeout=SSH_CONNECT_TIMEOUT)
        stdin, stdout, stderr = client.exec_command(cmd, timeout=30) # Increased timeout for service/nginx checks
        out = stdout.read().decode('utf-8', errors='ignore')
        err = stderr.read().decode('utf-8', errors='ignore')
        client.close()
        if err:
            return True, out + "\nERR:\n" + err
        return True, out
    except Exception as e:
        return False, str(e)


def gather_server(host, user, port, country, name):
    now = time.time()
    ping_ok, ping_ms = ping_host(host)
    data = {
        'name': name,
        'host': host,
        'country': country or '',
        'flag': get_flag_emoji(country) if country else '',
        'ping_ok': ping_ok,
        'ping_ms': ping_ms,
        'last_update': now,
        'ssh': None,
    }
    if not ping_ok:
        data['error'] = 'Ping failed'
        return data

    cmds = {
        'uptime': "uptime -p || uptime",
        'load': "awk '{print $1, $2, $3}' /proc/loadavg",
        'cpu_cores': 'nproc || echo 1',
        'mem': "free -b | awk 'NR==2{printf \"%s %s\", $2, $7}' || free -b",
        'disk': 'df -B1 --output=size,avail -x tmpfs -x devtmpfs / | tail -n1 || df -B1 /',
        'cpu_model': "cat /proc/cpuinfo | grep -m1 'model name' | cut -d ':' -f 2- | xargs",
        'cpu_mhz': "cat /proc/cpuinfo | grep -m1 'cpu MHz' | cut -d ':' -f 2- | xargs | cut -d '.' -f 1",
        'os': 'lsb_release -ds || cat /etc/os-release | grep PRETTY_NAME | cut -d\'=\' -f2 | tr -d \'"\' || cat /etc/issue.net',
        'kernel': 'uname -r',
        'top_procs_cpu': "ps -eo pcpu,user,args --sort=-pcpu | sed 1d | grep -vF 'ps -eo pcpu,user,args' | grep -vE 'sshd:|sshd-session:' | head -n 5",
        'top_procs_mem': "ps -eo pmem,rss,user,args --sort=-pmem | sed 1d | grep -vF 'ps -eo pmem,rss,user,args' | grep -vE 'sshd:|sshd-session:' | head -n 5",
        'logged_in_users': "who | grep -E 'tty|pts' || true",
        'net_stats': "IFACE=$(ip -4 route get 8.8.8.8 | awk '{print $5}' | head -n1); cat /proc/net/dev | grep \"${IFACE}:\" | awk '{print $2, $10}'; sleep 1; cat /proc/net/dev | grep \"${IFACE}:\" | awk '{print $2, $10}'",
        'virt_type': "virt-what 2>/dev/null | head -n1",
        'updates_check': """
CRON_FILE="/etc/cron.d/system-updates-check";
CRON_CONTENT="30 4 * * * root /usr/bin/apt update >/dev/null 2>&1 && /usr/bin/apt list --upgradable 2>/dev/null | grep -vc \\"Listing...\\" > /var/tmp/upgradable_packages.txt || true";
if ! grep -qF "$CRON_CONTENT" "$CRON_FILE" 2>/dev/null; then
    echo "$CRON_CONTENT" > "$CRON_FILE";
    chmod 644 "$CRON_FILE";
fi;
cat /var/tmp/upgradable_packages.txt 2>/dev/null || echo 0
""",
        'service_status': """
#!/bin/bash
echo "SERVICE_STATUS_START";
test_tcp_connection() {
    local address="$1"; local output_name="$2"; local is_config_check="${3:-false}";
    local port=$(echo "$address" | sed -E 's/.*:([0-9a-zA-Z]+)/\\1/');
    local host=$(echo "$address" | sed -E 's/^(.*):[0-9a-zA-Z]+$/\\1/');
    local binding_info="";
    if [[ "$host" == "127.0.0.1" || "$host" == "::1" ]]; then binding_info="localhost only";
    elif [[ "$host" == *":"* ]]; then binding_info="IPv6"; else binding_info="IPv4"; fi;
    local connect_host="localhost";
    if [ "$is_config_check" = true ]; then connect_host="127.0.0.1"; fi;
    local test_port="$port";
    case $port in http) test_port=80 ;; https) test_port=443 ;; esac;
    if nc -zvw1 "$connect_host" "$test_port" &>/dev/null; then echo "$output_name:$port:OK:$binding_info";
    else echo "$output_name:$port:FAILED:$binding_info"; fi;
};
test_ssh_connection() {
    local address="$1";
    local port=$(echo "$address" | sed -E 's/.*:([0-9a-zA-Z]+)/\\1/');
    local host=$(echo "$address" | sed -E 's/^(.*):[0-9a-zA-Z]+$/\\1/');
    local binding_info=""; local connect_host="localhost";
    if [[ "$host" == *":"* ]]; then binding_info="IPv6"; connect_host="::1"; else binding_info="IPv4"; connect_host="127.0.0.1"; fi;
    local test_port="$port"; [[ "$port" == "ssh" ]] && test_port=22;
    local ssh_output=$(ssh -n -p "$test_port" -o ConnectTimeout=2 -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "$connect_host" 'exit' 2>&1);
    local ssh_exit_code=$?;
    if [[ "$binding_info" == "IPv6" ]]; then
        if [[ "$ssh_output" == *"Cannot assign requested address"* || "$ssh_output" == *"Network is unreachable"* ]]; then
            return;
        fi;
    fi;
    if [ $ssh_exit_code -eq 0 ] || [[ "$ssh_output" == *"Permission denied"* ]]; then echo "SSH:$port:OK:$binding_info";
    else echo "SSH:$port:FAILED:$binding_info"; fi;
};
if command -v nginx >/dev/null 2>&1; then
    netstat_output=$(netstat -tlpn | grep 'nginx: master' || true);
    if [ -n "$netstat_output" ]; then echo "$netstat_output" | while read -r line; do test_tcp_connection "$(echo "$line" | awk '{print $4}')" "Nginx"; done; fi;
fi;
if command -v mysqld >/dev/null 2>&1 || command -v mariadbd >/dev/null 2>&1; then
    tcp_found=false; socket_found=false;
    netstat_output=$(netstat -tlpn | grep -E 'mysqld|mariadbd' || true);
    if [ -n "$netstat_output" ]; then tcp_found=true; echo "$netstat_output" | while read -r line; do test_tcp_connection "$(echo "$line" | awk '{print $4}')" "MySQL"; done; fi;
    config_files=("/etc/mysql/my.cnf" "/etc/mysql/mariadb.conf.d/50-server.cnf"); found_port_from_config=""; found_socket_from_config="";
    parse_mysql_configs() { for conf in "$@"; do if [ ! -f "$conf" ]; then continue; fi; local includedirs=$(grep -E '^\\s*!includedir' "$conf" | awk '{print $2}' || true); for dir in $includedirs; do if [ -d "$dir" ]; then parse_mysql_configs "$dir"/*.cnf; fi; done; local result=$(awk '/\\[mysqld\\]/{f=1;next} /\\[.*\\]/{f=0} f && /^(port|socket)/{print}' "$conf" | tail -n 1); if [[ "$result" == port* ]]; then found_port_from_config=$(echo "$result" | awk -F'=' '{print $2}' | xargs); elif [[ "$result" == socket* ]]; then found_socket_from_config=$(echo "$result" | awk -F'=' '{print $2}' | xargs); fi; done; };
    parse_mysql_configs "${config_files[@]}";
    if [ -n "$found_socket_from_config" ]; then socket_found=true; if [ -e "$found_socket_from_config" ]; then if mysqladmin --socket="$found_socket_from_config" ping &>/dev/null; then echo "MySQL_Socket:$found_socket_from_config:OK:"; else echo "MySQL_Socket:$found_socket_from_config:FAILED:"; fi; else echo "MySQL_Socket:$found_socket_from_config:FAILED:not found"; fi; fi;
    if [ "$tcp_found" = false ] && [ -n "$found_port_from_config" ]; then test_tcp_connection "127.0.0.1:$found_port_from_config" "MySQL" true; tcp_found=true; fi;
fi;
if command -v znc >/dev/null 2>&1; then
    netstat_output=$(netstat -tlpn | grep '/znc' || true);
    if [ -n "$netstat_output" ]; then echo "$netstat_output" | while read -r line; do test_tcp_connection "$(echo "$line" | awk '{print $4}')" "ZNC"; done; fi;
fi;
netstat_output=$(netstat -tlpn | grep 'sshd' || true);
if [ -n "$netstat_output" ]; then echo "$netstat_output" | while read -r line; do test_tcp_connection "$(echo "$line" | awk '{print $4}')" "SSH"; done; else
    sshd_port=22;
    if [ -f /etc/ssh/sshd_config ]; then local found_port=$(grep -E "^\\s*#?\\s*Port\\s+[0-9]+" /etc/ssh/sshd_config | tail -n 1 | sed 's/#//g' | awk '{print $2}' || true); if [ -n "$found_port" ]; then sshd_port="$found_port"; fi; fi;
    netstat_output=$(netstat -tlpn | grep -E ":${sshd_port}(\\s|$)" || true);
    if [ -z "$netstat_output" ]; then netstat_output=$(netstat -tlpn | grep -E ":22(\\s|$)|:ssh(\\s|$)" || true); fi;
    if [ -n "$netstat_output" ]; then echo "$netstat_output" | while read -r line; do test_ssh_connection "$(echo "$line" | awk '{print $4}')"; done; fi;
fi;
ps aux | grep 'python3.*\\.py' | grep -v 'grep' | while read -r line; do
    pid=$(echo "$line" | awk '{print $2}'); command=$(echo "$line" | awk '{ for(i=11; i<=NF; i++) printf "%s ", $i; print "" }'); script_name=$(echo "$command" | grep -oE '[^/ ]+\\.py' | head -1 | sed 's/\\.py$//');
    if [ -z "$pid" ] || [ -z "$script_name" ]; then continue; fi;
    netstat_output=$(netstat -tlpn | grep "$pid/" || true);
    if [ -z "$netstat_output" ]; then continue; fi;
    echo "$netstat_output" | while read -r net_line; do test_tcp_connection "$(echo "$net_line" | awk '{print $4}')" "$script_name"; done;
done;
echo "SERVICE_STATUS_END"
""",
        'nginx_config': """
#!/bin/bash
echo "NGINX_CONFIG_START";
get_all_configs() {
    local config_file="$1"; local parsed_files="$2";
    if [ ! -f "$config_file" ] || [[ "$parsed_files" == *"$config_file"* ]]; then return; fi;
    echo "$config_file"; parsed_files+=" $config_file";
    local includes=$(grep -E '^\\s*include' "$config_file" | sed -e 's/#.*//' -e 's/^\\s*include\\s*//' -e 's/;\\s*$//' || true);
    for inc in $includes; do for file in $inc; do get_all_configs "$file" "$parsed_files"; done; done;
};
if ! command -v nginx >/dev/null 2>&1 || ! command -v openssl >/dev/null 2>&1; then echo "NGINX_CONFIG_END"; exit 0; fi;
nginx_conf="/etc/nginx/nginx.conf";
all_config_files=$(get_all_configs "$nginx_conf" "" | tr ' ' '\\n' | sort -u | tr '\\n' ' ');
if [ -z "$all_config_files" ]; then echo "NGINX_CONFIG_END"; exit 0; fi;
parsed_data=$(cat $all_config_files | awk '
    function process_server_block() {
        if (server_name) {
            print "HOST|" server_name "|" ports "|" (has_ssl ? cert_path : "NO_SSL");
            print proxies_str;
        }
        server_name=""; ports=""; cert_path=""; has_ssl=0; proxies_str="";
    }
    {
        gsub(/#.*/, ""); gsub(/;/, "");
        if ($0 ~ /^\\s*server\\s*{/) { in_server = 1; brace_level = 1; next; }
        if (in_server) {
            brace_level += gsub(/{/, "{"); brace_level -= gsub(/}/, "}");
            if ($1 == "server_name") { server_name = $2; }
            if ($1 == "listen") { port = $2; sub(/\\[::\\]:/, "", port); protocol = ($0 ~ /\\[::\\]/ || $0 ~ /ipv6only=on/) ? "IPv6" : "IPv4"; ports = ports " " port "/" protocol; if ($0 ~ /ssl/) { has_ssl = 1; } }
            if ($1 == "ssl_certificate") { cert_path = $2; }
            if ($1 == "location") { current_location = $2; }
            if ($1 == "proxy_pass") { proxies_str = proxies_str "PROXY|" server_name "|" current_location "|" $2 "\\n"; }
            if (brace_level == 0) { process_server_block(); in_server = 0; }
        }
    }
');
echo "$parsed_data" | grep "^HOST|" | sort | while IFS='|' read -r type host port_list cert_path; do
    ssl_status="NO_SSL";
    if [ "$cert_path" != "NO_SSL" ]; then
        if [ -n "$cert_path" ] && [ -f "$cert_path" ]; then
            if exp_date=$(openssl x509 -in "$cert_path" -noout -enddate 2>/dev/null | cut -d= -f2); then
                if [ "$(date -d "$exp_date" +%s)" -gt "$(date +%s)" ]; then ssl_status="OK"; else ssl_status="Expired"; fi;
            else ssl_status="Invalid"; fi;
        else ssl_status="Not_Found"; fi;
    fi;
    echo "HOST:$host:$port_list:$ssl_status";
done;
echo "$parsed_data" | grep "^PROXY|" | sort | while IFS='|' read -r type host location target; do
    echo "PROXY:$host$location:$target";
done;
echo "NGINX_CONFIG_END";
"""
    }

    results = {}
    for k, cmd in cmds.items():
        ok, out = ssh_run_command(host, user, port, SSH_KEY_PATH, cmd)
        if not ok:
            data['error'] = f'SSH cmd failed: {out}'
            return data
        results[k] = out.strip()

    try:
        uptime = results.get('uptime', '')
        load_str = results.get('load', '0 0 0')
        load_parts = load_str.split()
        load_1m = float(load_parts[0]) if load_parts else 0.0
        cores = int(results.get('cpu_cores', '1').split()[0]) if results.get('cpu_cores') else 1

        mem_parts = results.get('mem','').split()
        mem_total = int(mem_parts[0]) if len(mem_parts) >= 1 else None
        mem_free = int(mem_parts[1]) if len(mem_parts) >= 2 else None
        mem_used = (mem_total - mem_free) if mem_total is not None and mem_free is not None else None
        mem_usage_percent = round((mem_used / mem_total) * 100, 1) if mem_total and mem_total > 0 else 0

        disk_parts = results.get('disk','').split()
        disk_total = int(disk_parts[0]) if len(disk_parts) >= 1 else None
        disk_free = int(disk_parts[1]) if len(disk_parts) >= 2 else None
        disk_used = (disk_total - disk_free) if disk_total is not None and disk_free is not None else None
        disk_usage_percent = round((disk_used / disk_total) * 100, 1) if disk_total and disk_total > 0 else 0
        
        net_rx_mbits, net_tx_mbits = 0.0, 0.0
        net_stats_lines = results.get('net_stats', '').splitlines()
        if len(net_stats_lines) == 2:
            start_stats = net_stats_lines[0].split()
            end_stats = net_stats_lines[1].split()
            if len(start_stats) == 2 and len(end_stats) == 2:
                rx_bytes_diff = int(end_stats[0]) - int(start_stats[0])
                tx_bytes_diff = int(end_stats[1]) - int(start_stats[1])
                net_rx_mbits = (rx_bytes_diff * 8) / 1000000
                net_tx_mbits = (tx_bytes_diff * 8) / 1000000

        virt_type_str = results.get('virt_type', '').strip()
        server_type = virt_type_str.capitalize() if virt_type_str else 'Physical'
        
        upgradable_packages_str = results.get('updates_check', '0').strip()
        upgradable_packages = int(upgradable_packages_str) if upgradable_packages_str.isdigit() else 0

        top_procs_mem_raw = results.get('top_procs_mem', '')
        formatted_procs_mem = []
        for line in top_procs_mem_raw.strip().splitlines():
            try:
                parts = line.strip().split(maxsplit=3)
                if len(parts) == 4:
                    pmem = parts[0]
                    rss_kb = int(parts[1])
                    rss_mb = round(rss_kb / 1024)
                    user = parts[2]
                    command = parts[3]
                    formatted_procs_mem.append(f" {pmem}% ({rss_mb}MB) {user} {command}")
                else: formatted_procs_mem.append(line)
            except (ValueError, IndexError): formatted_procs_mem.append(line)
        top_procs_mem = "\n".join(formatted_procs_mem)

        service_status_raw = results.get('service_status', '')
        service_status = []
        if "SERVICE_STATUS_START" in service_status_raw:
            service_status_block = service_status_raw.split("SERVICE_STATUS_START\n")[1].split("SERVICE_STATUS_END")[0]
            for line in service_status_block.strip().splitlines():
                parts = line.strip().split(':', 3)
                if len(parts) >= 3:
                    service_status.append({'name': parts[0], 'port': parts[1], 'status': parts[2], 'info': parts[3] if len(parts) > 3 else ''})
        
        nginx_config_raw = results.get('nginx_config', '')
        nginx_hosts = []
        nginx_proxies = []
        if "NGINX_CONFIG_START" in nginx_config_raw:
            config_block = nginx_config_raw.split("NGINX_CONFIG_START\n")[1].split("NGINX_CONFIG_END")[0]
            for line in config_block.strip().splitlines():
                if line.startswith("HOST:"):
                    parts = line.replace("HOST:", "").split(':', 2)
                    if len(parts) == 3:
                        nginx_hosts.append({'host': parts[0], 'details': parts[1], 'ssl_status': parts[2]})
                elif line.startswith("PROXY:"):
                    parts = line.replace("PROXY:", "").split(':', 1)
                    if len(parts) == 2:
                        nginx_proxies.append({'path': parts[0], 'target': parts[1]})

        cpu_model = results.get('cpu_model', '').strip()
        cpu_mhz = results.get('cpu_mhz', '').strip()
        os_info = results.get('os', '').strip()
        kernel_version = results.get('kernel', '').strip()
        top_procs_cpu = results.get('top_procs_cpu', '').strip()
        logged_in_users = results.get('logged_in_users', '').strip()

    except Exception:
        mem_total = mem_free = mem_used = disk_total = disk_free = disk_used = None
        mem_usage_percent = disk_usage_percent = 0; net_rx_mbits = net_tx_mbits = 0.0; upgradable_packages = 0
        cores = 1; load_1m = 0; load_str = "0 0 0"
        cpu_model = cpu_mhz = os_info = kernel_version = top_procs_cpu = top_procs_mem = logged_in_users = server_type = ''
        service_status = []; nginx_hosts = []; nginx_proxies = []

    data['ssh'] = {
        'uptime': uptime, 'load': load_str, 'load_1m': load_1m, 'cores': cores,
        'mem_total_bytes': mem_total, 'mem_free_bytes': mem_free, 'mem_used_bytes': mem_used, 'mem_usage_percent': mem_usage_percent,
        'disk_total_bytes': disk_total, 'disk_free_bytes': disk_free, 'disk_used_bytes': disk_used, 'disk_usage_percent': disk_usage_percent,
        'net_rx_mbits': net_rx_mbits, 'net_tx_mbits': net_tx_mbits, 'server_type': server_type, 'upgradable_packages': upgradable_packages,
        'cpu_model': cpu_model, 'cpu_mhz': cpu_mhz, 'os_info': os_info, 'kernel_version': kernel_version,
        'top_procs_cpu': top_procs_cpu, 'top_procs_mem': top_procs_mem, 'logged_in_users': logged_in_users, 'service_status': service_status,
        'nginx_hosts': nginx_hosts, 'nginx_proxies': nginx_proxies
    }
    return data


def get_cached_or_fetch(server):
    key = server['host']
    with _cache_lock:
        entry = _cache.get(key)
        if entry and (time.time() - entry['ts'] < CACHE_TTL):
            return entry['data'], entry['ts']
    
    # Get user and port from server dict with defaults
    user = server.get('user', 'root')
    port = server.get('port', 22)
    
    data = gather_server(server['host'], user, port, server.get('country',''), server.get('name', server['host']))
    with _cache_lock:
        _cache[key] = {'ts': time.time(), 'data': data}
    return data, _cache[key]['ts']

if FLASK_AVAILABLE:
    INDEX_HTML = '''
    <!doctype html>
    <html>
    <head>
    <meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Server Status</title>
    <link rel="icon" href="favicon.ico" type="image/x-icon">
    <link rel="icon" type="image/png" href="favicon.png">
    <style>
    :root{--bg:#0b0f14;--card:#0f1720;--muted:#9aa4b2;--accent:#66d9ef;--warn:#f5c542;}
    body{background:linear-gradient(180deg,#050607 0%, #0b0f14 100%);color:#e6eef6;font-family:Inter,ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,Helvetica Neue,Arial;margin:0;padding:16px}
    .header{display:flex;align-items:center;justify-content:space-between;margin-bottom:12px}
    .h1{font-size:20px}
    .controls{display:flex;align-items:center;gap:12px;}
    .controls button{background:none;border:1px solid var(--muted);color:var(--muted);padding:6px 10px;border-radius:8px;}
    .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:12px}
    .card{background:var(--card);padding:14px;border-radius:10px;box-shadow:0 6px 20px rgba(2,6,23,0.7)}
    .row{display:flex;justify-content:space-between;align-items:center}
    .small{font-size:13px;color:var(--muted)}
    .status-ok{color:#8ef3a0}
    .status-warn{color:var(--warn)}
    .status-bad{color:#ff8b8b}
    .metric{font-weight:600}
    .kv{display:flex;gap:8px;flex-wrap:wrap}
    .flag{font-size:22px;margin-right:8px}
    .footer{margin-top:14px;color:var(--muted);font-size:13px}
    .usage-bar-container{background:rgba(0,0,0,0.2);border-radius:4px;height:8px;margin-top:4px;width:100%;overflow:hidden;}
    .usage-bar{height:100%;border-radius:4px;transition:width 0.3s ease-out;}
    .usage-bar.status-ok{background-color:#4caf50;}
    .usage-bar.status-warn{background-color:var(--warn);}
    .usage-bar.status-bad{background-color:#f44336;}
    .procs-list{font-family:monospace;white-space:pre-wrap;overflow-wrap:break-word;font-size:11px;margin-top:4px;padding:6px;background:rgba(0,0,0,0.2);border-radius:4px;}
    .service-status-list{font-family:monospace;white-space:pre-wrap;font-size:12px;margin-top:4px;padding:6px;background:rgba(0,0,0,0.2);border-radius:4px;}
    </style>
    </head>
    <body>
    <div class="header">
      <div class="h1">Server Status</div>
      <div class="controls">
        <span class="small" id="countdown"></span>
        <button id="refreshBtn">Refresh (purge cache)</button>
        <button id="reloadBtn">Reload UI</button>
      </div>
    </div>
    <div id="grid" class="grid"></div>
    <div class="footer">Key: <span class="status-ok">PING OK</span> / <span class="status-warn">HIGH LOAD/USAGE</span> / <span class="status-bad">CRITICAL or DOWN</span></div>
    <script>
    const urlParams = new URLSearchParams(window.location.search);
    const authToken = urlParams.get('auth');
    const isDemo = urlParams.has('demo');

    function getUsageClass(p){
      if(p === null || isNaN(p)) return '';
      if(p > 90) return 'status-bad';
      if(p > 80) return 'status-warn';
      return 'status-ok';
    }

    function getLoadClass(load, cores){
      if(!load || !cores || cores === 0) return 'status-ok';
      const ratio = load / cores;
      if(ratio > 1.0) return 'status-bad';
      if(ratio > 0.8) return 'status-warn';
      return 'status-ok';
    }

    function buildUrl(path) {
        const params = new URLSearchParams();
        if (isDemo) params.append('demo', '');
        if (authToken) params.append('auth', authToken);
        const queryString = params.toString();
        return queryString ? `${path}?${queryString}` : path;
    }

    async function loadStatus(){
      const el=document.getElementById('grid');
      el.innerHTML='<div style="color:var(--muted)">Loading…</div>';
      try{
        const fetchUrl = buildUrl('status.json');
        const r = await fetch(fetchUrl);
        if(!r.ok) {
            if(r.status === 404) throw new Error('Not Found (check proxy path)');
            throw new Error('HTTP '+r.status);
        }
        const data=await r.json();
        el.innerHTML='';
        data.forEach(s=>{
          const c=document.createElement('div'); c.className='card';
          const pingMetric = s.ping_ok ? `PING OK ${s.ping_ms ? '(' + s.ping_ms.toFixed(1) + ' ms)' : ''}` : 'NO PING';
          let html=`<div class="row"><div><span class="flag">${s.flag||''}</span><strong>${s.name}</strong> <span class="small">${s.host}</span></div><div class="small">${s.last_update?new Date(s.last_update*1000).toLocaleString():''}</div></div>`;
          html+=`<div class="row" style="margin-top:8px"><div class="small">Ping</div><div class="metric ${s.ping_ok? 'status-ok':'status-bad'}">${pingMetric}</div></div>`;
          if(s.ssh){
            const loadClass = getLoadClass(s.ssh.load_1m, s.ssh.cores);
            const memClass = getUsageClass(s.ssh.mem_usage_percent);
            const diskClass = getUsageClass(s.ssh.disk_usage_percent);
            const updatesClass = s.ssh.upgradable_packages > 0 ? 'status-warn' : '';

            html+=`<div style="margin-top:8px" class="kv">`;
            html+=`<div class="small">Uptime<br><span class="metric">${escapeHtml(s.ssh.uptime||'')}</span></div>`;
            html+=`<div class="small">Load<br><span class="metric ${loadClass}">${escapeHtml(s.ssh.load||'')}</span></div>`;
            html+=`<div class="small">Type<br><span class="metric">${escapeHtml(s.ssh.server_type||'')}</span></div>`;
            html+=`<div class="small">Updates<br><span class="metric ${updatesClass}">${s.ssh.upgradable_packages} packages</span></div>`;
            html+=`<div class="small">Network (In/Out)<br><span class="metric">${s.ssh.net_rx_mbits.toFixed(2)} / ${s.ssh.net_tx_mbits.toFixed(2)} Mbit/s</span></div>`;
            html+=`<div class="small">OS<br><span class="metric">${escapeHtml(s.ssh.os_info||'')}</span></div>`;
            html+=`<div class="small">Kernel<br><span class="metric">${escapeHtml(s.ssh.kernel_version||'')}</span></div>`;
            html+=`<div class="small">CPU<br><span class="metric">${s.ssh.cores||'?'} cores @ ${s.ssh.cpu_mhz||'?'} MHz</span></div>`;
            html+=`<div class="small" style="flex-basis: 100%;">CPU Model<br><span class="metric">${escapeHtml(s.ssh.cpu_model||'')}</span></div>`;

            html+=`<div class="small" style="flex-basis: 100%;">Memory<br><span class="metric ${memClass}">${fmtBytes(s.ssh.mem_used_bytes)} used / ${fmtBytes(s.ssh.mem_free_bytes)} free / ${fmtBytes(s.ssh.mem_total_bytes)} total</span><div class="usage-bar-container"><div class="usage-bar ${memClass}" style="width:${s.ssh.mem_usage_percent}%"></div></div></div>`;
            html+=`<div class="small" style="flex-basis: 100%;">Disk<br><span class="metric ${diskClass}">${fmtBytes(s.ssh.disk_used_bytes)} used / ${fmtBytes(s.ssh.disk_free_bytes)} free / ${fmtBytes(s.ssh.disk_total_bytes)} total</span><div class="usage-bar-container"><div class="usage-bar ${diskClass}" style="width:${s.ssh.disk_usage_percent}%"></div></div></div>`;

            if(s.ssh.service_status && s.ssh.service_status.length > 0) {
                let serviceHtml = '';
                s.ssh.service_status.forEach(svc => {
                    const statusClass = svc.status === 'OK' ? 'status-ok' : 'status-bad';
                    const info = svc.info ? ` (${svc.info})` : '';
                    const port = svc.port.includes('/') ? `socket` : svc.port; // Display 'socket' for path
                    const icon = svc.status === 'OK' ? '✔' : '✖';
                    serviceHtml += `<div><span class="${statusClass}">${icon}</span> ${escapeHtml(svc.name)} ${escapeHtml(port)}: <span class="${statusClass}">${escapeHtml(svc.status)}${escapeHtml(info)}</span></div>`;
                });
                html+=`<div class="small" style="flex-basis: 100%;">Service Status<div class="service-status-list">${serviceHtml}</div></div>`;
            }
            
            if (s.ssh.nginx_hosts && s.ssh.nginx_hosts.length > 0) {
                let nginxHtml = '';
                s.ssh.nginx_hosts.forEach(host => {
                    let sslText = '';
                    if (host.ssl_status === 'OK') {
                        sslText = ' <span class="status-ok">SSL</span>';
                    } else if (host.ssl_status !== 'NO_SSL') {
                        sslText = ` <span class="status-bad">SSL (${escapeHtml(host.ssl_status)})</span>`;
                    }
                    nginxHtml += `<div><strong>Host:</strong> ${escapeHtml(host.host)}${escapeHtml(host.details)}${sslText}</div>`;
                });
                s.ssh.nginx_proxies.forEach(proxy => {
                    nginxHtml += `<div><strong>Proxy:</strong> ${escapeHtml(proxy.path)} -&gt; ${escapeHtml(proxy.target)}</div>`;
                });
                html+=`<div class="small" style="flex-basis: 100%;">Nginx Configuration<div class="procs-list">${nginxHtml}</div></div>`;
            }

            if(s.ssh.logged_in_users){
                html+=`<div class="small" style="flex-basis: 100%;">Logged In Users<div class="procs-list">${escapeHtml(s.ssh.logged_in_users)}</div></div>`;
            }

            if(s.ssh.top_procs_cpu){
                html+=`<div class="small" style="flex-basis: 100%;">Top Processes (%CPU)<div class="procs-list">${escapeHtml(s.ssh.top_procs_cpu)}</div></div>`;
            }
            if(s.ssh.top_procs_mem){
                html+=`<div class="small" style="flex-basis: 100%;">Top Processes (%MEM)<div class="procs-list">${escapeHtml(s.ssh.top_procs_mem)}</div></div>`;
            }

            html+=`</div>`;
          } else {
            html+=`<div style="margin-top:8px" class="small">${s.error||'No SSH data'}</div>`;
          }
          c.innerHTML=html;
          el.appendChild(c);
        });
      }catch(e){
        el.innerHTML='<div style="color:#ff8b8b">Error loading status: '+e.message+'</div>'
      }
    }

    function fmtBytes(b){ if(b === null || typeof b === 'undefined') return '?'; b=Number(b); if(isNaN(b)) return '?';
      if(b>1e12) return (b/1e12).toFixed(2)+' TB';
      if(b>1e9) return (b/1e9).toFixed(2)+' GB';
      if(b>1e6) return (b/1e6).toFixed(2)+' MB';
      return Math.round(b)+' B';
    }

    function escapeHtml(s){ if(!s) return ''; return String(s).replace(/[&<>"']/g, function(m){return({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;', "'":'&#39;'}[m]);}); }

    document.getElementById('refreshBtn').addEventListener('click', async()=>{
      if(!confirm('Purge cache and reload data?')) return;
      const refreshUrl = buildUrl('refresh');
      const r=await fetch(refreshUrl, {method:'POST'});
      if(r.ok) {
        countdown = 0; // Trigger immediate refresh and reset timer
        updateCountdown();
      } else {
        alert('Refresh failed');
      }
    });

    document.getElementById('reloadBtn').addEventListener('click', ()=>location.reload());

    const REFRESH_INTERVAL_SECONDS = 120;
    let countdown = REFRESH_INTERVAL_SECONDS;
    const countdownEl = document.getElementById('countdown');

    function updateCountdown() {
      if (countdownEl) {
        countdownEl.textContent = `Next Refresh: ${countdown}s`;
      }
    }

    function startRefreshTimer() {
      setInterval(() => {
        countdown--;
        if (countdown <= 0) {
          loadStatus();
          countdown = REFRESH_INTERVAL_SECONDS;
        }
        updateCountdown();
      }, 1000);
    }

    loadStatus();
    updateCountdown();
    startRefreshTimer();


    </script>
    </body>
    </html>
    '''

    @app.route('/')
    @combined_auth_required
    def index():
        return render_template_string(INDEX_HTML)

    @app.route('/favicon.ico')
    def favicon_ico():
        return send_from_directory(APP_DIR, 'favicon.ico', mimetype='image/vnd.microsoft.icon')

    @app.route('/favicon.png')
    def favicon_png():
        return send_from_directory(APP_DIR, 'favicon.png', mimetype='image/png')

    @app.route('/status.json')
    @combined_auth_required
    def status_json():
        is_demo = 'demo' in request.args
        servers = load_servers()
        out = []
        threads = []

        def fetch_and_append(server, output_list):
            data, _ = get_cached_or_fetch(server)
            output_list.append(data)

        for s in servers:
            thread = threading.Thread(target=fetch_and_append, args=(s, out))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        # Apply demo mode transformations if requested
        if is_demo:
            for i, server in enumerate(out):
                server['name'] = f'Server-{i + 1}'
                server['host'] = 'x.x.x.x'

                if server.get('ssh'):
                    # Sanitize Nginx hosts
                    if server['ssh'].get('nginx_hosts'):
                        for nginx_host in server['ssh']['nginx_hosts']:
                            domain = nginx_host['host'].strip()
                            parts = domain.split('.')
                            nginx_host['host'] = 'sub.example.com' if len(parts) > 2 else 'example.com'
                    
                    # Sanitize Nginx proxies
                    if server['ssh'].get('nginx_proxies'):
                        path_segment_map = {}
                        demo_counter = 1

                        def sanitize_path_segments(path_str):
                            nonlocal demo_counter
                            if not path_str or path_str == '/':
                                return path_str
                            
                            segments = [s for s in path_str.split('/') if s]
                            new_segments = []
                            for segment in segments:
                                if segment not in path_segment_map:
                                    path_segment_map[segment] = f"demo{demo_counter}"
                                    demo_counter += 1
                                new_segments.append(path_segment_map[segment])
                            
                            new_path = "/".join(new_segments)
                            if path_str.startswith('/'):
                                new_path = '/' + new_path
                            if path_str.endswith('/'):
                                new_path = new_path + '/'
                            return new_path

                        for proxy in server['ssh']['nginx_proxies']:
                            # Sanitize path's domain part
                            path_parts = proxy['path'].split('/', 1)
                            path_domain_part = path_parts[0]
                            path_path_part = '/' + path_parts[1] if len(path_parts) > 1 else ''
                            
                            sanitized_domain = 'example.com'
                            if '.' in path_domain_part:
                                parts = path_domain_part.split('.')
                                sanitized_domain = 'sub.example.com' if len(parts) > 2 else 'example.com'
                            
                            # Sanitize path's path part
                            proxy['path'] = sanitized_domain + sanitize_path_segments(path_path_part)

                            # Sanitize target URL (domain and path)
                            target_match = re.match(r'(https?://)([^/]+)(.*)', proxy['target'])
                            if target_match:
                                protocol, domain_with_port, path = target_match.groups()
                                domain_only = domain_with_port.split(':')[0]
                                
                                sanitized_domain = domain_with_port
                                if '.' in domain_only and not re.match(r'\d{1,3}(\.\d{1,3}){3}', domain_only):
                                    parts = domain_only.split('.')
                                    sanitized_domain_only = 'sub.example.com' if len(parts) > 2 else 'example.com'
                                    sanitized_domain = domain_with_port.replace(domain_only, sanitized_domain_only)

                                sanitized_path = sanitize_path_segments(path)
                                proxy['target'] = f"{protocol}{sanitized_domain}{sanitized_path}"

        out.sort(key=lambda x: x.get('name',''))
        return jsonify(out)

    @app.route('/refresh', methods=['POST'])
    @combined_auth_required
    def refresh():
        with _cache_lock:
            _cache.clear()

        servers = load_servers()
        threads = []

        def fetch_and_cache(server):
            get_cached_or_fetch(server)

        for s in servers:
            thread = threading.Thread(target=fetch_and_cache, args=(s,))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        return jsonify({'ok': True})
        
def start_server():
    if not FLASK_AVAILABLE:
        print("\nERROR: Flask or other required web modules are not installed.")
        print("Please run the master installer first or install them manually:")
        print("  sudo python3 server.py --install-master")
        sys.exit(1)
    
    use_token_auth = SECRET_TOKEN and SECRET_TOKEN != "token"

    print('Using SSH key:', SSH_KEY_PATH)
    print('Servers file:', SERVERS_FILE)
    
    if users:
        print(f"Password auth enabled. User: {PANEL_USER}, Pass: {PANEL_PASS}")
        if PANEL_USER == "user" and PANEL_PASS == "pass":
            print("\n\033[93mWARNING: You are using the default username and password.\033[0m")
            print("It is strongly recommended to change them by re-running the installer:")
            print("  sudo python3 server.py --install-master\n")
    else:
        print("Password auth is disabled.")
        
    if use_token_auth:
        if not users:
            print("Token-only auth is enabled.")
            print(f"Access URL: http://{BIND_HOST}:{BIND_PORT}/?auth={SECRET_TOKEN}")
        else:
            print(f'URL token auth enabled. Token: {SECRET_TOKEN}')
    else:
        print('URL token auth is disabled (default or empty token is set).')

    if not users and not use_token_auth:
        print("\n\033[93mWARNING: All authentication is disabled. Dashboard is publicly accessible.\033[0m")

    print(f'Starting Waitress server, listening on http://{BIND_HOST}:{BIND_PORT}')
    serve(app, host=BIND_HOST, port=BIND_PORT)


# --- CLI and Installer Functions ---
def print_help():
    print("Options/Help - Server Dashboard:")
    print("-h / --help         - This output")
    print("--install-master    - Install required packages to run dashboard on this system, run config wizard for Binding/Users/etc, write example servers.json and generate SSH key if desired")
    print("--install-slaves    - Install required packages on slaves read from servers.json")
    print("--start             - Start Dashboard server")

def run_command(cmd, show_output=False):
    """Runs a command, returns True on success, False on failure."""
    try:
        if show_output:
            result = subprocess.run(cmd, shell=True)
        else:
            result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return result.returncode == 0
    except Exception:
        return False
        
def install_package(pkg):
    """Installs an apt package and reports status."""
    print(f"- {pkg}: ", end="", flush=True)
    # Use a more reliable check for package installation
    if run_command(f"dpkg -s {pkg} 2>/dev/null | grep -q 'Status: install ok installed'"):
        print("\033[92mAlready installed\033[0m")
        return True
    
    # Try to install
    if run_command(f"sudo apt-get install -y -qq {pkg}"):
        print("\033[92mInstalled\033[0m")
        return True
    else:
        print("\033[91mFailed\033[0m")
        return False

def run_master_installer():
    if os.geteuid() != 0:
        print("Error: --install-master must be run with sudo.")
        sys.exit(1)

    print("--Installing Core Dependencies--")
    run_command("sudo apt-get update -qq")
    # Removed 'python3' as it's required to run the script itself
    core_deps = ['openssh-client', 'python3-venv', 'python3-pip']
    for pkg in core_deps:
        if not install_package(pkg):
            print(f"\nFailed to install required package: {pkg}. Aborting.")
            sys.exit(1)
    print("--Core Dependencies OK--\n\n")

    print("--Installing Python3 Modules (via apt)--")
    py_deps = ['python3-paramiko', 'python3-flask-httpauth', 'python3-waitress']
    failed_py_deps = []
    for pkg in py_deps:
        if not install_package(pkg):
            failed_py_deps.append(pkg)

    if failed_py_deps:
        print("\n\033[91mFailed to install Python module(s) via apt, Aborting - Use PIP in venv:\033[0m")
        print("  python3 -m venv venv")
        print("  source venv/bin/activate")
        print("  pip install --upgrade pip")
        print("  pip install flask paramiko flask-httpauth waitress")
        sys.exit(1)
    
    print("\n--Packages Installed, Please configure venv after this installer finishes--")
    print("  python3 -m venv venv")
    print("  source venv/bin/activate")
    print("  pip install --upgrade pip")
    print("  pip install flask paramiko flask-httpauth waitress")
    
    print("\n\n")

    # Favicon Download
    favicon_path = os.path.join(APP_DIR, 'favicon.png')
    if not os.path.exists(favicon_path):
        print("--Downloading favicon.png--")
        try:
            url = "https://raw.githubusercontent.com/i-william-hr/ServerDashboard/refs/heads/main/favicon.png"
            urllib.request.urlretrieve(url, favicon_path)
            print("Favicon downloaded successfully.")
        except Exception as e:
            print(f"Could not download favicon: {e}")
            print("Continuing without favicon.")
    print("\n\n")

    # SSH Key Generation
    default_key_name = "dashboard"
    default_key_path = os.path.join(APP_DIR, default_key_name)
    new_ssh_path = SSH_KEY_PATH
    if not os.path.exists(SSH_KEY_PATH):
        answer = input(f"--SSH key '{SSH_KEY_PATH}' not found. Generate a new key pair named '{default_key_name}' in this directory? [Y/n] ").lower().strip()
        if answer == "" or answer == "y":
            run_command(f'ssh-keygen -t ed25519 -f {default_key_name} -N "" -q')
            new_ssh_path = default_key_path
            print("\n--Public key, add on each slave server for user root:--")
            print("  - mkdir -p /root/.ssh/")
            with open(f"{default_key_name}.pub", 'r') as f:
                pub_key = f.read().strip()
                print(f"  - echo '{pub_key}' >> /root/.ssh/authorized_keys")
    
    print("\n\n")

    # servers.json Generation
    if not os.path.exists(SERVERS_FILE):
        print("--No server configuration detected - Writing example servers.json, Please edit manually--")
        example_json = """// The only required fields are "name" and "host".
// If not provided, "user" defaults to "root" and "port" defaults to 22.
// The "country" field for the flag is optional.
[
  {
    "name": "Server-1",
    "host": "171.22.1.1",
    "country": "DE"
  },
  {
    "name": "Server-2",
    "host": "172.245.1.1",
    "user": "root",
    "port": 2222,
    "country": "IE"
  },
  {
    "name": "Server-3",
    "host": "192.71.1.1",
    "user": "root",
    "port": 2222,
    "country": "NL"
  }
]"""
        with open(SERVERS_FILE, 'w') as f:
            f.write(example_json)
        print("Content:")
        print(example_json)

    print("\n\n")

    # Config wizard
    print("--Server configuration--")
    print("-To use default simply press enter-")
    bind_host = input(f"Bind to IP (Default: 0.0.0.0, Use 127.0.0.1 for local only): ") or "0.0.0.0"
    bind_port = input(f"Bind to Port (Default: 8889): ") or "8889"
    panel_user = input(f"Panel username (Default: user): ") or "user"
    panel_pass = input(f"Panel password (Default: pass): ") or "pass"
    secret_token = input(f"Panel access token (Default: disabled, enter any to enable): ") or "token"
    cache_ttl = input(f"SSH Refresh time (Default 300 sec): ") or "300"

    with open(os.path.join(APP_DIR, '.env'), 'w') as f:
        f.write(f"BIND_HOST={bind_host}\n")
        f.write(f"BIND_PORT={bind_port}\n")
        f.write(f"PANEL_USER={panel_user}\n")
        f.write(f"PANEL_PASS={panel_pass}\n")
        f.write(f"SECRET_TOKEN={secret_token}\n")
        f.write(f"CACHE_TTL={cache_ttl}\n")
        f.write(f"SSH_KEY_PATH={new_ssh_path}\n")
    
    print("\nConfiguration saved to .env file. You can now start the server with '--start'")
    sys.exit(0)


def run_slave_installer():
    if os.geteuid() != 0:
        print("Error: --install-slaves must be run with sudo.")
        sys.exit(1)
        
    servers = load_servers()
    if not servers:
        print("--No servers configured in servers.json or file does not exist--")
        sys.exit(1)
        
    print("--Servers loaded from config--")

    for server in servers:
        host = server['host']
        user = server.get('user', 'root')
        port = server.get('port', 22)
        name = server['name']
        
        print(f"\n{name} {host} - ", end="", flush=True)

        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(hostname=host, port=port, username=user, key_filename=SSH_KEY_PATH, timeout=SSH_CONNECT_TIMEOUT)
            
            # Check for marker file
            sftp = client.open_sftp()
            try:
                sftp.stat('/var/tmp/dash_setup')
                print("Skipping: Existing setup found")
                sftp.close()
                client.close()
                continue
            except FileNotFoundError:
                pass # Continue with installation
            sftp.close()

            print("Installing packages:")
            
            # Install packages one by one
            stdin, stdout, stderr = client.exec_command("apt-get update -qq")
            stdout.channel.recv_exit_status() # Wait for command to finish
            
            slave_deps = ['virt-what', 'net-tools', 'netcat-openbsd', 'openssl', 'mysql-client', 'mariadb-client-compat']
            failed_packages = []
            
            for pkg in slave_deps:
                # Check if already installed
                stdin, stdout, stderr = client.exec_command(f"dpkg -s {pkg} 2>/dev/null | grep -q 'Status: install ok installed'")
                if stdout.channel.recv_exit_status() == 0:
                    print(f"- {pkg}: Already installed")
                    continue
                
                # Install
                stdin, stdout, stderr = client.exec_command(f"apt-get install -y -qq {pkg}")
                exit_status = stdout.channel.recv_exit_status()
                
                if exit_status == 0:
                    print(f"- {pkg}: Installed")
                else:
                    # Special handling for mysql/mariadb clients
                    if pkg == 'mysql-client':
                        print(f"- {pkg}: Failed (will try mariadb-client-compat)")
                    elif pkg == 'mariadb-client-compat':
                        stdin, stdout, stderr = client.exec_command("dpkg -s mysql-client 2>/dev/null | grep -q 'Status: install ok installed'")
                        if stdout.channel.recv_exit_status() != 0:
                            print(f"- {pkg}: Failed")
                            failed_packages.append(pkg)
                    else:
                        print(f"- {pkg}: Failed")
                        failed_packages.append(pkg)

            if not failed_packages:
                client.exec_command("touch /var/tmp/dash_setup")
                print(f"{name} {host} - All packages installed with success")
            else:
                print(f"- INFO: {', '.join(failed_packages)} failed to install - Check manually or not all (if any) metrics will function")
                print(f"{name} {host} - Failure with one or more packages")

            client.close()
            
        except Exception as e:
            print(f"Skipping: Connection failed ({e})")

    print("\n\n--All slaves installed, check above for errors and repair as needed--")
    sys.exit(0)


if __name__ == '__main__':
    if len(sys.argv) == 1 or sys.argv[1] in ['-h', '--help']:
        print_help()
    elif sys.argv[1] == '--install-master':
        run_master_installer()
    elif sys.argv[1] == '--install-slaves':
        if not FLASK_AVAILABLE: # paramiko needed for slave install
            print("\nERROR: Required modules not found. Please run '--install-master' first.")
            sys.exit(1)
        run_slave_installer()
    elif sys.argv[1] == '--start':
        start_server()
    else:
        print(f"Unknown option: {sys.argv[1]}")
        print_help()
