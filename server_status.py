"""
Server Status - single-file Flask webapp (sample tailored)

What it does
- Runs on the Waitress production WSGI server.
- Binds to 127.0.0.1 so it's only accessible via a reverse proxy like Nginx.
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
  sudo apt update && sudo apt install -y python3 python3-venv python3-pip openssh-client
  python3 -m venv venv
  source venv/bin/activate
  pip install --upgrade pip
  pip install flask paramiko flask-httpauth waitress

Install on ALL REMOTE servers:
  sudo apt update && sudo apt install -y virt-what; sudo apt install -y net-tools; sudo apt install -y netcat-openbsd; sudo apt install -y mysql-client; sudo apt install -y mariadb-client-compat; sudo apt install -y openssl

Run:
  # For better security, set your own secret token
  export SECRET_TOKEN="change-me-to-something-long-and-random"
  python3 server.py  # listens on 127.0.0.1:8889

Env vars:
  SECRET_TOKEN (default token)
  SSH_KEY_PATH (default /root/.ssh/id_ed25519)
  CACHE_TTL (default 300)
  BIND_HOST (default 127.0.0.1)
  BIND_PORT (default 8889)

"""

from flask import Flask, jsonify, request, render_template_string, send_from_directory
from flask_httpauth import HTTPBasicAuth
from waitress import serve
from functools import wraps
import subprocess
import paramiko
import json
import os
import time
import threading
import re


# --- Main Configuration ---
APP_DIR = os.path.dirname(os.path.abspath(__file__))
SERVERS_FILE = os.path.join(APP_DIR, 'servers.json')
SSH_KEY_PATH = os.environ.get('SSH_KEY_PATH', '/root/.ssh/id_ed25519')
CACHE_TTL = int(os.environ.get('CACHE_TTL', '300'))
SSH_CONNECT_TIMEOUT = 5
PING_COUNT = 1
SECRET_TOKEN = os.environ.get('SECRET_TOKEN', 'token')
BIND_HOST = os.environ.get('BIND_HOST', '127.0.0.1')
BIND_PORT = int(os.environ.get('BIND_PORT', '8889'))


_cache = {}
_cache_lock = threading.Lock()

app = Flask(__name__)
auth = HTTPBasicAuth()
app.config['TEMPLATES_AUTO_RELOAD'] = True

# --- Authentication Setup ---
users = {
    "user": "pass"
}

@auth.verify_password
def verify_password(username, password):
    if username in users and users.get(username) == password:
        return username

def combined_auth_required(func):
    """Custom decorator to allow URL token OR Basic Auth."""
    @wraps(func)
    def decorated_view(*args, **kwargs):
        if SECRET_TOKEN and request.args.get('auth') == SECRET_TOKEN:
            return func(*args, **kwargs)
        if 'demo' in request.args: # Allow demo mode without auth
            return func(*args, **kwargs)
        return auth.login_required(func)(*args, **kwargs)
    return decorated_view
# --------------------------


def load_servers():
    try:
        with open(SERVERS_FILE, 'r') as f:
            return json.load(f)
    except Exception:
        return []


def get_flag_emoji(cc: str) -> str:
    if not cc or len(cc) != 2:
        return ''
    base = 0x1F1E6
    return ''.join(chr(base + ord(c) - ord('A')) for c in cc.upper())


def ping_host(host: str) -> tuple[bool, float | None]:
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


def ssh_run_command(host, user, key_path, cmd):
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(hostname=host, username=user, key_filename=key_path, timeout=SSH_CONNECT_TIMEOUT)
        stdin, stdout, stderr = client.exec_command(cmd, timeout=30) # Increased timeout for service/nginx checks
        out = stdout.read().decode('utf-8', errors='ignore')
        err = stderr.read().decode('utf-8', errors='ignore')
        client.close()
        if err:
            return True, out + "\nERR:\n" + err
        return True, out
    except Exception as e:
        return False, str(e)


def gather_server(host, user, country, name):
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
        'top_procs_cpu': "ps -eo pcpu,user,args --sort=-pcpu | sed 1d | grep -vF 'ps -eo pcpu,user,args' | head -n 3",
        'top_procs_mem': "ps -eo pmem,rss,user,args --sort=-pmem | sed 1d | grep -vF 'ps -eo pmem,rss,user,args' | head -n 3",
        'logged_in_users': "who | grep -vF \"$(who am i)\" || true",
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
        ok, out = ssh_run_command(host, user, SSH_KEY_PATH, cmd)
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
    data = gather_server(server['host'], server.get('user','root'), server.get('country',''), server.get('name', server['host']))
    with _cache_lock:
        _cache[key] = {'ts': time.time(), 'data': data}
    return data, _cache[key]['ts']

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
                    for proxy in server['ssh']['nginx_proxies']:
                        # Sanitize path
                        path_domain_part = proxy['path'].split('/')[0]
                        if '.' in path_domain_part:
                            parts = path_domain_part.split('.')
                            sanitized_domain = 'sub.example.com' if len(parts) > 2 else 'example.com'
                            proxy['path'] = proxy['path'].replace(path_domain_part, sanitized_domain)
                        
                        # Sanitize target
                        match = re.search(r'(https?://)([^/:]+)', proxy['target'])
                        if match:
                            target_domain = match.group(2)
                            if '.' in target_domain:
                                parts = target_domain.split('.')
                                sanitized_domain = 'sub.example.com' if len(parts) > 2 else 'example.com'
                                proxy['target'] = proxy['target'].replace(target_domain, sanitized_domain)

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

if __name__ == '__main__':
    print('Using SSH key:', SSH_KEY_PATH)
    print('Servers file:', SERVERS_FILE)
    if SECRET_TOKEN:
        print(f'URL auth enabled. Token: {SECRET_TOKEN}')
    print(f'Starting Waitress server, listening on http://{BIND_HOST}:{BIND_PORT}')
    serve(app, host=BIND_HOST, port=BIND_PORT)
