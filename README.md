# ServerDashboard



- Description:

This is a python app that provides a nice simple webinterface to monitor linux servers and services, using only SSH and few apt packages on targets.

The data is updated every 300 seconds by SSH from each host and the interface refreshes all 120 seconds.

A mobile interface designed for iPhone and Android with relatively high resolution screen is included, see DEMO pictures.

Tested as root in screen but should work with any user if bind port is above 1024 and the SSH key is accesible to it




- Automatic install with config wizard:

run "python3 server_status.py --install-master"

Copy SSH key to slaves as instructed

Add slaves to servers.json

run "python3 server_status.py --install-master"

edit the ".env" file if needed, no changes/config in the script are required


- Manual installation:

See Py and Json file for config (Minimum PY: SSH key, User/Pass or Token - Minimum JSON: Name, IP/Host, SSH User, Country code)

Install packages on master: apt update && apt install -y python3 python3-venv python3-pip openssh-client python3-paramiko python3-flask-httpauth python3-waitress

Create Python venv on master as per guide in Py file (might not be needed if all packages above are installed by apt, untested)

Install packages on slaves: apt update && apt install -y virt-what; apt install -y net-tools; apt install -y netcat-openbsd; apt install -y mysql-client; apt install -y mariadb-client-compat; apt install -y openssl

Info: Install of either mysql-client or mariadb-client-compat will fail dependig on OS/Version, this is fine as they work the same

Set a TOKEN and/or User and Password (If no token is set token auth is disabled)

Generate ssh key on master (ssh-keygen), copy public key to slaves and set path for private key in Py (Default path set is for "ssh-keygen" without arguments as root on Debian and Ubuntu)



This monitors/Shows:

- Ping - Uptime - Load (with Green/Yellow/Red marking) - Type (VM/Dedicated and what VM type) - Apt updates pending - Net In/Out (Mbit)

- OS Version - Kernel Version - CPU cores & Mhz

- CPU Model - Memory Used/Free/Total (with usage bar in Green/Yellow/Red) - Disk Used/Free/Total (also with usage bar)

- Top 5 processes by CPU (in %) and Memory (in % and in MB)

- Logged in users with IP or terminal if local

-

- Various Services, with automatic detection of ports they run on (and check for socket for MySQL):

- Nginx - MySQL/MariaDB - ZNC - SSH - Python scripts like my AppleHealthDashboard

- Shows all configured domains on Nginx, their ports and if SSL if trhe cert is valid

- Shows all Nginx reverse proxies and their targets

