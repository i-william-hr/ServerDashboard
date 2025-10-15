# ServerDashboard

This is a python app that provides a nice simple webinterface to monitor linux servers and services, using only SSH and few apt packages on targets.

See Py and Json file for config (Minimum PY: SSH key, User/Pass or Token - Minimum JSON: Name - IP - SSH User - Country code)

The data is updated every 600 seconds by SSH from each host and the interface refreshes all 120 seconds.

A mobile interface designed for iPhone and Android with relatively high resolution screen is included, see DEMO pictures.

Tested as root in screen but should work with any user if bind port is above 1024


Do not forget:

- Install packages on each slave: apt update && apt install -y virt-what; apt install -y net-tools; apt install -y netcat-openbsd; apt install -y mysql-client; apt install -y mariadb-client-compat

- Change bind from 127.0.0.1 to 0.0.0.0 at the Py end if no reverse proxy is used, Change port as desired

- Generate ssh key on master (ssh-keygen), copy public key to slaves and set path for private key in Py (Default set is for ssh-keygen on Debian and Ubuntu)

- ssh root@SLAVE from master for each slave to save the SSH host key



This monitors/Shows:

- Ping - Uptime - Load (with Green/Yellow/Red marking) - Type (VM/Dedicated and what VM type) - Apt updates pending - Net In/Out (Mbit)

- OS Version - Kernel Version - CPU cores & Mhz

- CPU Model - Memory Used/Free/Total (with usage bar in Green/Yellow/Red) - Disk Used/Free/Total (also with usage bar)

- Top processes by CPU (in %) and Memory (in % and in MB)

-

- Various Services, with automatic detection of ports they run on (and check for socket for MySQL):

- Nginx - MySQL/MariaDB - ZNC - SSH - Python scripts like my AppleHealthDashboard

