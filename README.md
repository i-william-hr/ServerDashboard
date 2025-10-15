# ServerDashboard

This is a python app that provides a nice simple webinterface to monitor linux servers and services, using only SSH and few apt packages on targets.

See Py and Json file for packages needed and config.

The data is updated every 600 seconds by SSH from each host and the interface refreshes all 120 seconds.


This monitors/Shows:

- Ping - Uptime - Load (with Green/Yellow/Red marking) - Type (VM/Dedicated and what VM type) - Apt updates pending - Net In/Out (Mbit)

- OS Version - Kernel Version - CPU cores & Mhz

- CPU Model - Memory Used/Free/Total (with usage bar in Green/Yellow/Red) - Disk Used/Free/Total (also with usage bar)

- Top processes by CPU (in %) and Memory (in % and in MB)

-

- Various Services, with automatic detection of ports they run on (and check for socket for MySQL):

- Nginx - MySQL/MariaDB - ZNC - SSH - Python scripts like my AppleHealthDashboard

