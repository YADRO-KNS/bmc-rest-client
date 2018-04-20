# bmc-rest-client

This script was written based on the https://github.com/openbmc/openbmc-tools

To configure, edit `${HOME}/.config/bmc/settings:
```
[global]
username = root
password = *****
server = server1

[server1]
hostname = bmc.server1.corp.domain.com 

[qemu-bmc]
hosstname = localhost
port = 10443
```

Then you can call `bmc.py` for `server1` without additional arguments:
```
bmc.py get /xyz/openbmc_project/inventory/system/chassis/motherboard
```
or call `bmc.py` for running qemu at localhost:
```
bmc.py --server qemu-bmc list /xyz/openbmc_project
```

All specified in command line arguments will be used instead configured.

