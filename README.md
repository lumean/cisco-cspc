# cisco-cspc

## Use Case Description

`cspc_api.py` is a small API client to Cisco's [Common Services Platform Collector (CSPC)](https://www.cisco.com/c/en/us/support/cloud-systems-management/common-services-platform-collector-cspc/series.html)

It provides methods to access the most frequently used APIs for adding & removing devices and corresponding credentials.
This is currently far from a complete API client implementation, but I hope enough to get you started in synchronizing devices
from your current inventory management system to CSPC.

More information can be found at [CSPC Install and Upgrade Guides](https://www.cisco.com/c/en/us/support/cloud-systems-management/common-services-platform-collector-cspc/products-installation-guides-list.html)

## Installation

```
git clone https://github.com/lumean/cisco-cspc.git
cd cisco-cspc
pip install -r requirements.txt
```

## Usage

```
# include this repo to your path (adapt accordingly):
path = os.path.join(os.path.dirname(__file__), 'path', 'to', 'this', 'repo')
sys.path.append(path)

from cspc_api import CspcApi

format = "%(asctime)s %(name)10s %(levelname)8s: %(message)s"
logfile=None
logging.basicConfig(format=format, level=logging.DEBUG,
                    datefmt="%H:%M:%S", filename=logfile)

cspc = CspcApi('<IP of your CSPC server>', 'admin', 'admin_pass', verify=False)

...
```

See also [Examples](examples/)


## How to test the software

Tested agains CSPC patch 2.10.0.1

For testing download and setup CSPC as VM, see below.


## Getting help

If you have questions, concerns, bug reports, etc., please create an issue against this repository.
This project is maintained in my free time, so please be patient.

## Getting involved

Pull requests are welcome!

Currently missing:
- unit tests

## Author(s)

This project was written and is maintained by the following individuals:

* Manuel Widmer <mawidmer@cisco.com>

# Integration Testing

## CSPC VM Setup

For testing I use virtualbox release >=6.1.32. Download the ova file & patch from
[software.cisco.com](https://software.cisco.com/download/home/286312935/type/286312958/release/2.10.0.1).
If the ova import fails, you need to manually create the VM with the following settings:

Extract the virtual harddisk vmdk from the ova with 7zip or an archive utility of your choice.

-> Collector-2.10.0.1-B-7-disk1.vmdk

- Redhat (64-bit)
- Base Memory 8192 MB, Chipset PIIX3, Pointing PS2/Mouse,
- Enable I/O APIC, Hardware Clock on UTC
- 4 vCPU (Enable PAE/NX, Enable Nested VT-x/AMD-V)
- Storage:
  - add Floppy Controller
  - add LsiLogic SAS Controller (note: 2 disks below are mandatory)
    - 1st Disk Collector-2.10.0.1-B-7-disk1.vmdk
    - 2nd Disk create a new vmdisk-small.vmdk (30GB)
- Disable Audio
- Network Adapter (NAT)
  - Advanced: Adapter Type Intel PRO/1000 MT Server (8254EM)
  - Port forwarding: ssh 2227 -> 22, webui 2228 -> 8001  (you are free to chose the source ports as you see fit)
- Remaining settings are left at their default value if not explicitly mentioned above.

Note: above settings are just from my personal test VM, for production values of CSPC please refer to
[the official sizing](https://www.cisco.com/c/dam/en/us/support/docs/cloud-systems-management/common-services-platform-collector-cspc/CSPC-Quick-Start-Guide.pdf).

Boot the VM, it might perform multiple reloads, then asks for the admin password.

Note down the admin pasword, you need it later. You can also change the password in the CSPC UI.

If 2.10 startup job(/etc/rc.d/rc.local) is running for more than 20 mins then try pressing
Alt+F1 through Alt+F6 (or Ctrl+Alt+F1 to F6) to shift to alternate virtual terminals and you may see one
of them waiting for with the admin password prompt.

Note down the admin password, you should arrive to a screen as follows.
Choose 3 to start the admin shell:

<img src=initial_setup_1.png />

Navigate to https://localhost:2228/

login as admin and complete the initial setup
- Configure the 3 security questions
- Choose a timezone (all other settings can be left empty)
- Register collector by providing a service certificate (you can get it e.g. via https://service.cisco.com)
<img src=initial_setup_2.png />
(Note: the trial option to login with your CCO account no longer works, corresponding backend services
have been decomissioned some time ago)
- After registering the certificate cancle the wizard without adding any devices.

Some addtional tuning recommended for ease of use:

Disable login captcha:
- under Administration -> Login Settings...
  - Disable Captcha Prompt
  - Expire Passwords: Never

Enable ssh / root access:
On the virtualbox console or via ssh login as admin

```bash
# login via ssh (assuming you use the forwarded ports as described above)
# ssh -p 2227 admin@localhost       (enter the admin pw)
===========================================================================
                Cisco Network Appliance Administration
===========================================================================
To see the list of all the commands press '?'

admin# pwdreset collectorlogin 90
Password for 'collectorlogin' reset to - <removed> successfully
Password expires in 90 days
Shell is enabled
passwd: all authentication tokens updated successfully
*** Please memorize the new password ***
Lost passwords cannot be recovered. The only alternative to recover is to reinstall the server.


admin# pwdreset root 90
Password for 'root' reset to - <removed> successfully
Password expires in 90 days
Shell is enabled
passwd: all authentication tokens updated successfully
*** Please memorize the new password ***
Lost passwords cannot be recovered. The only alternative to recover is to reinstall the server.
```
Then connect via SSH using the generated passwords above and switch to the root user:
```bash
# login via ssh (assuming you use the forwarded ports as described above)
# ssh -p 2227 collectorlogin@localhost       (enter the collectorlogin pw)
# su -     (enter the root pw)

# cspc/cli admin passwords expires after 90 days, it's easier to disable expiry for the test VM
passwd -x -1 -n -1 -w -1 root
passwd -x -1 -n -1 -w -1 collectorlogin

# verify change with
chage -l root
chage -l collectorlogin
```


## Run the integration tests agains the VM

```bash
# install development dependencies
pip install -r requirements-dev.txt

cd tests
# change seetings below to fit your setup
cat > cspc.env << EOF
CSPC_USER=admin
CSPC_PASS=<adminpass>
CSPC_HOST=localhost
CSPC_PORT=2228
EOF

python test_cspc_api.py
```




