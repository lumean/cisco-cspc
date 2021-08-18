# cisco-cspc

## Use Case Description

`cspc_api.py` is a small API client to Cisco's [Common Services Platform Collector (CSPC)](https://www.cisco.com/c/en/us/support/cloud-systems-management/common-services-platform-collector-cspc/series.html)

It provides methods to access the most frequently used APIs for adding & removing devices and corresponding credentials.
This is currently far from a complete API client implementation, but I hope enough to get you started in synchronizing devices
from you current inventory management system to CSPC.

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

### DevNet Sandbox

A great way to make your repo easy for others to use is to provide a link to a [DevNet Sandbox](https://developer.cisco.com/site/sandbox/) that provides a network or other resources required to use this code. In addition to identifying an appropriate sandbox, be sure to provide instructions and any configuration necessary to run your code with the sandbox.

## How to test the software

Tested agains CSPC version 2.9. 

For testing download and setup CSPC as VM.


## Getting help

If you have questions, concerns, bug reports, etc., please create an issue against this repository.
This project is maintained in my free time, so please be patient.

## Getting involved

Pull requests are welcome!

Currently missing:
- unit tests
- integration testing with CSPC VM


## Author(s)

This project was written and is maintained by the following individuals:

* Manuel Widmer <mawidmer@cisco.com>
