import os
import sys
import logging

path = os.path.join(os.path.dirname(__file__), '..')
sys.path.append(path)

from cspc_api import CspcApi

format = "%(asctime)s %(name)10s %(levelname)8s: %(message)s"
logfile=None
logging.basicConfig(format=format, level=logging.DEBUG,
                    datefmt="%H:%M:%S", filename=logfile)

cspc_user = 'dummy'
cspc_pass = 'dummy'

cspc = CspcApi('1.2.3.4', cspc_user, cspc_pass, verify=False)

creds = {
    '1.2.3.4': {
        'user': 'abcd',
        'password': 'test',
        'enable_password': 'test',
        'snmp_read_community': 'public',
        'snmp_write_community': 'blub',

    }
}
devices = {
     '1.2.3.4': 'testhostname1',
     '1.2.3.5': 'testhostname2',
}

print(cspc.add_multiple_device_credentials_ssh_snmp(creds))

print(cspc.add_multiple_devices(devices))

# print(cspc.delete_multiple_devices([{'Id': '63'}]))
