import os
import sys
import logging

path = os.path.join(os.path.dirname(__file__), '..')
sys.path.append(path)

from src.cspc_api.cspc_api import CspcApi

format = "%(asctime)s %(name)10s %(levelname)8s: %(message)s"
logfile=None
logging.basicConfig(format=format, level=logging.DEBUG,
                    datefmt="%H:%M:%S", filename=logfile)

cspc_user = 'dummy'
cspc_pass = 'dummy'

cspc = CspcApi('1.2.3.4', cspc_user, cspc_pass, verify=False)

snmp_credentials = {
    'my_snmp_wildcard': {
        'ip_expression': '*.*.*.*',
        'snmp_read_community': 'public',
        'snmp_write_community': 'blub',

    }
}
ssh_credentials = {
    'my_ssh_wildcard': {
        'ip_expression': '*.*.*.*',
        'user': 'abcd',
        'password': 'test',
        'enable_password': 'test'

    }
}
devices = [
    {
        'HostName': 'testhostname1',
        'IPAddress': '1.2.3.4',
        'DomainName': 'testhostname1.example.com',
        'PrimaryDeviceName': 'testhostname1.example.com',
    },
    {
        'HostName': 'testhostname2',
        'IPAddress': '1.2.3.5',
        'DomainName': 'testhostname2.example.com',
        'PrimaryDeviceName': 'testhostname2.example.com',
    },
]



print(cspc.add_multiple_device_credentials_ssh(ssh_credentials))
print(cspc.add_multiple_device_credentials_snmpv2c(snmp_credentials))

print(cspc.add_multiple_devices(devices))

# print(cspc.delete_multiple_devices([{'Id': '63'}]))
