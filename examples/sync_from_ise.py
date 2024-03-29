#!/usr/bin/env python
# -*- coding: utf-8 -*-

# This script synchronizes all devices from ISE to CSPC. It then
# compares unreachable devices from CSPC with the ISE inventory and
# if a device cannot be found in ISE, this script will delete it from CSPC
# finally a discovery job is triggered for the new devices

import json
import logging
import os
import re
import socket
import sys

# pip install git+https://github.com/lumean/cisco-cspc.git@v1.0.0
from cspc_api import CspcApi

# dependencies
deps = ["cisco-ise-ers-api"]
# dependencies
deps = {
    "cisco-ise-ers-api": "https://github.com/lumean/cisco-ise-ers-api.git",
}
for folder, origin in deps.items():
    dep_path = os.path.join(os.path.dirname(__file__), "..", folder)
    sys.path.append(dep_path)
    if not os.path.isdir(dep_path):
        print(f"Please ensure dependency is available at {dep_path}")
        print("Run the following command to fix it:")
        print(f"cd ..; git clone {origin}")
        exit()

from ise_ers_api import IseErsApi

format = "%(asctime)s %(name)10s %(levelname)8s: %(message)s"
logfile = None
logging.basicConfig(format=format, level=logging.WARN, datefmt="%H:%M:%S", filename=logfile)

ise_user, ise_pass = "ise_user", "ise_pass"
cspc_user, cspc_pass = "admin", "cspc_admin_pass"

# print(ise_user, ise_pass, cspc_user, cspc_pass)

# unset all proxies
os.environ["HTTPS_PROXY"] = ""
os.environ["https_proxy"] = ""


def export_all_ise_devices():
    print("reading devices from ISE")
    ise = IseErsApi("ise.exmple.org", ise_user, ise_pass, verify=False)
    all_devices = ise.export_all_network_elements()
    with open("ise_device_details.json", "w") as f:
        json.dump(all_devices, f, indent=2)
    return all_devices


def load_ise_devices_from_json():
    with open("ise_device_details.json", "r") as f:
        return json.load(f)


all_devices = export_all_ise_devices()
# all_devices = load_devices_from_json()


ssh_credentials = {
    "ise_*.*.*.*_sshv2": {
        "ip_expression": "*.*.*.*",
        "user": ise_user,
        "password": ise_pass,
        "enable_password": ise_pass,
    }
}

snmp_credentials = {
    "ise_*.*.*.*_snmpv2c_default": {
        "ip_expression": "*.*.*.*",
        "snmp_read_community": "my_read",
        "snmp_write_community": "my_write",
    },
    "ise_*.*.*.*_snmpv2c_special1": {
        "ip_expression": "*.*.*.*",
        "snmp_read_community": "my_read1",
        "snmp_write_community": "my_read1",
    },
}

exclude_names = {"HA port WLC": r"wlc.*-ha"}

# in future maybe add subnet support...
exclude_ips = {
    "127.0.0.1": "ise test host",
    "10.0.0.1": "some other host to ignore",
}

exclude_types = {
    "Checkpoint": "not a Cisco device",
    "Forti": "not a Cisco device",
}


def print_exclude_reason(reason, device):
    print(
        f"exclude ({reason}): "
        + device["name"]
        + " ip: "
        + str(device["NetworkDeviceIPList"])
        + " profile "
        + device["profileName"]
        + " "
        + str(device["NetworkDeviceGroupList"])
    )


devices_to_sync = list()

num_wlc = 0
for device in all_devices:
    skip = False
    # check if device needs to be skipped
    for reason, regex in exclude_names.items():
        if re.search(regex, device["name"]):
            print_exclude_reason(reason, device)
            skip = True
            break
    if skip:
        continue

    for dev_type, reason in exclude_types.items():
        for string in device["NetworkDeviceGroupList"]:
            if dev_type in string:
                print_exclude_reason(reason, device)
                skip = True
                break
    if skip:
        continue

    # if len(device['NetworkDeviceIPList']) > 1:
    #     print_exclude_reason('multiple /32', device)
    #     continue

    for ip_mask in device["NetworkDeviceIPList"]:
        if ip_mask["mask"] != 32:
            print_exclude_reason("not a /32", device)
            skip = True
            break

        if ip_mask["ipaddress"] in exclude_ips:
            print_exclude_reason(exclude_ips[ip_mask["ipaddress"]], device)
            skip = True
            break

        # good to sync, add to device list
        cscp_device = {
            "HostName": device["name"],
            "IPAddress": ip_mask["ipaddress"],
            "PrimaryDeviceName": device["name"],
        }
        devices_to_sync.append(cscp_device)

        # example how to match on specific device type string:
        for string in device["NetworkDeviceGroupList"]:
            if "Wireless#WLC" in string:
                num_wlc += 1

cspc = CspcApi("10.10.10.10", cspc_user, cspc_pass, verify=False)
print(len(all_devices), "Devices in ISE (multiple IP per device possible)")
print(len(devices_to_sync), "Devices IP to sync")
print(num_wlc, "WLCs")

print(cspc.add_multiple_device_credentials_ssh(ssh_credentials))
print(cspc.add_multiple_device_credentials_snmpv2c(snmp_credentials))

existing_count = 0
existing_devices = cspc.get_devices_as_dict()

# save complete list of ISE IP addresses to a separate variable
ise_device_ip_list = [d["IPAddress"] for d in devices_to_sync]

# remove already existing devices from our devices_to_sync list.
new_devices_to_sync = []
for new_device in devices_to_sync:
    is_new = True
    for existing_device in existing_devices:
        if existing_device["IPAddress"] == new_device["IPAddress"]:
            is_new = False
            existing_count += 1
            break
    if is_new:
        new_devices_to_sync.append(new_device)

print(f"{existing_count} Devices already exist, {len(new_devices_to_sync)} will be newly added...")
cspc.add_multiple_devices(new_devices_to_sync)
print("Devices added.")

unreachable = cspc.get_unreachable_devices()
not_in_ise = []

for device in unreachable:
    # perform dns reverse lookup to see if defined in DNS
    try:
        dns_tuple = socket.gethostbyaddr(device["IPAddress"])
        # e.g. ('my-hostname.example.org', [], ['172.16.1.1'])
        dns_name = dns_tuple[0]
    except:
        # socket.herror: [Errno 11004] host not found
        dns_name = "no reverse DNS found"

    if device["IPAddress"] not in ise_device_ip_list:
        print("{}, {}, not found in ISE".format(device["IPAddress"], dns_name))
        not_in_ise.append(device)

print("{} devices will be removed from CSPC".format(len(not_in_ise)))

print(cspc.delete_multiple_devices(not_in_ise))

print("Starting discovery job for newly added devices...")
if len(new_devices_to_sync) > 0:
    print(cspc.discovery_by_ip(new_devices_to_sync, ["snmpv2c"]))

print("Done.")
