import json
import logging
import os
import sys
import time

from dotenv import load_dotenv

from cspc_api import CspcApi

base_dir = os.path.dirname(os.path.dirname(__file__))

fmt = "%(asctime)s %(name)10s %(levelname)8s: %(message)s"
logfile = os.path.join(os.path.dirname(__file__), "log.txt")
logging.basicConfig(format=fmt, level=logging.DEBUG, datefmt="%H:%M:%S", filename=logfile)

load_dotenv(os.path.join(base_dir, "tests", "cspc.env"))

try:
    cspc = CspcApi(
        host=os.environ["CSPC_HOST"],
        user=os.environ["CSPC_USER"],
        pwd=os.environ["CSPC_PASS"],
        verify=False,
        port=os.environ["CSPC_PORT"],
    )
except KeyError as e:
    sys.exit(f"{e} not defined in tests/cspc.env, please check...")

snmp_credentials = {
    "my_snmp_wildcard": {
        "ip_expression": "*.*.*.*",
        "snmp_read_community": "public",
        "snmp_write_community": "blub",
    },
}
snmpv3_credentials = {
    "my_snmpv3_wildcard": {
        "ip_expression": "*.*.*.*",
        "snmpv3_user": "public",
        "snmpv3_auth_algorithm": "SHA",  # SHA, MD5
        "snmpv3_auth_password": "demo_authentication_pw",
        "snmpv3_priv_algorithm": "AES-128",  # 3DES, AES-128, AES-192, AES-256
        "snmpv3_priv_password": "demo_privacy_pw",
    },
}
ssh_credentials = {
    "my_ssh_wildcard": {
        "ip_expression": "*.*.*.*",
        "user": "abcd",
        "password": "test",
        "enable_password": "test",
    },
}
telnet_credentials = {
    "my_telnet_wildcard": {
        "ip_expression": "*.*.*.*",
        "user": "testtelnet",
        "password": "testtelnet",
        "enable_password": "testtelnet",
    },
}
devices = [
    {
        "HostName": "testhostname1",
        "IPAddress": "1.2.3.4",
        "DomainName": "testhostname1.example.com",
        "PrimaryDeviceName": "testhostname1.example.com",
    },
    {
        "HostName": "testhostname2",
        "IPAddress": "1.2.3.5",
        "DomainName": "testhostname2.example.com",
        "PrimaryDeviceName": "testhostname2.example.com",
    },
]


print("\ncleanup existing devices first:")
all_devices = cspc.get_devices_as_dict()
print(all_devices)
print(cspc.delete_multiple_devices(all_devices))

print("\nadd some credentials:")
print(cspc.add_multiple_device_credentials_telnet(telnet_credentials))
print(cspc.add_multiple_device_credentials_ssh(ssh_credentials))
print(cspc.add_multiple_device_credentials_snmpv2c(snmp_credentials))
print(cspc.add_multiple_device_credentials_snmpv3(snmpv3_credentials))

print("\nadd devices:")
print(cspc.add_multiple_devices(devices))

print("\nmodify devices:")
all_devices = cspc.get_devices_as_dict()
print(all_devices)
for dev in all_devices:
    dev["PrimaryDeviceName"] = dev["IPAddress"]

print(cspc.modify_multiple_devices(all_devices))

print("\ncheck after modify devices:")
all_devices = cspc.get_devices_as_dict()
print(all_devices)

print("\nDiscovery Job start:")
resp = cspc.discovery_by_ip(all_devices, ["snmpv2c", "snmpv3"])
resp_dict = cspc.response_as_dict(resp)
print(json.dumps(resp_dict, indent=2))
# before refactor response_as_dict
# job_id = resp_dict["Job"]["Schedule"]["JobDetails"]["JobId"]
# job_run_id = resp_dict["Job"]["Schedule"]["JobDetails"]["JobRunId"]
job_id = CspcApi.get_in_dict(resp_dict, "Response", "Job", "Schedule", "JobDetails", "JobId")
job_run_id = CspcApi.get_in_dict(resp_dict, "Response", "Job", "Schedule", "JobDetails", "JobRunId")
print(f"\nJob started with job_id: {job_id} job_run_id: {job_run_id}")

ip_range = [
    {"start": "10.10.10.1", "end": "10.10.10.3"},
    {"start": "10.10.10.100", "end": "10.10.10.103"},
]
print("\nStart Discovery by IP Range:")
resp = cspc.discovery_by_ip_range(ip_range, ["snmpv3"])
resp_dict = cspc.response_as_dict(resp)
print(json.dumps(resp_dict, indent=2))
job_id = CspcApi.get_in_dict(resp_dict, "Response", "Job", "Schedule", "JobDetails", "JobId")
job_run_id = CspcApi.get_in_dict(resp_dict, "Response", "Job", "Schedule", "JobDetails", "JobRunId")
print(f"\nJob started with job_id: {job_id} job_run_id: {job_run_id}")


print("\nAll Jobs:")
all_jobs_xml = cspc.get_job_list()
print(all_jobs_xml)
all_jobs_dict = cspc.response_as_dict(all_jobs_xml)
print(json.dumps(all_jobs_dict, indent=2))

# print(cspc.get_job_by_id(7))
# <Response requestId="3333"><Status code='SUCCESSFUL' /><Job><GetJobList operationId="1" ><Status code="SUCCESSFUL"/>
# <JobDetailList><JobDetail><JobId>7</JobId><JobName>XmlApiDiscovery1649670162478</JobName><JobGroup>RunNowDiscoveryJobGrp</JobGroup><Description>XmlApiDiscovery1649670162478</Description><CreatedBy>admin</CreatedBy><CreatedOn>1649670171000</CreatedOn><FirstRunTime>1649670163457</FirstRunTime><LastStartTime>1649670163457</LastStartTime><LastRunTime>1649670171623</LastRunTime><NextScheduleTime></NextScheduleTime><RunCount>1</RunCount><ServiceName></ServiceName><Schedule runnow="true"></Schedule></JobDetail></JobDetailList></GetJobList></Job></Response>
print(f"\nget_job_status of discovery job_id: {job_id} job_run_id: {job_run_id}")
resp = cspc.get_job_status(job_id, job_run_id)
# resp = cspc.get_job_status(10, 1)
# <Response requestId="3333"><Status code='SUCCESSFUL' /><Job><GetStatus operationId="1" ><Status code="SUCCESSFUL"/>
# <JobRunDetailList><JobRunDetail><State>Completed</State><Status>Success</Status><StartTime>1643028300458</StartTime><EndTime>1643028301375</EndTime></JobRunDetail></JobRunDetailList></GetStatus></Job></Response>
resp_dict = cspc.response_as_dict(resp)

print(json.dumps(resp_dict, indent=2))
print(f"\nWait for job to complete - job_id: {job_id} job_run_id: {job_run_id}")
# while resp_dict["Job"]["GetStatus"]["JobRunDetailList"]["JobRunDetail"]["State"] != "Completed":
while (
    CspcApi.get_in_dict(
        resp_dict,
        "Response",
        "Job",
        "GetStatus",
        "JobRunDetailList",
        "JobRunDetail",
        "State",
    )
    != "Completed"
):
    print(f"waiting for discovery to finish job_id: {job_id} job_run_id: {job_run_id}")
    time.sleep(5)
    resp = cspc.get_job_status(job_id, job_run_id)
    resp_dict = cspc.response_as_dict(resp)

print("\nmodify devices:")
all_devices = cspc.get_devices_as_dict()
print(all_devices)
for index, dev in enumerate(all_devices):
    dev["PrimaryDeviceName"] = devices[index]["PrimaryDeviceName"]
    dev["HostName"] = devices[index]["HostName"]

print(cspc.modify_multiple_devices(all_devices))
all_devices = cspc.get_devices_as_dict()
print(all_devices)

print("\ndelete non-existing device:")
print(cspc.delete_multiple_devices([{"Id": "63"}]))
print("\ndelete all devices:")
print(cspc.delete_multiple_devices(all_devices))
