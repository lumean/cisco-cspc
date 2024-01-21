#!/usr/bin/env python
# -*- coding: utf-8 -*-

import base64
import logging
import os
import sys
import time
from xml.etree import ElementTree
from xml.etree.ElementTree import Element

import requests
import urllib3
from pyexpat import ErrorString


class CspcApi:
    """XML API Client Class for CSPC"""

    xml_request_dir = os.path.join(os.path.realpath(os.path.dirname(__file__)), "xml_requests")

    ElementTree.register_namespace("", "http://www.parinetworks.com/api/schemas/1.1")

    def __init__(self, host, user, pwd, verify, port=8001):
        """

        Args:
            host (str): IP or hostname (without https://) of CSPC
            user (str): Username for ers API
            password (str): Password for ers API user
            verify (bool): enable / disable certificate check for requests to CSPC.
        """

        self.logger = logging.getLogger("CspcApi")
        self.host = host + ":" + str(port)
        self.user = user
        self.password = pwd
        self.creds = ":".join([self.user, self.password])
        self.encoded_auth = base64.b64encode(self.creds.encode("utf-8"))

        if not verify:
            urllib3.disable_warnings()

        self.headers = {
            # 'accept': 'application/xml',
            "Authorization": " ".join(["Basic", self.encoded_auth.decode("utf-8")]),
            "cache-control": "no-cache",
        }
        self.kwargs = {"verify": verify, "headers": self.headers}

    def _info(self):
        """Performs get request to the CSPC info API endpoint

        Returns:
            str: response body of CSPC get /cspc/info
        """
        link = "https://" + self.host + "/cspc/info"

        self.logger.debug("GET " + link + "\nRequest Headers: " + str(self.headers))
        response = requests.get(link, **self.kwargs)
        response_headers = response.headers
        self.logger.debug("Response Headers:\n" + str(response_headers))
        body = response.text
        self.logger.debug("Response Body:\n" + body)
        return body

    def _xml(self, payload):
        """Performs POST xml request to CSPC

        Args:
            payload (str): string, use _get_xml_payload() to load content from `xml_request_dir`

        Returns:
            str: body of the CSPC response, usually an xml string

        Example:
            Parse the body with ElementTree (from xml.etree import ElementTree) to proceed::

                payload = self._get_xml_payload('get_details_of_all_devices.xml')
                all_devices = self._xml(payload)
                tree = ElementTree.fromstring(all_devices)
        """
        link = "https://" + self.host + "/cspc/xml"

        self.logger.debug(
            "POST " + link + "\nRequest Headers: " + str(self.headers) + "\nRequest Body: " + str(payload)
        )
        response = requests.post(link, payload, **self.kwargs)
        response_headers = response.headers
        body = response.text
        self.logger.debug("Response Headers:\n" + str(response_headers))
        self.logger.debug("Response Body:\n" + body)
        if response.status_code != 200:
            raise RuntimeError(response)
        return body

    @staticmethod
    def _to_dict(xml_elem, parents_children=None) -> dict:
        """Recursively Converts an xml element tree to a dictionary.

        Each xml element is converted to a dict as follows::

            {
                "TagName" : {
                    "attributes": {}
                    "text": "Actual Text Content"
                    "children": [
                        # repeat same structure
                    ]
                }
            }

        Args:
            xml_element (xml.Element):
            parents_children: only needed during recursion

        Returns
            dict
        """
        # convert current elem to dict
        xml_elem_dict = {
            xml_elem.tag: {
                "attributes": xml_elem.attrib,
                "text": xml_elem.text,
                "children": [],
            }
        }

        # if there is no parent, we are the root
        result_dict = None
        if parents_children is None:
            result_dict = xml_elem_dict

        # append current elem to list of children of parent elem
        if parents_children is not None:
            parents_children.append(xml_elem_dict)

        # loop through all element children
        for elem in xml_elem:
            CspcApi._to_dict(elem, xml_elem_dict[xml_elem.tag]["children"])

        return result_dict

    @staticmethod
    def response_as_dict(api_response_text) -> dict:
        """Converts the response text (usually xml) to a dict"""
        tree = ElementTree.fromstring(api_response_text)
        return CspcApi._to_dict(tree)

    @staticmethod
    def get_in_dict(response_dict, *args) -> str:
        """_summary_

        Args:
            response_dict (dict): _description_

        Returns:
            str: None if not found, or the string.
        """
        if len(args) == 1:
            return response_dict[args[0]]["text"]

        # Else recurse
        children = response_dict[args[0]]["children"]
        for child in children:
            if args[1] in child:
                result = CspcApi.get_in_dict(child, *args[1:])
                if result is not None:
                    return result
                # else continue in next child

        # raise if we cannot find the next key
        raise KeyError(f"'{args[1]}' not found in {children}")

    def _get_xml_payload(self, request_name):
        """Loads the full/skeleton xml request from an example file

        Args:
            payload (str): xml file in the `xml_request_dir`

        Returns:
            str: xml from file string
        """
        path = os.path.join(CspcApi.xml_request_dir, request_name)
        with open(path, "r", encoding="utf-8") as f:
            payload = f.read()
        return payload

    def _get_xml_elem(self, path, elem_tree):
        """Search in a loaded XML for a specific subtree tag

        This assumes namespace  {"ns": "http://www.parinetworks.com/api/schemas/1.1"}
        and search by .//ns:<path>

        Args:
            path (str): tag name to search for
            elem_tree (xml.etree.ElementTree) : tree to search

        Returns:
            xml.etree.Element: first element matched by tagname
        """
        # https://docs.python.org/3/library/xml.etree.elementtree.html
        # xml library will prefix all elements with their NS from a parsed file.
        ns = {"ns": "http://www.parinetworks.com/api/schemas/1.1"}
        return elem_tree.find(f".//ns:{path}", namespaces=ns)

    def send_and_import_seed_file_csv(self, csv, device_group_name):
        """upload seedfile to CSPC

        Args:
            csv (str): csv formatted list of devices to add
            device_group_name (str): can be empty string

        Returns:
            str: body of the CSPC response
        """
        seed_file_name = f'{device_group_name}-{time.strftime("%Y%m%d-%H%M%S")}.csv'
        xmlrequest = f"""
        <Request>
            <Job>
                <Schedule operationId="1">
                <JobSchedule runnow="true"/>
                <ImportSeedFileJob jobName="testimport">
                    <Description>Import SeedFile Job </Description>
                    <DeviceGroup>{device_group_name}</DeviceGroup>
                    <SeedFileDescr>cnc seed file</SeedFileDescr>
                    <SeedFileFormat>CISCO_CNC_CSV</SeedFileFormat>
                    <FileDetails>
                    <SeedFileName>{seed_file_name}</SeedFileName>
                    </FileDetails>
                    <TriggerDiscovery>true</TriggerDiscovery>
                    <TriggerDav>false</TriggerDav>
                </ImportSeedFileJob>
                </Schedule>
            </Job>
        </Request>
        """

        link = "https://" + self.host + "/cspc/seedfile"

        files = {"request": (None, xmlrequest.encode("utf8")), "file": (seed_file_name, csv.encode("utf8"))}

        response = requests.post(link, files=files, headers=self.headers, verify=False)

        self.logger.debug("POST " + link + "\nRequest Headers: " + str(self.headers) + "\nRequest Body: " + str(files))

        response_headers = response.headers
        self.logger.debug("Response Headers:\n" + str(response_headers))
        body = response.text
        self.logger.debug("Response Body:\n" + body)

        return body

    def get_devices(self) -> list[Element]:
        """Returns all registered devices as list of xml Elementes

        Returns:
            list: of XML Elements

        Example:
        ```
            <Device>
                <Id>31591</Id>
                <HostName>switch1</HostName>
                <IPAddress>172.16.2.112</IPAddress>
                <Status>Reachable</Status>
                <DeviceFamily>LANSwitches</DeviceFamily>
                <ProductFamily><![CDATA[Cisco Catalyst 2960-S Series Switches]]></ProductFamily>
                <Model>cat29xxStack</Model>
                <SerialNumber>S/N discovery disabled</SerialNumber>
                <Vendor>Cisco Systems Inc.</Vendor>
                <OS>IOS</OS>
                <Version>15.2(4)E7</Version>
                <Image></Image>
                <DiscTime>1600812032000</DiscTime>
                <InvTime>1600812032634</InvTime>
                <SysObjectId>.1.3.6.1.4.1.9.1.1208</SysObjectId>
                <SysLocation><![CDATA[Company1 3rd Floor]]></SysLocation>
                <SysDescription><![CDATA[Cisco IOS Software, C2960X Software (C2960X-UNIVERSALK9-M), Version 15.2(4)E7, RELEASE SOFTWARE (fc2)  Technical Support: http://www.cisco.com/techsupport  Copyright (c) 1986-2018 by Cisco Systems, Inc.  Compiled Tue 18-Sep-18 13:07 by prod_rel_team]]></SysDescription>
                <DomainName>infra.example.com</DomainName>
                <DeviceSource>10.0.0.10</DeviceSource>
                <PrimaryDeviceName><![CDATA[switch1.infra.example.com]]></PrimaryDeviceName>
                <SysName><![CDATA[switch1.infra.example.com]]></SysName>
            </Device>
        ```
        """
        all_devices = self._xml(self._get_xml_payload("get_details_of_all_devices.xml"))
        tree = ElementTree.fromstring(all_devices)
        devices = tree.findall(".//Device")

        self.logger.info("num devices: " + str(len(devices)))

        return devices

    def get_devices_as_dict(self):
        """Returns all registered devices as list of python dictionaries

        Returns:
            list: of dicts,  see :func: `<get_devices>`  for possible dict keys

        """
        devices = self.get_devices()
        list_of_dict = []
        for device_elem in devices:
            device_dict = {}
            for elem in device_elem:
                device_dict[elem.tag] = elem.text
            list_of_dict.append(device_dict)

        return list_of_dict

    def get_unreachable_devices(self):
        """returns an array of dict with unreachable devices

        Returns:
            list: of device dictionariers with keys: Id, HostName, IPAddress, Status
        """
        devices = self.get_devices()

        self.logger.info("num devices: " + str(len(devices)))
        unreachable_devices = []
        for elem in devices:
            if elem.findtext("Status").lower() != "reachable":
                dev_dict = {
                    "Id": str(elem.findtext("Id")),
                    "HostName": str(elem.findtext("HostName")),
                    "IPAddress": str(elem.findtext("IPAddress")),
                    "Status": str(elem.findtext("Status")),
                }
                unreachable_devices.append(dev_dict)
                # print(dev_dict)
        return unreachable_devices

    def get_devices_by(self, key, value):
        """returns an array of dict with devices where the text attribute of the key element matches (case-sensitive)
        the given value with python 'in' operator

        i.e. if value in device<key>...

        For list of possible keys see #get_devices

        Args:
            key (str): tag name to match
            value (str):  tag contents to match against

        Returns:
            list: of device dictionariers with all keys from #get_devices

        Example:
        ```
            # find all devices having 1.2.3. in their IP address
            my_devices = cspc.get_devices_by('IPAddress', '1.2.3.')
        ```
        """
        devices = self.get_devices()

        self.logger.info("num devices: " + str(len(devices)))
        matched_devices = []
        for device in devices:
            if value in device.findtext(key):
                device_dict = {}
                for child in device:
                    device_dict[child.tag] = str(device.findtext(child.tag))
                matched_devices.append(device_dict)
        return matched_devices

    def _add_elem_with_text(self, tag, text, parent):
        d = ElementTree.Element(tag)
        d.text = text
        parent.append(d)
        return d

    def add_multiple_device_credentials_snmpv2c(self, credentials):
        """Adds snmpv2c credentials for multiple devices by IP expression

        Args:
            credentials (dict): key = credential_name, value = dict(ip_expression=, snmp_read_community=, snmp_write_community=)

        Returns:
            str: Response of CSPC

        Example:
            This is an example payload for snmp or telnet credentials:
            ```<DeviceCredential identifier="My_snmpv1_1">
                <Protocol>snmpv1</Protocol>
                <WriteCommunity>private</WriteCommunity>
                <IpExpressionList>
                    <IpExpression>*.*.*.*</IpExpression>
                </IpExpressionList>
                <ExcludeIpExprList>
                    <IpExpression>192.168.*.*IpExpression>
                </ExcludeIpExprList>
            </DeviceCredential>
            <DeviceCredential identifier="My_telnet_1">
                <Protocol>telnet</Protocol>
                <UserName>admin</UserName>
                <Password>admin</Password>
                <EnableUserName>testuser</EnableUserName>
                <EnablePassword>testpass</EnablePassword>
                <IpExpressionList>
                    <IpExpression>*.*.*.*</IpExpression>
                    <IpExpression>FE80::0009</IpExpression>
                </IpExpressionList>
                <ExcludeIpExprList>
                    <IpExpression>192.168.0.*</IpExpression>
                </ExcludeIpExprList>
            </DeviceCredential>
            ```
        """
        tree = ElementTree.fromstring(self._get_xml_payload("add_multiple_device_credentials.xml"))

        cred_list = self._get_xml_elem("DeviceCredentialList", tree)
        for cred_name, creds in credentials.items():
            # SNMPv2c credential
            device_credential = ElementTree.Element("DeviceCredential", identifier=cred_name)
            self._add_elem_with_text("Protocol", "snmpv2c", device_credential)
            self._add_elem_with_text("ReadCommunity", creds["snmp_read_community"], device_credential)
            self._add_elem_with_text("WriteCommunity", creds["snmp_write_community"], device_credential)
            ip_expr = ElementTree.Element("IpExpressionList")
            self._add_elem_with_text("IpExpression", creds["ip_expression"], ip_expr)
            device_credential.append(ip_expr)
            cred_list.append(device_credential)

        return self._xml(ElementTree.tostring(tree, encoding="unicode"))

    def add_multiple_device_credentials_ssh(self, credentials):
        """Adds sshv2 credentials for multiple devices by IP expression

        Args:
            credentials (dict): key = credential_name, value = dict(ip_expression=, user=, password=, enable_password=)

        Returns:
            str: Response of CSPC

        Example:
            This is an example payload for snmp or telnet credentials:
            ```<DeviceCredential identifier="My_snmpv1_1">
                <Protocol>snmpv1</Protocol>
                <WriteCommunity>private</WriteCommunity>
                <IpExpressionList>
                    <IpExpression>*.*.*.*</IpExpression>
                </IpExpressionList>
                <ExcludeIpExprList>
                    <IpExpression>192.168.*.*IpExpression>
                </ExcludeIpExprList>
            </DeviceCredential>
            <DeviceCredential identifier="My_telnet_1">
                <Protocol>telnet</Protocol>
                <UserName>admin</UserName>
                <Password>admin</Password>
                <EnableUserName>testuser</EnableUserName>
                <EnablePassword>testpass</EnablePassword>
                <IpExpressionList>
                    <IpExpression>*.*.*.*</IpExpression>
                    <IpExpression>FE80::0009</IpExpression>
                </IpExpressionList>
                <ExcludeIpExprList>
                    <IpExpression>192.168.0.*</IpExpression>
                </ExcludeIpExprList>
            </DeviceCredential>
            ```
        """
        tree = ElementTree.fromstring(self._get_xml_payload("add_multiple_device_credentials.xml"))

        cred_list = self._get_xml_elem("DeviceCredentialList", tree)
        for cred_name, creds in credentials.items():
            # SSHv2 credential
            device_credential = ElementTree.Element("DeviceCredential", identifier=cred_name)
            self._add_elem_with_text("Protocol", "sshv2", device_credential)
            self._add_elem_with_text("UserName", creds["user"], device_credential)
            self._add_elem_with_text("Password", creds["password"], device_credential)
            self._add_elem_with_text("EnablePassword", creds["enable_password"], device_credential)
            ip_expr = ElementTree.Element("IpExpressionList")
            self._add_elem_with_text("IpExpression", creds["ip_expression"], ip_expr)
            device_credential.append(ip_expr)
            cred_list.append(device_credential)

        return self._xml(ElementTree.tostring(tree, encoding="unicode"))

    def add_multiple_devices(self, devices):
        """Adds multiple devices to CSPC.

        Note: By default the IP Address is chosen as PrimaryDeviceName. PrimaryDeviceName is used
        as 'Hostname' key by other Cisco Tools (SNTC, BCS). So if you need Hostname or FQDN name in
        those tools, please specify the PrimaryDeviceName.

        Args:
            devices (list<dict>): list of device dictionaries. For valid keys see :func: `<get_devices>`
            at minimum IPAddress is required.

        Returns:
            str: Response of CSPC

        See also: examples/add_devices_and_credentials.py
        """
        tree = ElementTree.fromstring(self._get_xml_payload("add_multiple_devices.xml"))
        device_list = self._get_xml_elem("DeviceList", tree)
        for device in devices:
            elem = ElementTree.Element("Device")
            for tag, value in device.items():
                d = ElementTree.Element(tag)
                d.text = value
                elem.append(d)

            device_list.append(elem)

        return self._xml(ElementTree.tostring(tree, encoding="unicode"))

    def modify_multiple_devices(self, devices):
        """Modifies multiple devices

        Args:
            devices (list<dict>): list of device dictionaries. For valid keys see :func: `<get_devices>`
            at minimum IPAddress is required.

        Returns:
            str: Response of CSPC
        """
        tree = ElementTree.fromstring(self._get_xml_payload("modify_multiple_devices.xml"))
        device_list = self._get_xml_elem("DeviceList", tree)
        for device in devices:
            elem = ElementTree.Element("Device")
            for tag, value in device.items():
                d = ElementTree.Element(tag)
                d.text = value
                elem.append(d)

            device_list.append(elem)

        return self._xml(ElementTree.tostring(tree, encoding="unicode"))

    def delete_multiple_devices(self, device_array):
        """Deletes multiple devices by ID from CSPC

        Args:
            device_array (list): list of dictionaries, as returned by :func: `<unreachable_devices>` or
                                 :func: `<get_devices_as_dict>`. Each dict needs at least an 'Id' key.

        Returns:
            str: Response of CSPC
        """
        tree = ElementTree.fromstring(self._get_xml_payload("delete_multiple_devices.xml"))
        device_list = self._get_xml_elem("DeviceList", tree)
        for dev in device_array:
            elem = ElementTree.Element("Device")
            d = ElementTree.Element("Id")
            d.text = dev["Id"]
            elem.append(d)
            device_list.append(elem)

        return self._xml(ElementTree.tostring(tree, encoding="unicode"))

    def discovery_by_ip(self, device_array, protocol_list=["snmpv2c"]):  # pylint: disable=dangerous-default-value
        """Discovers multiple devices by IP address and tries given list of protocols.

        Note: discovery can take a long time. E.g. 5k devices will take up to 50 minutes.
        You might want to poll the discovery job for state == Completed.

        Args:
            device_array (list): list of dictionaries, as returned by :func: `<get_devices_as_dict>`.
                                 Each dict needs at least an 'IPAddress' key.
            protocol_list (list):
        Returns:
            str: Response of CSPC
        """
        tree = ElementTree.fromstring(self._get_xml_payload("discovery_by_ip.xml"))
        discovery_job = self._get_xml_elem("DiscoveryJob", tree)
        # make sure discoveryjob has a unique identifier by appending current time in ms.
        discovery_job.set("identifier", f"XmlApiDiscovery{int(time.time()*1000)}")
        ip_address_list = self._get_xml_elem("IPAddressList", tree)
        for dev in device_array:
            elem = ElementTree.Element("IPAddress")
            elem.text = dev["IPAddress"]
            ip_address_list.append(elem)

        for discovery_proto in protocol_list:
            proto_list = self._get_xml_elem("MgmtProtocolList", tree)
            elem = ElementTree.Element("MgmtProtocol")
            elem.text = discovery_proto
            proto_list.append(elem)
            proto_list = self._get_xml_elem("DAVProtocolList", tree)
            elem = ElementTree.Element("DAVProtocol")
            elem.text = discovery_proto
            proto_list.append(elem)

        return self._xml(ElementTree.tostring(tree, encoding="unicode"))

    def get_job_list(self):
        """Returns job details of all jobs

        Args:
            job_id (int): the CSPC job id, e.g. as in the response of :func: `<discovery_by_ip_and_snmp>`.
        Returns:
            str: Response of CSPC
        Example::

            <Response requestId="3333">
                <Status code='SUCCESSFUL' />
                <Job>
                    <GetJobList operationId="1" >
                        <Status code="SUCCESSFUL"/>
                        <JobDetailList>
                            <JobDetail>
                                <JobId>7</JobId><JobName>XmlApiDiscovery1649670162478</JobName>
                                <JobGroup>RunNowDiscoveryJobGrp</JobGroup><Description>XmlApiDiscovery1649670162478</Description>
                                <CreatedBy>admin</CreatedBy><CreatedOn>1649670171000</CreatedOn>
                                <FirstRunTime>1649670163457</FirstRunTime>
                                <LastStartTime>1649670163457</LastStartTime><LastRunTime>1649670171623</LastRunTime>
                                <NextScheduleTime></NextScheduleTime><RunCount>1</RunCount>
                                <ServiceName></ServiceName><Schedule runnow="true"></Schedule>
                            </JobDetail>
                            <JobDetail>
                              ...
                            </JobDetail>
                        </JobDetailList>
                    </GetJobList>
                </Job>
            </Response>
        """
        tree = ElementTree.fromstring(self._get_xml_payload("get_job_list_all.xml"))
        # job_list = self._get_xml_elem("GetJobList", tree)
        return self._xml(ElementTree.tostring(tree, encoding="unicode"))

    def get_job_by_id(self, job_id):
        """Returns job details

        Args:
            job_id (int): the CSPC job id, e.g. as in the response of :func: `<discovery_by_ip_and_snmp>`.
        Returns:
            str: Response of CSPC
        Example::

            <Response requestId="3333">
                <Status code='SUCCESSFUL' />
                <Job>
                    <GetJobList operationId="1" >
                        <Status code="SUCCESSFUL"/>
                        <JobDetailList>
                            <JobDetail>
                                <JobId>7</JobId><JobName>XmlApiDiscovery1649670162478</JobName>
                                <JobGroup>RunNowDiscoveryJobGrp</JobGroup><Description>XmlApiDiscovery1649670162478</Description>
                                <CreatedBy>admin</CreatedBy><CreatedOn>1649670171000</CreatedOn>
                                <FirstRunTime>1649670163457</FirstRunTime>
                                <LastStartTime>1649670163457</LastStartTime><LastRunTime>1649670171623</LastRunTime>
                                <NextScheduleTime></NextScheduleTime><RunCount>1</RunCount>
                                <ServiceName></ServiceName><Schedule runnow="true"></Schedule>
                            </JobDetail>
                        </JobDetailList>
                    </GetJobList>
                </Job>
            </Response>
        """
        tree = ElementTree.fromstring(self._get_xml_payload("get_job_list.xml"))
        job_list = self._get_xml_elem("GetJobList", tree)
        elem = ElementTree.Element("JobId")
        elem.text = str(job_id)
        job_list.append(elem)
        return self._xml(ElementTree.tostring(tree, encoding="unicode"))

    def get_job_status(self, job_id, run_id):
        """Returns the status of a job

        Args:
            job_id (int): the CSPC job id, e.g. as in the response of :func: `<discovery_by_ip_and_snmp>`.
            run_id (int): the CSPC job id, e.g. as in the response of :func: `<get_job_by_id>`.

        Returns:
            str: Response of CSPC

        Example::

            <Response requestId="3333">
                <Status code='SUCCESSFUL' />
                <Job>
                    <GetStatus operationId="1" >
                        <Status code="SUCCESSFUL"/>
                        <JobRunDetailList>
                            <JobRunDetail>
                                <State>Completed</State><Status>Success</Status>
                                <StartTime>1643028300458</StartTime><EndTime>1643028301375</EndTime>
                            </JobRunDetail>
                        </JobRunDetailList>
                    </GetStatus>
                </Job>
            </Response>
        """
        tree = ElementTree.fromstring(self._get_xml_payload("get_job_status.xml"))
        job_list = self._get_xml_elem("GetStatus", tree)
        elem = ElementTree.Element("JobId")
        elem.text = str(job_id)
        job_list.append(elem)
        elem = ElementTree.Element("JobRunId")
        elem.text = str(run_id)
        job_list.append(elem)
        return self._xml(ElementTree.tostring(tree, encoding="unicode"))

    def get_formatted_csv_device_entry(
        self, ipaddress, hostname="", username="", password="", enable_password="", snmp_v2_RO="", snmp_v2_RW=""
    ):
        """
        Returns:
            str: single line of csv including trailing newline '\\n'

        """
        col1_IP_Address_including_domain_or_simply_an_IP = ipaddress
        col2_Host_Name = hostname
        col3_Domain_Name = ""
        col4_Device_Identity = ""
        col5_Display_Name = ""
        col6_SysObjectID = ""
        col7_DCR_Device_Type = ""
        col8_MDF_Type = ""
        col9_Snmp_RO = snmp_v2_RO
        col10_Snmp_RW = snmp_v2_RW
        col11_SnmpV3_User_Name = ""  # TODO
        col12_Snmp_V3_Auth_Pass = ""  # TODO
        col13_Snmp_V3_Engine_ID = ""  # TODO
        col14_Snmp_V3_Auth_Algorithm = ""  # TODO
        col15_RX_Boot_Mode_User = ""
        col16_RX_Boot_Mode_Pass = ""
        col17_Primary_User_Tacacs_User = username
        col18_Primary_Pass_Tacacs_Pass = password
        col19_Primary_Enable_Pass = enable_password
        col20_Http_User = ""  # TODO
        col21_Http_Pass = ""  # TODO
        col22_Http_Mode = ""  # TODO
        col23_Http_Port = ""  # TODO
        col24_Https_Port = ""  # TODO
        col25_Cert_Common_Name = ""
        col26_Secondary_User = ""
        col27_Secondary_Pass = ""
        col28_Secondary_Enable_Pass = ""
        col29_Secondary_Http_User = ""
        col30_Secondary_Http_Pass = ""
        col31_Snmp_V3_Priv_Algorithm = ""  # TODO
        col32_Snmp_V3_Priv_Pass = ""  # TODO
        col33_User_Field_1 = ""
        col34_User_Field_2 = ""
        col35_User_Field_3 = ""
        col36_User_Field_4 = ""

        return f"{col1_IP_Address_including_domain_or_simply_an_IP},{col2_Host_Name},{col3_Domain_Name},{col4_Device_Identity},{col5_Display_Name},{col6_SysObjectID},{col7_DCR_Device_Type},{col8_MDF_Type},{col9_Snmp_RO},{col10_Snmp_RW},{col11_SnmpV3_User_Name},{col12_Snmp_V3_Auth_Pass},{col13_Snmp_V3_Engine_ID},{col14_Snmp_V3_Auth_Algorithm},{col15_RX_Boot_Mode_User},{col16_RX_Boot_Mode_Pass},{col17_Primary_User_Tacacs_User},{col18_Primary_Pass_Tacacs_Pass},{col19_Primary_Enable_Pass},{col20_Http_User},{col21_Http_Pass},{col22_Http_Mode},{col23_Http_Port},{col24_Https_Port},{col25_Cert_Common_Name},{col26_Secondary_User},{col27_Secondary_Pass},{col28_Secondary_Enable_Pass},{col29_Secondary_Http_User},{col30_Secondary_Http_Pass},{col31_Snmp_V3_Priv_Algorithm},{col32_Snmp_V3_Priv_Pass},{col33_User_Field_1},{col34_User_Field_2},{col35_User_Field_3},{col36_User_Field_4}\n"


def _setup_logging():
    fmt = "%(asctime)s %(name)10s %(levelname)8s: %(message)s"
    # logfile='cspc.log'
    logfile = None
    logging.basicConfig(format=fmt, level=logging.INFO, datefmt="%H:%M:%S", filename=logfile)


if __name__ == "__main__":
    _setup_logging()
    if "CSPC_USER" not in os.environ or "CSPC_PASSWORD" not in os.environ:
        exit("make sure environment variables `CSPC_USER` and `CSPC_PASSWORD` are defined")
    if len(sys.argv) != 2:
        exit(f"usage: ./{sys.argv[0]} CSPC_IP")

    c = CspcApi(f"{sys.argv[1]}:8001", os.environ.get("CSPC_USER"), os.environ.get("CSPC_PASSWORD"), verify=False)
    c._info()
    # print(os.path.realpath(__file__))
    u = c.get_unreachable_devices()
