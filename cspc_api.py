#!/usr/bin/env python
# -*- coding: utf-8 -*-

import base64
import ssl
import http.client
import logging
import os
import sys
import time
from xml.etree import ElementTree
import requests

class CspcApi:

    xml_request_dir = os.path.join(os.path.realpath(os.path.dirname(__file__)), 'xml_requests')

    def __init__(self, host, user, pwd):

        self.logger = logging.getLogger('CspcApi')
        self.host = host
        self.endpoint = 'https://{}:8001/cspc/xml'.format(host)
        self.user = user
        self.password = pwd
        self.creds = ':'.join([self.user, self.password])
        self.encodedAuth = base64.b64encode(self.creds.encode('utf-8'))

        self.headers = {
            #'accept': 'application/xml',
            'Authorization': ' '.join(['Basic', self.encodedAuth.decode('utf-8')]),
            'cache-control': 'no-cache',
        }

    def _info(self):
        """Performs get request to the CSPC info API endpoint

        Returns:
            str: response body of CSPC get /cspc/info 
        """
        link = '/cspc/info'
        conn = http.client.HTTPSConnection(self.host, context=ssl.SSLContext(ssl.PROTOCOL_TLSv1_2))
        conn.request('GET', link, headers=self.headers)
        self.logger.debug('GET https://' + conn.host + ':' + str(conn.port) + link + '\nRequest Headers: ' + str(self.headers))
        response = conn.getresponse()
        response_headers = response.info()
        self.logger.debug('Response Headers:\n' + str(response_headers))
        body = response.read().decode('utf-8')
        self.logger.debug('Response Body:\n' + body)
        return body


    def _xml(self, request_name):
        """ Performs POST xml request to CSPC

        Args:
            request_name (str): name of an xml file in the `xml_request_dir`

        Returns:
            str: body of the CSPC response, usually an xml string

        Example:
            # Parse the body with ElementTree (from xml.etree import ElementTree) to proceed:
            all_devices = self._xml('get_details_of_all_devices.xml')
            tree = ElementTree.fromstring(all_devices)
        """
        path = os.path.join(CspcApi.xml_request_dir, request_name)
        with open(path, 'r') as f:
            payload = f.read()
        link = '/cspc/xml'
        conn = http.client.HTTPSConnection(self.host, context=ssl.SSLContext(ssl.PROTOCOL_TLSv1_2))
        conn.request('POST', link, headers=self.headers, body=payload)
        self.logger.debug('POST https://' + conn.host + ':' + str(conn.port) + link +
            '\nRequest Headers: ' + str(self.headers) +
            '\nRequest Body: ' + str(payload))
        response = conn.getresponse()
        response_headers = response.info()
        self.logger.debug('Response Headers:\n' + str(response_headers))
        body = response.read().decode('utf-8')
        self.logger.debug('Response Body:\n' + body)
        return body



    def send_and_import_seed_file_csv(self, csv, device_group_name):
        """ upload seedfile to CSPC

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


        link = 'https://' + self.host + '/cspc/seedfile'

        files = {'request': (None, xmlrequest.encode('utf8')), 'file': (seed_file_name, csv.encode('utf8'))}

        response = requests.post(link, files=files, headers=self.headers, verify=False)

        self.logger.debug('POST '+ link +
            '\nRequest Headers: ' + str(self.headers) +
                          '\nRequest Body: ' + str(files))

        response_headers =response.headers
        self.logger.debug('Response Headers:\n' + str(response_headers))
        body = response.text
        self.logger.debug('Response Body:\n' + body)

        return body




    def get_devices(self):
        """returns an array of dict with all registered devices
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
        all_devices = self._xml('get_details_of_all_devices.xml')
        tree = ElementTree.fromstring(all_devices)
        devices = tree.findall('.//Device')

        self.logger.info('num devices: ' + str(len(devices)))

        return devices


    def get_unreachable_devices(self):
        """returns an array of dict with unreachable devices

        Returns:
            list: of device dictionariers with keys: Id, HostName, IPAddress, Status 
        """
        devices = self.get_devices()

        self.logger.info('num devices: ' + str(len(devices)))
        unreachable_devices = []
        for elem in devices:
            if elem.findtext('Status').lower() != 'reachable':
                dev_dict = {
                    'Id': str(elem.findtext('Id')),
                    'HostName': str(elem.findtext('HostName')),
                    'IPAddress': str(elem.findtext('IPAddress')),
                    'Status': str(elem.findtext('Status'))
                }
                unreachable_devices.append(dev_dict)
                #print(dev_dict)
        return unreachable_devices


    def delete_multiple_devices(self, device_array):
        """ Deletes multiple devices by ID from CSPC

        Args:
            device_array (list): list of hashes, as returned by :func: `<unreachable_devices>`

        Returns:
            str: Response of CSPC
        """

        namespaces = {
            'ns' : 'http://www.parinetworks.com/api/schemas/1.1'
        }
        #  xmlns="http://www.parinetworks.com/api/schemas/1.1"
        payload = """<Request requestId="">
  <Manage>
    <Delete operationId="1">
      <DeviceList>
      </DeviceList>
    </Delete>
  </Manage>
</Request>"""
        tree = ElementTree.fromstring(payload)
        device_list = tree.find('.//DeviceList', namespaces=namespaces)
        for dev in device_array:
            elem = ElementTree.Element('Device')
            d = ElementTree.Element('Id')
            d.text = dev['Id']
            elem.append(d)
            device_list.append(elem)

        with open(os.path.join(CspcApi.xml_request_dir, 'delete_multiple_devices.xml'), 'w') as f:
            f.write(ElementTree.tostring(tree, encoding='unicode'))

        #return "noop"
        return self._xml('delete_multiple_devices.xml')


    def get_formatted_csv_device_entry(self, ipaddress, hostname='', username ='', password='', enable_password='', snmp_v2_RO ='', snmp_v2_RW =''):
        """
        Returns:
            str: single line of csv including trailing newline '\\n'

        """
        col1_IP_Address_including_domain_or_simply_an_IP = ipaddress
        col2_Host_Name = hostname
        col3_Domain_Name = ''
        col4_Device_Identity = ''
        col5_Display_Name = ''
        col6_SysObjectID = ''
        col7_DCR_Device_Type = ''
        col8_MDF_Type = ''
        col9_Snmp_RO = snmp_v2_RO
        col10_Snmp_RW = snmp_v2_RW
        col11_SnmpV3_User_Name = '' #TODO
        col12_Snmp_V3_Auth_Pass = '' #TODO
        col13_Snmp_V3_Engine_ID = '' #TODO
        col14_Snmp_V3_Auth_Algorithm = '' #TODO
        col15_RX_Boot_Mode_User = ''
        col16_RX_Boot_Mode_Pass = ''
        col17_Primary_User_Tacacs_User = username
        col18_Primary_Pass_Tacacs_Pass = password
        col19_Primary_Enable_Pass = enable_password
        col20_Http_User = '' #TODO
        col21_Http_Pass = '' #TODO
        col22_Http_Mode = '' #TODO
        col23_Http_Port = '' #TODO
        col24_Https_Port = '' #TODO
        col25_Cert_Common_Name = ''
        col26_Secondary_User = ''
        col27_Secondary_Pass = ''
        col28_Secondary_Enable_Pass = ''
        col29_Secondary_Http_User = ''
        col30_Secondary_Http_Pass = ''
        col31_Snmp_V3_Priv_Algorithm = ''#TODO
        col32_Snmp_V3_Priv_Pass = ''#TODO
        col33_User_Field_1 = ''
        col34_User_Field_2 = ''
        col35_User_Field_3 = ''
        col36_User_Field_4 = ''

        return f'{col1_IP_Address_including_domain_or_simply_an_IP},{col2_Host_Name},{col3_Domain_Name},{col4_Device_Identity},{col5_Display_Name},{col6_SysObjectID},{col7_DCR_Device_Type},{col8_MDF_Type},{col9_Snmp_RO},{col10_Snmp_RW},{col11_SnmpV3_User_Name},{col12_Snmp_V3_Auth_Pass},{col13_Snmp_V3_Engine_ID},{col14_Snmp_V3_Auth_Algorithm},{col15_RX_Boot_Mode_User},{col16_RX_Boot_Mode_Pass},{col17_Primary_User_Tacacs_User},{col18_Primary_Pass_Tacacs_Pass},{col19_Primary_Enable_Pass},{col20_Http_User},{col21_Http_Pass},{col22_Http_Mode},{col23_Http_Port},{col24_Https_Port},{col25_Cert_Common_Name},{col26_Secondary_User},{col27_Secondary_Pass},{col28_Secondary_Enable_Pass},{col29_Secondary_Http_User},{col30_Secondary_Http_Pass},{col31_Snmp_V3_Priv_Algorithm},{col32_Snmp_V3_Priv_Pass},{col33_User_Field_1},{col34_User_Field_2},{col35_User_Field_3},{col36_User_Field_4}\n'



def _setup_logging():
    format = "%(asctime)s %(name)10s %(levelname)8s: %(message)s"
    # logfile='cspc.log'
    logfile=None
    logging.basicConfig(format=format, level=logging.INFO,
                        datefmt="%H:%M:%S", filename=logfile)


if __name__ == '__main__':
    _setup_logging()
    if 'CSPC_USER' not in os.environ or 'CSPC_PASSWORD' not in os.environ:
        exit('make sure environment variables `CSPC_USER` and `CSPC_PASSWORD` are defined')
    if len(sys.argv) != 2:
        exit(f'usage: ./{sys.argv[0]} CSPC_IP')

    c = CspcApi(f'{sys.argv[0]}:8001', os.environ.get('CSPC_USER'), os.environ.get('CSPC_PASSWORD'))
    c._info()
   # print(os.path.realpath(__file__))
    u = c.get_unreachable_devices()
