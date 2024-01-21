import csv


class CXCloudAgent:
    """Utility functions for CX Coud Agent"""

    # https://www.cisco.com/c/dam/en/us/support/docs/cloud-systems-management/cx-cloud-agent/seed-file-template.pdf
    # https://www.cisco.com/c/en/us/support/docs/cloud-systems-management/cx-cloud-agent/218316-cx-cloud-agent-overview-v2-2.html#toc-hId-1815861778
    SEED_FILE_COLUMNS = [
        "ip_or_hostname",     # A ip or hostname
        "snmp_version",       # B snmpv2c or snmpv3
        "snmpv2c_community",  # C
        "snmpv3_user",        # D
        "snmpv3_auth_algo",   # E MD5 or SHA
        "snmpv3_auth_pw",     # F
        "snmpv3_priv_algo",   # G DES, 3DES, AES-128, AES-192, AES-256
        "snmpv3_priv_pw",     # H
        "snmpv3_engine_id",   # I  optional
        "cli_protocol",       # J telnet, sshv1, sshv2
        "cli_port",           # K port number, e.g. 22 for ssh
        "cli_user",           # L
        "cli_pw",             # M
        "cli_enable_user",    # N
        "cli_enable_pw",      # O
        "reserved1",          # P future use
        "reserved2",          # Q future use
        "reserved3",          # R future use
        "reserved4",          # S future use
    ]

    def cscp_device_to_cxagent_seed_csv(device):
        pass

    def device_to_csv(device_dict, filename):
        """Refer to SEED_FILE_COLUMNS
        """

        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(device_dict.keys())
            writer.writerow(device_dict.values())