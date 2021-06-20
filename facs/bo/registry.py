from regipy.registry import RegistryHive
from facs.bo.abstract import AbstractBo


class RegistryBo(AbstractBo):
    CONNECTION_TYPES = {
        '6': 'wired',
        '23': 'VPN',
        '71': 'wireless',
        '243': 'mobile',
    }

    def get_profiling_from_registry(self, hive_system, hive_software):
        profiling = {}
        reg_system = RegistryHive(hive_system)
        reg_software = RegistryHive(hive_software)

        profiling['control_sets'] = self.__get_control_sets(reg_system)
        current_control_set = '\\ControlSet{:03d}'.format(profiling['control_sets']['current'])

        profiling['computer_name'] = self.__get_computer_name(reg_system, current_control_set)
        profiling['os'] = self.__get_operating_system(reg_software)
        profiling['time_zone'] = self.__get_timezone(reg_system, current_control_set)
        profiling['networks'] = self.__get_networks(reg_system, reg_software, current_control_set)

        # local users
        # usb
        return profiling

    def __get_control_sets(self, reg_system):
        key = reg_system.get_key('\\Select')
        values = {value.name: value.value for value in key.get_values()}

        return {
            'current': values['Current'],
            'last_known_good': values['LastKnownGood'],
            'available': reg_system.get_control_sets(''),
        }

    def __get_computer_name(self, reg_system, current_control_set):
        path = current_control_set + '\\Control\\ComputerName\\ComputerName'
        key = reg_system.get_key(path)
        values = {value.name: value.value for value in key.get_values()}

        return values['ComputerName']

    def __get_operating_system(self, reg_software):
        path = '\\Microsoft\\Windows NT\\CurrentVersion'
        key = reg_software.get_key(path)
        values = {value.name: value.value for value in key.get_values()}
        version = '{} Release {} Build {}'.format(values['ProductName'], values['ReleaseId'], values['CurrentBuild'])

        return {
            'version': version,
            'install_date': self._unixepoch_to_datetime(values['InstallDate']),
        }

    def __get_timezone(self, reg_system, current_control_set):
        path = current_control_set + '\\Control\\TimeZoneInformation'
        key = reg_system.get_key(path)
        values = {value.name: value.value for value in key.get_values()}

        return {
            'name': values['TimeZoneKeyName'],
            'active_time_bias': values['ActiveTimeBias'],
        }

    def __get_networks(self, reg_system, reg_software, current_control_set):
        networks = {
            'nics': [],
            'parameters': [],
            'connections': [],
        }

        # collect NIC
        path = '\\Microsoft\\Windows NT\\CurrentVersion\\NetworkCards'
        key = reg_software.get_key(path)
        for subkey in key.iter_subkeys():
            values = {value.name: value.value for value in subkey.get_values()}
            networks['nics'].append({
                'guid': values['ServiceName'],
                'description': values['Description'],
            })

        # collect last known parameters (IP, subnet, domain, DHCP, NS, ...)
        for nic in networks['nics']:
            path = current_control_set + '\\Services\\Tcpip\\Parameters\\Interfaces\\' + nic['guid'].lower()
            key = reg_system.get_key(path)

            # main key for a NIC
            parameters = self.__decode_tcpip_interface_key(nic, key)
            if parameters is not None:
                networks['parameters'].append(parameters)

            # subkeys for WiFi access points
            for subkey in key.iter_subkeys():
                subparameters = self.__decode_tcpip_interface_key(nic, subkey)
                if subparameters is not None:
                    networks['parameters'].append(subparameters)

        # collect connections
        parameters_indexed = {parameters['network_hint']: parameters for parameters in networks['parameters']}
        subkeys = ['Managed', 'Unmanaged']
        for sk in subkeys:
            path = '\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Signatures\\' + sk
            key = reg_software.get_key(path)
            for subkey in key.iter_subkeys():
                values_signature = {value.name: value.value for value in subkey.get_values()}
                profile = reg_software.get_key('\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Profiles\\' + values_signature['ProfileGuid'])
                values_profile = {value.name: value.value for value in profile.get_values()}

                # attempt to match an IP based on SSID
                ssid = values_profile['ProfileName']
                ip_first = None
                ip_last = None
                first_connected_at = self._systemtime_to_datetime(values_profile['DateCreated'])
                last_connected_at = self._systemtime_to_datetime(values_profile['DateLastConnected'])
                parameters = parameters_indexed.get(ssid)
                if parameters is not None:
                    lease_start = parameters['lease_start']
                    lease_end = parameters['lease_end']
                    if first_connected_at >= parameters['lease_start'] and first_connected_at <= parameters['lease_end']:
                        ip_first = parameters['ip']
                    if last_connected_at >= parameters['lease_start'] and last_connected_at <= parameters['lease_end']:
                        ip_last = parameters['ip']

                # record the connection
                networks['connections'].append({
                    'gateway_mac': bytes(values_signature['DefaultGatewayMac']).hex(),
                    'dns_suffix': values_signature['DnsSuffix'],
                    'ssid': ssid,
                    'profile_guid': values_signature['ProfileGuid'],
                    'connection_type': self.CONNECTION_TYPES[str(values_profile['NameType'])],
                    'first_connected_at': first_connected_at,
                    'last_connected_at': last_connected_at,
                    'ip_first': ip_first,
                    'ip_last': ip_last,
                })

        return networks

    def __decode_tcpip_interface_key(self, nic, key):
        values = {value.name: value.value for value in key.get_values()}

        if values.get('DhcpIPAddress') is None:
            return None

        network_hint = ''
        if values.get('DhcpIPAddress') is not None:
            for idx in range(0, len(values['DhcpNetworkHint']) - 1, 2):
                network_hint += values['DhcpNetworkHint'][idx + 1] + values['DhcpNetworkHint'][idx]

        domain = ''
        if values.get('DhcpDomain') is not None:
            domain = values['DhcpDomain']

        return {
            'nic_guid': nic['guid'],
            'nic_description': nic['description'],
            'network_hint': bytes.fromhex(network_hint).decode('utf-8'),
            'ip': values['DhcpIPAddress'],
            'subnet_mask': values['DhcpSubnetMask'],
            'dhcp_server': values['DhcpServer'],
            'dns_servers': values['DhcpNameServer'],
            'gateway': ','.join(values['DhcpDefaultGateway']),
            'domain': domain,
            'lease_start': self._unixepoch_to_datetime(values['LeaseObtainedTime']),
            'lease_end': self._unixepoch_to_datetime(values['LeaseTerminatesTime']),
        }
