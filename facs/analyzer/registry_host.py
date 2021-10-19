from facs.analyzer import evtx
from regipy.exceptions import RegistryKeyNotFoundException, NoRegistrySubkeysException
from regipy.structs import VALUE_KEY
from regipy.utils import boomerang_stream

from facs.entity.report import ReportEntity
from facs.entity.host_info import HostInfoEntity
from facs.entity.local_user import LocalUserEntity
from facs.entity.application import ApplicationEntity
from facs.entity.autorun import AutorunEntity
from facs.entity.network_parameters import NetworkParametersEntity
from facs.entity.storage_info import StorageInfoEntity
from facs.entity.timeline import TimelineEntity
from facs.analyzer.abstract import AbstractAnalyzer


class HostRegistryAnalyzer(AbstractAnalyzer):
    __NETWORK_TYPES = {
        '6': 'wired',
        '23': 'VPN',
        '71': 'wireless',
        '243': 'mobile',
    }

    __SERVICES_START_TYPES = {
        '0': 'boot (kernel)',
        '1': 'system (I/O subsystem)',
        '2': 'autoload (Service Control Manager)',
        '3': 'on demand (Service Control Manager)',
        '4': 'disabled (Service Control Manager)',
    }

    __PREFETCHER_STATUSES = {
        '0': 'disabled',
        '1': 'application prefetching enabled',
        '2': 'boot prefetching enabled',
        '3': 'boot and application prefetching enabled'
    }

    __STORAGE_INTERNAL_DRIVE = 'internal storage'
    __STORAGE_EXTERNAL_DRIVE = 'uas_mass_storage'
    __STORAGE_MSC = 'usb_mass_storage'
    __STORAGE_MTP = 'mtp'
    __STORAGE_VIRTUAL = 'virtual_drive'

    __STORAGE_DRIVERS = {
        __STORAGE_EXTERNAL_DRIVE: 'uaspstor.inf',
        __STORAGE_MSC: 'usbstor.inf',
        __STORAGE_MTP: 'wpdmtp.inf',
    }

    def __init__(self):
        super().__init__()
        self.__current_control_set = None
        self.__computer_name = None

    def set_current_control_set(self, reg_system):
        key = reg_system.get_key('\\Select')
        self.__current_control_set = '\\ControlSet{:03d}'.format(key.get_value('Current'))

    def set_computer_name(self, reg_system):
        path = self.__current_control_set + '\\Control\\ComputerName\\ComputerName'
        key = reg_system.get_key(path)
        self.__computer_name = key.get_value('ComputerName')

    # https://docs.microsoft.com/en-us/windows/win32/intl/code-page-identifiers
    # https://docs.python.org/3/library/codecs.html#standard-encodings
    # it has an impact when decoding key name (bytes.decode())
    def set_registry_codepage(self, reg_system):
        path = self.__current_control_set + '\\Control\\Nls\\CodePage'
        key = reg_system.get_key(path)
        codepage = key.get_value('OEMCP')

        # because CP850 decode "Invité" as "InvitÚ" ...
        # both of these codepage are "Western Europe", should be sufficient
        if codepage == '850':
            codepage = '1252'
        self.__codepage = codepage

    def get_registry_codepage(self, reg_system):
        path = self.__current_control_set + '\\Control\\Nls\\CodePage'
        key = reg_system.get_key(path)
        codepage = key.get_value('OEMCP')
        if codepage == '850':
            codepage = '1252'

        return codepage

    def collect_host_info(self, reg_system, reg_software):
        # describe what is done
        report = ReportEntity(
            title='Collected system information',
            details=[
                'computer name from key SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ComputerName',
                'OS info from key SYSTEM\\Microsoft\\Windows NT\\CurrentVersion',
                'time zone info from key SYSTEM\\CurrentControlSet\\Control\\TimeZoneInformation',
                'control sets from key SYSTEM\\Select',
                'NICs from subkeys of SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkCards',
                'prefetch status from key SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management\\PrefetchParameters'
            ]
        )

        # analyze
        analysis = []

        # collect control sets
        key = reg_system.get_key('\\Select')
        values = {value.name: value.value for value in key.get_values()}

        analysis.append(HostInfoEntity(
            title='control sets',
            value='current is {}; last known good is {}; available are [{}]'.format(values['Current'], values['LastKnownGood'], ';'.join(reg_system.get_control_sets('')))
        ))

        # collect computer name
        path = self.__current_control_set + '\\Control\\ComputerName\\ComputerName'
        key = reg_system.get_key(path)
        values = {value.name: value.value for value in key.get_values()}
        analysis.append(HostInfoEntity(
            title='computer name',
            value=key.get_value('ComputerName')
        ))

        # collect OS version
        path = '\\Microsoft\\Windows NT\\CurrentVersion'
        key = reg_software.get_key(path)
        values = {value.name: value.value for value in key.get_values()}
        release = values.get('ReleaseId', '')
        analysis.append(HostInfoEntity(
            title='OS',
            value='{} Release {} Build {}; installed on {}'.format(values['ProductName'], release, values['CurrentBuild'], values['InstallDate'])
        ))

        # collect time zone
        path = self.__current_control_set + '\\Control\\TimeZoneInformation'
        key = reg_system.get_key(path)
        values = {value.name: value.value for value in key.get_values()}
        analysis.append(HostInfoEntity(
            title='local time',
            value='{} (UTC = local time + {} min)'.format(values['TimeZoneKeyName'], values['ActiveTimeBias'])
        ))

        # collect NICs
        path = '\\Microsoft\\Windows NT\\CurrentVersion\\NetworkCards'
        key = reg_software.get_key(path)
        for subkey in key.iter_subkeys():
            values = {value.name: value.value for value in subkey.get_values()}
            analysis.append(HostInfoEntity(
                title='NIC',
                value='{} ({})'.format(values['ServiceName'], values['Description'])
            ))

        # collect prefetch status
        path = self.__current_control_set + '\\Control\\Session Manager\\Memory Management\\PrefetchParameters'
        key = reg_system.get_key(path)
        prefetcher_status = key.get_value('EnablePrefetcher')
        analysis.append(HostInfoEntity(
            title='prefetcher status',
            value=self.__PREFETCHER_STATUSES.get(str(prefetcher_status), prefetcher_status)
        ))
        return report, analysis

    def collect_local_users(self, reg_sam):
        # describe what is done
        report = ReportEntity(
            title='Collected local accounts information',
            details=[
                'accounts from key SAM\\SAM\\Domains\\Account\\Users',
                'groups membership from key SAM\\SAM\\Domains\\Builtin\\Aliases',
                'account creation from key SAM\\SAM\\Domains\\Account\\Users\\Names',
            ]
        )

        # analyze (parsing based on https://github.com/EricZimmerman/RegistryPlugins: UserAccounts.cs)
        analysis = []

        # collect local accounts creation date
        accounts_creation = {}
        path = '\\SAM\\Domains\\Account\\Users\\Names'
        key = reg_sam.get_key(path)
        for subkey in key.iter_subkeys():
            accounts_creation[subkey.header.key_name_string.decode(self.__codepage)] = self._filetime_to_datetime(subkey.header.last_modified)

        # collect group membership info
        group_members_sids = {}
        path = '\\SAM\\Domains\\Builtin\\Aliases'
        key = reg_sam.get_key(path)
        for subkey in key.iter_subkeys():
            if subkey.header.key_name_string in [b'Names', b'Members']:
                continue

            value = subkey.get_value('C')

            base_offset = 0x34
            offset = int.from_bytes(value[0x10:0x14], byteorder='little', signed=False) + base_offset
            length = int.from_bytes(value[0x14:0x18], byteorder='little', signed=False)
            group_name = value[offset:offset + length].decode('utf-16le')

            offset = int.from_bytes(value[0x28:0x2c], byteorder='little', signed=False) + base_offset
            nb_members = int.from_bytes(value[0x30:0x34], byteorder='little', signed=False)

            members = []
            offset_start = offset
            for i in range(0, nb_members):
                sid_type = int.from_bytes(value[offset_start:offset_start + 2], byteorder='little', signed=False)

                sid_bytes = None
                if sid_type == 0x501:
                    sid_bytes = value[offset_start:offset_start + 0x1c]
                    step = 0x1c

                if sid_type == 0x101:
                    sid_bytes = value[offset_start:offset_start + 0x0c]
                    step = 0x0c

                if sid_bytes is None:
                    continue

                sid = ['S']
                sid.append(str(sid_bytes[0]))
                sid.append(str(int.from_bytes(sid_bytes[4:8], byteorder='big', signed=False)))
                for i in range(8, len(sid_bytes)-1, 4):
                    sid.append(str(int.from_bytes(sid_bytes[i:i+4], byteorder='little', signed=False)))

                members.append('-'.join(sid))
                offset_start += step

            group_members_sids[group_name] = members

        # reindex group membership per user rid
        rids_info = {}
        for group_name, sids in group_members_sids.items():
            for sid in sids:
                rid = sid.split('-')[-1]
                if rid not in rids_info.keys():
                    rids_info[rid] = {
                        'sid': sid,
                        'memberships': []
                    }

                rids_info[rid]['memberships'].append(group_name)

        # collect account info
        path = '\\SAM\\Domains\\Account\\Users'

        key = reg_sam.get_key(path)
        for subkey in key.iter_subkeys():
            if subkey.header.key_name_string == b'Names':
                continue

            values = {value.name: value.value for value in subkey.get_values()}

            ms_account = ''
            if values.get('InternetUserName') is not None:
                ms_account += values['InternetUserName'].decode('utf-16le')

            rid = int.from_bytes(values['F'][0x30:0x34], byteorder='little', signed=False)
            sid = rids_info[str(rid)]['sid'] if rids_info.get(str(rid), None) is not None else ''
            memberships = ','.join(rids_info[str(rid)]['memberships']) if rids_info.get(str(rid), None) is not None else ''

            ft = int.from_bytes(values['F'][0x08:0x0B], byteorder='little', signed=False)
            last_login = self._filetime_to_datetime(ft)

            ft = int.from_bytes(values['F'][0x18:0x20], byteorder='little', signed=False)
            last_pw_change = self._filetime_to_datetime(ft)

            ft = int.from_bytes(values['F'][0x20:0x28], byteorder='little', signed=False)
            account_expire = self._filetime_to_datetime(ft)

            ft = int.from_bytes(values['F'][0x28:0x30], byteorder='little', signed=False)
            last_pw_incorrect = self._filetime_to_datetime(ft)

            account_disabled = False
            flags = int.from_bytes(values['F'][0x38:0x3a], byteorder='little', signed=False)
            if flags & 1 == 1:
                account_disabled = True

            base_offset = 0xcc
            offset = int.from_bytes(values['V'][0x0c:0x10], byteorder='little', signed=False) + base_offset
            length = int.from_bytes(values['V'][0x10:0x14], byteorder='little', signed=False)
            username = values['V'][offset:offset+length].decode('utf-16le')

            offset = int.from_bytes(values['V'][0x18:0x1c], byteorder='little', signed=False) + base_offset
            length = int.from_bytes(values['V'][0x1c:0x20], byteorder='little', signed=False)
            full_name = values['V'][offset:offset+length].decode('utf-16le')

            analysis.append(LocalUserEntity(
                rid=rid,
                sid=sid,
                username=username,
                full_name=full_name,
                ms_account=ms_account,
                groups=memberships,
                nb_logins_invalid=int.from_bytes(values['F'][0x40:0x42], byteorder='little', signed=False),
                nb_logins_total=int.from_bytes(values['F'][0x42:0x44], byteorder='little', signed=False),
                is_disabled=account_disabled,
                created_at=accounts_creation[username],
                expire_at=account_expire if account_expire is not None else '',
                last_login_at=last_login if last_login is not None else '',
                last_pw_incorrect_at=last_pw_incorrect if last_pw_incorrect is not None else '',
                last_pw_change_at=last_pw_change if last_pw_change is not None else ''
            ))

        return report, analysis

    def collect_applications(self, evtx_uninstalled, reg_software):
        # describe what is done
        report = ReportEntity(
            title='Collected application installed system wide or uninstalled',
            details=[
                'system wide installation from key SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall',
                'uninstalled applications from Application channel, provider MsiInstaller, EID 11724',
            ]
        )

        # analyze
        analysis = []
        path = '\\Microsoft\\Windows\\CurrentVersion\\Uninstall'
        key = reg_software.get_key(path)
        for subkey in key.iter_subkeys():
            values = {value.name: value.value for value in subkey.get_values()}

            if values.get('UninstallString') is None:
                continue

            analysis.append(ApplicationEntity(
                source='Uninstaller from SAM hive',
                name=values['DisplayName'],
                info='version:{} ; install_date:{} ; location:{}'.format(values.get('DisplayVersion', ''), values.get('InstallDate', ''), values.get('InstallLocation', ''))
            ))

        for application in evtx_uninstalled:
            analysis.append(ApplicationEntity(
                source='Uninstalled application from MSI installer events',
                name=application['note'],
                info='uninstalled at:{}'.format(application['start'])
            ))

        return report, analysis

    def analyze_autoruns(self, reg_system, reg_software):
        # describe what is done
        report = ReportEntity(
            title='Collected autostart services and applications',
            details=[
                'Windows services from subkeys of SYSTEM\\CurrentControlSet\\Services',
                'shell value at logon from key SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon',
                'commands executed at each run of cmd.exe from key SOFTWARE\\Microsoft\\Command Processor',
                'autostart app and service from key SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
                'autostart app and service from key SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
            ]
        )

        # analyze
        analysis = []

        # collect windows services
        path = self.__current_control_set + '\\Services'
        key = reg_system.get_key(path)
        for subkey in key.iter_subkeys():
            values = {value.name: value.value for value in subkey.get_values()}

            if 'ImagePath' not in values.keys():
                continue

            analysis.append(AutorunEntity(
                reg_key='HKLM\\SYSTEM' + path + subkey.header.key_name_string.decode(self.__codepage),
                last_modified_at=self._filetime_to_datetime(subkey.header.last_modified),
                description='Windows services',
                name=values.get('DisplayName', ''),
                value=values['ImagePath'],
                start_type=self.__SERVICES_START_TYPES.get(str(values['Start']), values['Start']),
                service_type=values['Type']
            ))

        # collect winlogon shell value
        path = '\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon'
        key = reg_software.get_key(path)
        values = {value.name: value.value for value in key.get_values()}
        analysis.append(AutorunEntity(
            reg_key='HKLM\\SOFTWARE' + path,
            last_modified_at=self._filetime_to_datetime(key.header.last_modified),
            description='Shell value expected to be explorer.exe',
            name='Shell',
            value=values.get('Shell', '')
        ))

        # collect command processor values (executed when cmd run)
        path = '\\Microsoft\\Command Processor'
        try:
            key = reg_software.get_key(path)
            for value in key.get_values():
                analysis.append(AutorunEntity(
                    reg_key='HKLM\\SOFTWARE' + path,
                    last_modified_at=self._filetime_to_datetime(key.header.last_modified),
                    description='Executed at each run of cmd.exe',
                    name=value.name,
                    value=value.value
                ))
        except RegistryKeyNotFoundException:
            pass

        # collect run/run once subkeys
        path = '\\Microsoft\\Windows\\CurrentVersion\\Run'
        key = reg_software.get_key(path)
        for value in key.get_values():
            analysis.append(AutorunEntity(
                reg_key='HKLM\\SOFTWARE' + path,
                last_modified_at=self._filetime_to_datetime(key.header.last_modified),
                description='Program automatically started at system boot',
                name=value.name,
                value=value.value
            ))

        path = '\\Microsoft\\Windows\\CurrentVersion\\RunOnce'
        key = reg_software.get_key(path)
        for value in key.get_values():
            analysis.append(AutorunEntity(
                reg_key='HKLM\\SOFTWARE' + path,
                last_modified_at=self._filetime_to_datetime(key.header.last_modified),
                description='Program automatically started at system boot',
                name=value.name,
                value=value.value
            ))

        return report, analysis

    def analyze_networks(self, reg_system, reg_software):
        # describe what is done
        report = ReportEntity(
            title='Collected network connections (ethernet, wifi, VPN)',
            details=[
                'interface parameters from subkeys of SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces (if IP address found)',
                'connections history from subkeys of SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Signatures',
            ]
        )

        # analyze
        analysis = []

        # collect last known parameters for ethernet/wifi/VPN interfaces (IP, subnet, domain, DHCP, NS, ...)
        path = self.__current_control_set + '\\Services\\Tcpip\\Parameters\\Interfaces'
        key = reg_system.get_key(path)
        for subkey in key.iter_subkeys():
            nic = subkey.header.key_name_string.decode(self.__codepage)

            # main key for a NIC
            parameters = self.__decode_tcpip_interface_key(nic, key)
            if parameters is not None:
                analysis.append(parameters)

            # subkeys for WiFi access points
            for subsubkey in subkey.iter_subkeys():
                subparameters = self.__decode_tcpip_interface_key(nic, subsubkey)
                if subparameters is not None:
                    analysis.append(subparameters)

        # collect connections history
        timeline = []
        parameters_indexed = {parameters.network_hint: parameters for parameters in analysis}
        signatures = ['Managed', 'Unmanaged']
        for signature in signatures:
            path = '\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Signatures\\' + signature
            key = reg_software.get_key(path)
            for subkey in key.iter_subkeys():
                values_signature = {value.name: value.value for value in subkey.get_values()}
                profile = reg_software.get_key('\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Profiles\\' + values_signature['ProfileGuid'])
                values_profile = {value.name: value.value for value in profile.get_values()}

                # attempt to match an IP based on SSID
                ssid = values_profile['ProfileName']
                parameters = parameters_indexed.get(ssid, None)
                ip_first = None
                ip_last = None
                first_connected_at = self._systemtime_to_datetime(values_profile['DateCreated'])
                last_connected_at = self._systemtime_to_datetime(values_profile['DateLastConnected'])
                if parameters is not None and parameters.last_lease_start is not None and parameters.last_lease_end is not None:
                    if first_connected_at >= parameters.last_lease_start and first_connected_at <= parameters.last_lease_end:
                        ip_first = parameters.ip
                    if last_connected_at >= parameters.last_lease_start and last_connected_at <= parameters.last_lease_end:
                        ip_last = parameters.ip

                # record the connection
                source = 'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Signatures\\'
                note = 'connection type {}; gateway MAC {}; profile GUID {}'.format(
                    self.__NETWORK_TYPES.get(str(values_profile['NameType']), str(values_profile['NameType'])),
                    bytes(values_signature['DefaultGatewayMac']).hex(),
                    values_signature['ProfileGuid']
                )

                event = TimelineEntity(
                    start=first_connected_at,
                    host='{} (IP {})'.format(self.__computer_name, ip_first),
                    event='First network connection to (domain: {}; SSID: {})'.format(values_signature['DnsSuffix'], ssid),
                    event_type=TimelineEntity.TIMELINE_TYPE_EVENT,
                    source=source,
                    note=note
                )
                timeline = self._append_to_timeline(event, timeline)

                event = TimelineEntity(
                    start=last_connected_at,
                    host='{} (IP {})'.format(self.__computer_name, ip_last),
                    event='Last network connection to (domain: {}; SSID: {})'.format(values_signature['DnsSuffix'], ssid),
                    event_type=TimelineEntity.TIMELINE_TYPE_EVENT,
                    source=source,
                    note=note
                )
                timeline = self._append_to_timeline(event, timeline)

        return report, timeline, analysis

    def __decode_tcpip_interface_key(self, nic, key):
        values = {value.name: value.value for value in key.get_values()}

        # discard if no IP address
        if values.get('DhcpIPAddress') is None:
            return None

        network_hint = ''
        if values.get('DhcpNetworkHint') is not None:
            for idx in range(0, len(values['DhcpNetworkHint']) - 1, 2):
                network_hint += values['DhcpNetworkHint'][idx + 1] + values['DhcpNetworkHint'][idx]
        network_hint = bytes.fromhex(network_hint).decode('utf-8')

        return NetworkParametersEntity(
            nic_guid=nic,
            is_vpn=values.get('VPNInterface', ''),
            network_hint=network_hint,
            ip=values['DhcpIPAddress'],
            subnet=values.get('DhcpSubnetMask', ''),
            dhcp=values.get('DhcpServer', ''),
            dns=values.get('DhcpNameServer', ''),
            gateway=','.join(values.get('DhcpDefaultGateway', [])),
            domain=values.get('DhcpDomain', ''),
            last_lease_start=self._unixepoch_to_datetime(values['LeaseObtainedTime']) if values.get('LeaseObtainedTime') is not None else None,
            last_lease_end=self._unixepoch_to_datetime(values['LeaseTerminatesTime']) if values.get('LeaseTerminatesTime') is not None else None
        )

    def analyze_usb(self, evtx_storage, evtx_pnp, reg_system, reg_software):
        # describe what is done
        report = ReportEntity(
            title='Collected information about writable storage (PCI, UAS drives, USB mass storage, MTP devices)',
            details=[
                'hardware info from Microsoft-Windows-Partition/Diagnostic channel, provider Microsoft-Windows-Partition, EID 1006',
                'connections from Microsoft-Windows-Kernel-PnP/Configuration channel, provider Microsoft-Windows-Kernel-PnP, EID 410/430',
                'user labels and instance info from key SOFTWARE\\Microsoft\\Windows Portable Devices\\Devices',
                'device types from key SYSTEM\\CurrentControlSet\\Enum\\USB, property {a8b865dd-2e3d-4094-ad97-e593a70c75d6}',
                'models from key SYSTEM\\CurrentControlSet\\Enum\\USB, property {540b947e-8b40-45bc-a8a2-6a0b894cbda2}',
                'first/last connections from key SYSTEM\\CurrentControlSet\\Enum\\USB, property {83da6326-97a6-4088-9453-a1923f573b29}',
                'drive letters, and volume GUID from key SYSTEM\\MountedDevices (do check manually slack space)',
            ]
        )

        # analyze
        analysis = []
        user_labels = self.__collect_usb_user_labels(reg_software)
        usb_connections = self.__collect_usb_connections(reg_system)
        drive_letters = self.__collect_drive_letters(reg_system)

        analysis.extend(self.__assemble_internal_storage(evtx_storage, usb_connections, drive_letters))
        analysis.extend(self.__assemble_uas_storage(evtx_storage, usb_connections, drive_letters, user_labels))
        analysis.extend(self.__assemble_msc_storage(evtx_storage, usb_connections, drive_letters, user_labels))
        analysis.extend(self.__assemble_mtp_storage(usb_connections, user_labels))
        analysis.extend(self.__assemble_virtual_storage(drive_letters))

        # assemble timeline of connections
        timeline = self.__assemble_usb_timeline(evtx_pnp, usb_connections)

        return report, timeline, analysis

    def __assemble_internal_storage(self, evtx_storage, usb_connections, drive_letters):
        info = []

        for device in evtx_storage:
            # identify internal storage: their serial number is not listed in enum subkey
            is_internal = any(1 for elt in usb_connections if elt['serial_number'] == device['serial_number'])
            if is_internal is True:
                continue

            storage = StorageInfoEntity(
                device_type=self.__STORAGE_INTERNAL_DRIVE,
                manufacturer=device.get('manufacturer', ''),
                model=device.get('model', ''),
                revision=device.get('revision', ''),
                bytes_capacity=device.get('bytes_capacity', ''),
                disk_serial_number=device.get('disk_serial_number', ''),
                partition_type=device.get('partition_type', ''),
                disk_guid=device.get('disk_guid', ''),
                adapter_guid=device.get('adapter_guid', ''),
                registry_guid=device.get('registry_guid', ''),
                vendor_product=device.get('vendor_product', ''),
                serial_number=device.get('serial_number', ''),
            )

            found_mounted_device = False

            # retrieve drive letter from disk signature for MBR partitioned devices
            if device['partition_type'] == AbstractAnalyzer._PARTITION_MBR:
                drive_letters_matches = [elt for elt in drive_letters if elt['disk_signature'] == device['disk_signature']]
                for match in drive_letters_matches:
                    found_mounted_device = True
                    storage.last_known_drive_letter = match['drive_letter']
                    storage.disk_signature = device['disk_signature']
                    storage.partition_offset = match['partition_offset']
                    storage.volume_guid = match['volume_guid']
                    info.append(storage)

            # retrieve drive letter from partition guid for GPT partitioned devices
            if device['partition_type'] == AbstractAnalyzer._PARTITION_GPT:
                drive_letters_matches = [elt for elt in drive_letters if elt['partition_guid'] in device['partitions_guid']]
                for match in drive_letters_matches:
                    found_mounted_device = True
                    storage.last_known_drive_letter = match['drive_letter']
                    storage.partition_guid = match['partition_guid']
                    storage.disk_guid = device['disk_guid']
                    storage.volume_guid = match['volume_guid']
                    info.append(storage)

            # if device was not listed in mounted devices subkey
            if found_mounted_device is False:
                info.append(storage)
        return info

    def __assemble_uas_storage(self, evtx_storage, usb_connections, drive_letters, user_labels):
        info = []

        for device in usb_connections:
            # identify external storage
            if device['driver'] != self.__STORAGE_DRIVERS[self.__STORAGE_EXTERNAL_DRIVE]:
                continue

            # retrieve the hardware from evtx if any
            hardware = next((
                elt for elt in evtx_storage
                if elt.get('vid_pid') == device['vid_pid'] and elt['serial_number'] == device['serial_number']), None
            )

            storage = StorageInfoEntity(
                device_type=device['device_type'],
                driver=device['driver'],
                vid_pid=device['vid_pid'],
                device_label=device['device_label'],
                manufacturer=hardware.get('manufacturer', '') if hardware is not None else '',
                model=hardware.get('model', '') if hardware is not None else '',
                revision=hardware.get('revision', '') if hardware is not None else '',
                bytes_capacity=hardware.get('bytes_capacity', '') if hardware is not None else '',
                disk_serial_number=hardware.get('disk_serial_number', '') if hardware is not None else '',
                disk_guid=hardware['disk_guid'] if hardware is not None else '',
                adapter_guid=hardware['adapter_guid'] if hardware is not None else '',
                registry_guid=hardware['registry_guid'] if hardware is not None else '',
                partition_type=hardware['partition_type'] if hardware is not None else '',
                serial_number=hardware['serial_number'] if hardware is not None else '',
            )

            # retrieve user label
            label = next((elt for elt in user_labels if elt['registry_guid'] == storage.registry_guid), None)
            storage.user_label = label['user_label'] if label is not None else ''

            found_mounted_device = False

            # retrieve drive letter from disk signature for MBR partitioned devices
            if storage.partition_type == AbstractAnalyzer._PARTITION_MBR:
                drive_letters_matches = [elt for elt in drive_letters if elt['disk_signature'] == hardware['disk_signature']]
                for match in drive_letters_matches:
                    found_mounted_device = True
                    storage.last_known_drive_letter = match['drive_letter']
                    storage.disk_signature = match['disk_signature']
                    storage.partition_offset = match['partition_offset']
                    storage.volume_guid = match['volume_guid']
                    info.append(storage)

            # retrieve driver letter from partition guid for GPT partitioned devices
            if storage.partition_type == AbstractAnalyzer._PARTITION_GPT:
                drive_letters_matches = [elt for elt in drive_letters if elt['partition_guid'] in hardware['partitions_guid']]
                for match in drive_letters_matches:
                    found_mounted_device = True
                    storage.last_known_drive_letter = match['drive_letter']
                    storage.partition_guid = match['partition_guid']
                    storage.volume_guid = match['volume_guid']
                    info.append(storage)

            # if device was not listed in mounted devices subkey
            if found_mounted_device is False:
                info.append(storage)

        return info

    def __assemble_msc_storage(self, evtx_storage, usb_connections, drive_letters, user_labels):
        info = []
        for device in usb_connections:
            # identify MSC device
            if device['driver'] != self.__STORAGE_DRIVERS[self.__STORAGE_MSC]:
                continue

            # retrieve the hardware from evtx if any
            hardware = next((
                elt for elt in evtx_storage
                if elt.get('vid_pid') == device['vid_pid'] and elt['serial_number'] == device['serial_number']
            ), None)

            storage = StorageInfoEntity(
                device_type=device['device_type'],
                driver=device['driver'],
                device_label=device['device_label'],
                vid_pid=device['vid_pid'],
                manufacturer=hardware.get('manufacturer', '') if hardware is not None else '',
                model=hardware.get('model', '') if hardware is not None else '',
                revision=hardware.get('revision', '') if hardware is not None else '',
                bytes_capacity=hardware.get('bytes_capacity', '') if hardware is not None else '',
                disk_serial_number=hardware.get('disk_serial_number', '') if hardware is not None else '',
                disk_guid=hardware['disk_guid'] if hardware is not None else '',
                adapter_guid=hardware['adapter_guid'] if hardware is not None else '',
                registry_guid=hardware['registry_guid'] if hardware is not None else ''
            )

            found_mounted_device = False

            # retrieve drive letter fom serial number
            drive_letters_matches = [
                elt for elt in drive_letters
                if elt.get('serial_number') is not None and elt['serial_number'].startswith(device['serial_number'])
            ]
            for match in drive_letters_matches:
                found_mounted_device = True
                storage.last_known_drive_letter = match['drive_letter']
                storage.volume_guid = match['volume_guid']
                storage.vendor_product = match['vendor_product']
                storage.serial_number = match['serial_number']

                label = next((
                    elt for elt in user_labels
                    if elt.get('vendor_product') == match['vendor_product'].upper() and elt['serial_number'] == match['serial_number']
                ), None)
                storage.user_label = label['user_label'] if label is not None else ''
                info.append(storage)

            # retrieve drive letter from disk signature for MBR partitioned devices
            if hardware is not None and hardware['partition_type'] == AbstractAnalyzer._PARTITION_MBR:
                drive_letters_matches = [elt for elt in drive_letters if elt['disk_signature'] == hardware['disk_signature']]
                for match in drive_letters_matches:
                    found_mounted_device = True
                    storage.last_known_drive_letter = match['drive_letter']
                    storage.partition_type = hardware['partition_type'],
                    storage.disk_signature = match['disk_signature']
                    storage.partition_offset = match['partition_offset']
                    storage.volume_guid = match['volume_guid']
                    info.append(storage)

            # retrieve driver letter from partition guid for GPT partitioned devices
            if hardware is not None and hardware['partition_type'] == AbstractAnalyzer._PARTITION_GPT:
                drive_letters_matches = [elt for elt in drive_letters if elt['partition_guid'] in hardware['partitions_guid']]
                for match in drive_letters_matches:
                    found_mounted_device = True
                    storage.last_known_drive_letter = match['drive_letter']
                    storage.partition_type = hardware['partition_type'],
                    storage.partition_guid = match['partition_guid']
                    storage.volume_guid = match['volume_guid']
                    info.append(storage)

            # if device was not listed in mounted devices subkey
            if found_mounted_device is False:
                info.append(storage)

        return info

    def __assemble_mtp_storage(self, usb_connections, user_labels):
        info = []
        for device in usb_connections:
            # identify MTP device
            if device['driver'] != self.__STORAGE_DRIVERS[self.__STORAGE_MTP]:
                continue

            label = next((
                elt for elt in user_labels
                if elt['vid_pid'] == device['vid_pid'] and elt['serial_number'] == device['serial_number'].upper()
            ), None)

            info.append(StorageInfoEntity(
                device_type=device['device_type'],
                driver=device['driver'],
                device_label=device['device_label'],
                vid_pid=device['vid_pid'],
                serial_number=device['serial_number'],
                user_label=label['user_label'] if label is not None else ''
            ))

        return info

    def __assemble_virtual_storage(self, drive_letters):
        info = []

        for device in drive_letters:
            # identify virtual device (eg. Google Drive FS, ...)
            if device['device_type'] != self.__STORAGE_VIRTUAL:
                continue

            info.append(StorageInfoEntity(
                device_type=device['device_type'],
                virtual_volume=device['instance_id'],
                last_known_drive_letter=device['drive_letter'],
                volume_guid=device['volume_guid']
            ))

        return info

    def __assemble_usb_timeline(self, evtx_pnp, usb_connections):
        timeline = []

        for event in evtx_pnp:
            vid_pid, serial_number = event['note'].split('#')
            to_keep = any(1 for elt in usb_connections if elt['vid_pid'] == vid_pid and elt['serial_number'] == serial_number)
            if to_keep is True:
                timeline.append(event)

        for elt in usb_connections:
            if elt['first_connection'] != '':
                event = TimelineEntity(
                    start=elt['first_connection'],
                    host=self.__computer_name,
                    event='First USB connection of {}'.format(elt['device_label']),
                    event_type=TimelineEntity.TIMELINE_TYPE_EVENT,
                    source='SYSTEM\\CurrentControlSet\\Enum\\USB',
                    note='{}; {}#{}'.format(elt['device_type'], elt['vid_pid'], elt['serial_number'])
                )
                timeline = self._append_to_timeline(event, timeline)

            if elt['last_connection'] != '':
                event = TimelineEntity(
                    start=elt['last_connection'],
                    host=self.__computer_name,
                    event='Last USB connection of {}'.format(elt['device_label']),
                    event_type=TimelineEntity.TIMELINE_TYPE_EVENT,
                    source='SYSTEM\\CurrentControlSet\\Enum\\USB',
                    note='{}; {}#{}'.format(elt['device_type'], elt['vid_pid'], elt['serial_number'])
                )
                timeline = self._append_to_timeline(event, timeline)

            if elt['last_removal'] != '':
                event = TimelineEntity(
                    start=elt['last_removal'],
                    host=self.__computer_name,
                    event='Last USB removal of {}'.format(elt['device_label']),
                    event_type=TimelineEntity.TIMELINE_TYPE_EVENT,
                    source='SYSTEM\\CurrentControlSet\\Enum\\USB',
                    note='{}; {}#{}'.format(elt['device_type'], elt['vid_pid'], elt['serial_number'])
                )
                timeline = self._append_to_timeline(event, timeline)

        return timeline

    def __collect_usb_user_labels(self, reg_software):
        devices = []

        # collect labels, vid_pid+serial number or volume guid+partition offset
        keys = ['user_label', 'vendor_product', 'vid_pid', 'serial_number', 'registry_guid', 'partition_offset']

        path = '\\Microsoft\\Windows Portable Devices\\Devices'
        key = reg_software.get_key(path)
        for subkey in key.iter_subkeys():
            instance_id = subkey.header.key_name_string.decode(self.__codepage).split('#')
            device = {key: None for key in keys}
            device['user_label'] = subkey.get_value('FriendlyName')

            # split instance ID depending on cases
            # SWD#WPDBUSENUM#_??_USBSTOR#DISK&<VEND_XXX&PROD_YYY#<Serial Number>#{<device class GUID>}
            # SWD#WPDBUSENUM#{<registry GUID>}#<partition start offset>
            # USB#VID_XXX&PID_YYY#<Serial Number>
            if instance_id[0] == 'SWD' and 'USBSTOR' in instance_id[2]:
                device['vendor_product'] = instance_id[3]
                device['serial_number'] = instance_id[4]

            if instance_id[0] == 'SWD' and '{' in instance_id[2]:
                device['registry_guid'] = instance_id[2]
                device['partition_offset'] = instance_id[3]

            if instance_id[0] == 'USB':
                device['vid_pid'] = instance_id[1]
                device['serial_number'] = instance_id[2]

            devices.append(device)
        return devices

    def __collect_usb_connections(self, reg_system):
        connections = []

        # collect vid_pid+serial number with first and last connections for external drive, MSC and MTP devices
        path = self.__current_control_set + '\\Enum\\USB'
        try:
            key = reg_system.get_key(path)
        except (NoRegistrySubkeysException, RegistryKeyNotFoundException):
            return connections

        for subkey in key.iter_subkeys():
            vid_pid = subkey.header.key_name_string.decode(self.__codepage)
            for sk_serial_number in subkey.iter_subkeys():
                serial_number = sk_serial_number.header.key_name_string.decode(self.__codepage)
                sk_properties = sk_serial_number.get_subkey('Properties')

                sk = sk_properties.get_subkey('{a8b865dd-2e3d-4094-ad97-e593a70c75d6}')
                values = self.__get_raw_values(reg_system, sk.get_subkey('0004'))
                device_type = values['(default)'].value.decode('utf-16le')[:-1]

                values = self.__get_raw_values(reg_system, sk.get_subkey('0005'))
                driver = values['(default)'].value.decode('utf-16le')[:-1]

                # only keep writable devices: UMS (usb stick and external drives) and MTP
                if driver not in list(self.__STORAGE_DRIVERS.values()):
                    continue

                sk = sk_properties.get_subkey('{540b947e-8b40-45bc-a8a2-6a0b894cbda2}')
                values = self.__get_raw_values(reg_system, sk.get_subkey('0004'))
                device_label = values['(default)'].value.decode('utf-16le')[:-1].strip(' ')

                sk = sk_properties.get_subkey('{83da6326-97a6-4088-9453-a1923f573b29}')
                first_connection = sk.get_subkey('0064')
                last_connection = sk.get_subkey('0066')
                last_removal = sk.get_subkey('0067')

                connections.append({
                    'device_label': device_label,
                    'vid_pid': vid_pid,
                    'serial_number': serial_number,
                    'device_type': device_type,
                    'driver': driver,
                    'first_connection': self._filetime_to_datetime(first_connection.header.last_modified),
                    'last_connection': self._filetime_to_datetime(last_connection.header.last_modified),
                    'last_removal': self._filetime_to_datetime(last_removal.header.last_modified) if last_removal is not None else '',
                })

        return connections

    def __collect_drive_letters(self, reg_system):
        devices = []

        # collect last known drive letters and volume guid
        keys = [
            'drive_letter', 'device_type', 'instance_id',
            'partition_type', 'disk_signature', 'partition_offset', 'partition_guid',
            'vendor_product', 'serial_number', 'volume_guid',
        ]

        path = '\\MountedDevices'
        key = reg_system.get_key(path)
        values = key.get_values()
        letters = {value.name: value.value for value in values if 'DosDevice' in value.name}
        volumes = {value.name: value.value for value in values if 'Volume' in value.name}

        # process listed drive letters
        # could guess more from slack space
        for name, value in letters.items():
            device = {key: None for key in keys}
            device['drive_letter'] = name.split('\\')[-1]
            device = self.__decode_mounted_device_value(value, device)

            # skip unknown device type
            if device['device_type'] is None:
                continue

            # attempt to associate a volume GUID
            guid = next((name for name, value in volumes.items() if value == device['instance_id'].encode('utf-16le')), None)
            if guid is not None:
                device['volume_guid'] = guid.split('\\')[-1][len('Volume'):]

            devices.append(device)

        # process remaining volume GUIDs which have no corresponding letter
        for volume, value in volumes.items():
            device = {key: None for key in keys}
            device['drive_letter'] = ''
            device = self.__decode_mounted_device_value(value, device)

            # skip if value already processed in previous loop
            processed = any(1 for d in devices if d['instance_id'] == device['instance_id'])
            if processed is True:
                continue

            device['volume_guid'] = volume.split('\\')[-1][len('Volume'):]
            devices.append(device)

        return devices

    def __decode_mounted_device_value(self, value, device):
        # for drive with mbr partitioning
        if len(value) == 12:
            device['device_type'] = self.__STORAGE_EXTERNAL_DRIVE
            device['instance_id'] = value.hex()
            device['partition_type'] = self._PARTITION_MBR
            device['disk_signature'] = value[0:4].hex()
            device['partition_offset'] = value[4:].hex()

        # for drive with gpt partitioning
        if len(value) == 24:
            device['device_type'] = self.__STORAGE_EXTERNAL_DRIVE
            device['instance_id'] = value.hex()
            device['partition_type'] = self._PARTITION_GPT
            device['partition_guid'] = value[8:].hex()

        # for usb mass storage
        if len(value) > 24 and 'USBSTOR' in value.decode('utf-16le'):
            device['device_type'] = self.__STORAGE_MSC
            device['instance_id'] = value.decode('utf-16le')
            instance_id = device['instance_id'].split('#')
            device['vendor_product'] = instance_id[1]
            device['serial_number'] = instance_id[2]

        # for virtual drive like Google Drive FS
        if len(value) > 24 and 'Volume' in value.decode('utf-16le'):
            device['device_type'] = self.__STORAGE_VIRTUAL
            device['instance_id'] = value.decode('utf-16le')

        return device

    def __get_raw_values(self, registry, name_key_record):
        # because regipy method get_values() skips values for unsupported value types
        # https://github.com/mkorman90/regipy/blob/master/regipy/structs.py
        values = {}

        for _ in range(0, name_key_record.header.values_count):
            with boomerang_stream(registry._stream) as substream:
                substream.seek(4096 + 4 + name_key_record.header.values_list_offset)
                value_offset = int.from_bytes(substream.read(4), byteorder='little', signed=False)
                substream.seek(4096 + 4 + value_offset)
                value = VALUE_KEY.parse_stream(substream)

                if value.name_size == 0:
                    value.name = '(default)'

                values[value.name] = name_key_record.read_value(value, substream)

        return values
