import json
import sys
import copy
from facs.entity.timeline import TimelineEntity
from facs.entity.storage_info import StorageInfoEntity
from facs.bo.abstract import AbstractBo


class ReportWinProfilingBo(AbstractBo):
    def assemble_report(self, results_evtx, results_registry, channels):
        timeline_global = []
        report_global = []

        timeline, report = self.__get_profiling_log_start_end(results_evtx['computer_name'], results_evtx['log_start_end'], channels)
        timeline_global.extend(timeline)
        report_global.append(report)

        timeline, report = self.__get_profiling_system_backdating(results_evtx['time_changed'])
        timeline_global.extend(timeline)
        report_global.append(report)

        timeline, report = self.__get_profiling_log_cleaning(results_evtx['log_tampered'])
        timeline_global.extend(timeline)
        report_global.append(report)

        timeline, report = self.__get_profiling_system_start_stop(results_evtx['host_start_stop'])
        timeline_global.extend(timeline)
        report_global.append(report)

        profiling_host, report = self.__get_profiling_host_info(results_registry)
        report_global.append(report)

        profiling_users, report = self.__get_profiling_local_users(results_registry)
        report_global.append(report)

        profiling_applications, report = self.__get_profiling_applications(results_evtx['app_uninstalled'], results_registry)
        report_global.append(report)

        timeline, profiling_nic, profiling_interfaces, report = self.__get_profiling_networks(results_registry)
        timeline_global.extend(timeline)
        profiling_host += profiling_nic
        report_global.append(report)

        timeline, profiling_storage, report = self.__get_profiling_storage(results_evtx['pnp_connections'], results_evtx['storage_info'], results_registry)
        timeline_global.extend(timeline)
        report_global.append(report)

        return {
            'timeline': timeline_global,
            'report': report_global,
            'profiling': {
                'host': profiling_host,
                'users': profiling_users,
                'interfaces': profiling_interfaces,
                'applications': profiling_applications,
                'writable_storage': profiling_storage,
            }
        }

    def __get_profiling_log_start_end(self, computer, start_end, channels):
        timeline = []
        report = {
            'title': '',
            'data': [],
        }

        report['title'] = 'Checked start/end of windows event log for main channels'
        for channel in channels:
            found = 'ok'
            if start_end[channel]['start'] is None:
                found = 'not found'

            report['data'].append('{:80}: {}'.format(channel, found))
            if start_end[channel]['start'] is None:
                continue

            event = TimelineEntity(
                start=str(start_end[channel]['start']),
                end=str(start_end[channel]['end']),
                host=computer,
                event='log start/end',
                event_type=TimelineEntity.TIMELINE_TYPE_LOG,
                source='{}.evtx'.format(channel)
            )

            timeline.append(event.to_dict())

        return timeline, report

    def __get_profiling_system_backdating(self, backdating):
        report = {
            'title': '',
            'data': [],
        }

        report['title'] = 'Checked evidences of system backdating'
        report['data'].append('Looked for clock drift bigger than 10 minutes')
        report['data'].append('From Security channel, provider Microsoft-Windows-Security-Auditing, EID 4616 where user is not "LOCAL SERVICE" or "SYSTEM"')
        report['data'].append('From System channel, provider Microsoft-Windows-Kernel-General, EID 1 where reason is not 2')
        report['data'].append('Found: {} event(s)'.format(len(backdating)))

        return backdating, report

    def __get_profiling_log_cleaning(self, cleaning):
        report = {
            'title': '',
            'data': [],
        }

        report['title'] = 'Checked evidences of log tampering'
        report['data'].append('From Security channel, provider Microsoft-Windows-Eventlog, EID 1100/1102/1104')
        report['data'].append('From System channel, provider Eventlog, EID 6005/6006')
        report['data'].append('Found {} event(s)'.format(len(cleaning)))

        return cleaning, report

    def __get_profiling_system_start_stop(self, start_stop):
        report = {
            'title': '',
            'data': [],
        }

        report['title'] = 'Checked evidences of host start/stop'
        report['data'].append('From Security channel, provider Microsoft-Windows-Eventlog, EID 4608/4609')
        report['data'].append('From System channel, provider Microsoft-Windows-Kernel-General, EID 12/13')
        report['data'].append('From System channel, provider User32, EID 1074')
        report['data'].append('Found {} event(s)'.format(len(start_stop)))

        return start_stop, report

    def __get_profiling_host_info(self, results_registry):
        profiling = []
        report = {
            'title': '',
            'data': [],
        }

        report['title'] = 'Collected system information'
        report['data'].append('computer name from key SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ComputerName')
        report['data'].append('OS info from key SYSTEM\\Microsoft\\Windows NT\\CurrentVersion')
        report['data'].append('time zone info from key SYSTEM\\CurrentControlSet\\Control\\TimeZoneInformation')
        report['data'].append('control sets from key SYSTEM\\Select')

        profiling.append({
            'name': 'computer name',
            'value': results_registry['computer_name'],
        })
        profiling.append({
            'name': 'OS',
            'value': '{}; installed on {}'.format(results_registry['os']['version'], results_registry['os']['install_date']),
        })
        profiling.append({
            'name': 'local time',
            'value': '{} (UTC = local time + {} min)'.format(results_registry['time_zone']['name'], results_registry['time_zone']['active_time_bias']),
        })
        profiling.append({
            'name': 'control sets',
            'value': 'current is {}; last known good is {}; available are [{}]'.format(
                results_registry['control_sets']['current'], results_registry['control_sets']['last_known_good'],
                ','.join(results_registry['control_sets']['available'])
            )
        })
        return profiling, report

    def __get_profiling_networks(self, results_registry):
        timeline = []
        profiling_nic = []
        profiling_interfaces = []
        report = {
            'title': '',
            'data': [],
        }

        report['title'] = 'Collected network connections'
        report['data'].append('NIC from subkeys of SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkCards')
        report['data'].append('interface parameters from subkeys of SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces')
        report['data'].append('connections history from subkeys of SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Signatures')

        for nic in results_registry['networks']['nics']:
            profiling_nic.append({
                'name': 'NIC',
                'value': 'GUID {} ({})'.format(nic['guid'], nic['description'])
            })

        for parameters in results_registry['networks']['parameters']:
            profiling_interfaces.append({'name': 'Last known interface parameters', **parameters})

        for connection in results_registry['networks']['connections']:
            source = 'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Signatures\\'
            note = 'connection type {}; gateway MAC {}; profile GUID {}'.format(
                connection['connection_type'], connection['gateway_mac'], connection['profile_guid']
            )
            network_desc = '(domain: {}; SSID: {})'.format(connection['dns_suffix'], connection['ssid'])

            host_first = results_registry['computer_name']
            if connection['ip_first'] is not None:
                host_first += ' ({})'.format(connection['ip_first'])
            host_last = results_registry['computer_name']
            if connection['ip_last'] is not None:
                host_last += ' ({})'.format(connection['ip_last'])

            event = TimelineEntity(
                start=str(connection['first_connected_at']),
                host=host_first,
                event='First connection to a network ' + network_desc,
                event_type=TimelineEntity.TIMELINE_TYPE_EVENT,
                source=source,
                note=note
            )
            timeline = self._append_to_timeline(event, timeline)

            event = TimelineEntity(
                start=str(connection['last_connected_at']),
                host=host_last,
                event='Last connection to a network ' + network_desc,
                event_type=TimelineEntity.TIMELINE_TYPE_EVENT,
                source=source,
                note=note
            )
            timeline = self._append_to_timeline(event, timeline)

        return timeline, profiling_nic, profiling_interfaces, report

    def __get_profiling_local_users(self, results_registry):
        profiling = []
        report = {
            'title': '',
            'data': [],
        }

        report['title'] = 'Collected local accounts information'
        report['data'].append('accounts from key SAM\\SAM\\Domains\\Account\\Users')
        report['data'].append('groups membership from key SAM\\SAM\\Domains\\Builtin\\Aliases')
        report['data'].append('account creation from key SAM\\SAM\\Domains\\Account\\Users\\Names')

        for user in results_registry['local_users']:
            profiling.append({'name': 'Local user', **user})

        return profiling, report

    def __get_profiling_applications(self, evtx_uninstalled, results_registry):
        profiling = []
        report = {
            'title': '',
            'data': [],
        }

        report['title'] = 'Collected application installed system wide or uninstalled'
        report['data'].append('system wide installation from key SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall')
        report['data'].append('uninstalled applications from Application channel, provider MsiInstaller, EID 11724')

        for application in results_registry['applications']:
            profiling.append({'name': 'system wide application', 'uninstall_date': '', **application})

        for application in evtx_uninstalled:
            profiling.append({
                'name': 'uninstalled application',
                'app_name': application['note'],
                'uninstall_date': application['start'],
            })

        return profiling, report

    def __get_profiling_storage(self, evtx_pnp_connections, evtx_storage_info, results_registry):
        timeline = []
        profiling = []
        report = {
            'title': '',
            'data': [],
        }

        report['title'] = 'Collected information about writable storage (PCI, UAS drives, USB mass storage, MTP devices)'
        report['data'].append('hardware info from Microsoft-Windows-Partition/Diagnostic channel, provider Microsoft-Windows-Partition, EID 1006')
        report['data'].append('connections from Microsoft-Windows-Kernel-PnP/Configuration channel, provider Microsoft-Windows-Kernel-PnP, EID 410/430')
        report['data'].append('user labels and instance info from key SOFTWARE\\Microsoft\\Windows Portable Devices\\Devices')
        report['data'].append('device types from key SYSTEM\\CurrentControlSet\\Enum\\USB, property {a8b865dd-2e3d-4094-ad97-e593a70c75d6}')
        report['data'].append('models from key SYSTEM\\CurrentControlSet\\Enum\\USB, property {540b947e-8b40-45bc-a8a2-6a0b894cbda2}')
        report['data'].append('first/last connections from key SYSTEM\\CurrentControlSet\\Enum\\USB, property {83da6326-97a6-4088-9453-a1923f573b29}')
        report['data'].append('drive letters, and volume GUID from key SYSTEM\\MountedDevices (do check manually slack space)')

        # add connections, only keep those referring to USB mass storage, MTP or UAS mass storage
        for event in evtx_pnp_connections:
            vid_pid, serial_number = event['note'].split('#')
            to_keep = any(1 for elt in results_registry['usb']['connections'] if elt['vid_pid'] == vid_pid and elt['serial_number'] == serial_number)
            if to_keep is True:
                timeline.append(event)

        # add first/last connections to the timeline
        for elt in results_registry['usb']['connections']:
            if elt['first_connection'] != '':
                event = TimelineEntity(
                    start=elt['first_connection'],
                    host=results_registry['computer_name'],
                    event='First connection of {}'.format(elt['device_model']),
                    event_type=TimelineEntity.TIMELINE_TYPE_EVENT,
                    source='SYSTEM\\CurrentControlSet\\Enum\\USB',
                    note='{}; {}#{}'.format(elt['device_type'], elt['vid_pid'], elt['serial_number'])
                )
                timeline = self._append_to_timeline(event, timeline)

            if elt['last_connection'] != '':
                event = TimelineEntity(
                    start=elt['last_connection'],
                    host=results_registry['computer_name'],
                    event='Last connection of {}'.format(elt['device_model']),
                    event_type=TimelineEntity.TIMELINE_TYPE_EVENT,
                    source='SYSTEM\\CurrentControlSet\\Enum\\USB',
                    note='{}; {}#{}'.format(elt['device_type'], elt['vid_pid'], elt['serial_number'])
                )
                timeline = self._append_to_timeline(event, timeline)

            if elt['last_removal'] != '':
                event = TimelineEntity(
                    start=elt['last_removal'],
                    host=results_registry['computer_name'],
                    event='Last removal of {}'.format(elt['device_model']),
                    event_type=TimelineEntity.TIMELINE_TYPE_EVENT,
                    source='SYSTEM\\CurrentControlSet\\Enum\\USB',
                    note='{}; {}#{}'.format(elt['device_type'], elt['vid_pid'], elt['serial_number'])
                )
                timeline = self._append_to_timeline(event, timeline)

        # assemble info for internal storage
        info = self.__assemble_info_internal_storage(evtx_storage_info, results_registry['usb'])
        profiling.extend(info)

        # assemble info for external USB drive (UAS mass storage)
        info = self.__assemble_info_uas_storage(evtx_storage_info, results_registry['usb'])
        profiling.extend(info)

        # assemble info for USB mass storage
        info = self.__assemble_info_msc_storage(evtx_storage_info, results_registry['usb'])
        profiling.extend(info)

        # assemble info for MTP devices
        info = self.__assemble_info_mtp_storage(results_registry['usb'])
        profiling.extend(info)

        # assemble info for virtual devices (eg. Google Drive FS)
        info = self.__assemble_info_virtual_storage(results_registry['usb'])
        profiling.extend(info)

        return timeline, profiling, report

    def __assemble_info_internal_storage(self, evtx_storage_info, registry_usb):
        info = []

        for device in evtx_storage_info:
            # identify internal storage: their serial number is not listed in enum subkey
            usb_connections_serial_numbers = [elt['serial_number'] for elt in registry_usb['connections']]
            if device['serial_number'] in usb_connections_serial_numbers:
                continue

            data = StorageInfoEntity(
                device_type=self._STORAGE_INTERNAL_DRIVE,
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
            found = False

            # match drive letter on disk signature for MBR partitioned devices
            if device['partition_type'] == AbstractBo._PARTITION_MBR:
                drive_letters_matches = [elt for elt in registry_usb['drive_letters'] if elt['disk_signature'] == device['disk_signature']]
                for match in drive_letters_matches:
                    found = True
                    data.last_known_drive_letter = match['drive_letter']
                    data.disk_signature = device['disk_signature']
                    data.partition_offset = match['partition_offset']
                    data.volume_guid = match['volume_guid']
                    info.append(data.to_dict())

            # match drive letter on partition guid for GPT partitioned devices
            if device['partition_type'] == AbstractBo._PARTITION_GPT:
                drive_letters_matches = [elt for elt in registry_usb['drive_letters'] if elt['partition_guid'] in device['partitions_guid']]
                for match in drive_letters_matches:
                    found = True
                    data.last_known_drive_letter = match['drive_letter']
                    data.partition_guid = match['partition_guid']
                    data.disk_guid = device['disk_guid']
                    data.volume_guid = match['volume_guid']
                    info.append(data.to_dict())

            # if device was not listed in mounted devices subkey
            if found is False:
                info.append(data.to_dict())
        return info

    def __assemble_info_uas_storage(self, evtx_storage_info, registry_usb):
        info = []

        for device in registry_usb['connections']:
            # identify external storage
            if device['driver'] != self._STORAGE_DRIVERS[self._STORAGE_EXTERNAL_DRIVE]:
                continue

            hardware = next((
                elt for elt in evtx_storage_info
                if elt.get('vid_pid') == device['vid_pid'] and elt['serial_number'] == device['serial_number']), None
            )

            data = StorageInfoEntity(
                device_type=device['device_type'],
                driver=device['driver'],
                vid_pid=device['vid_pid'],
                device_label=device['label'],
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

            labels = [elt for elt in registry_usb['user_labels'] if elt['registry_guid'] == data.registry_guid]
            data.user_label = labels[0]['user_label']
            found = False

            # match drive letter on disk signature for MBR partitioned devices
            if data.partition_type == AbstractBo._PARTITION_MBR:
                drive_letters_matches = [elt for elt in registry_usb['drive_letters'] if elt['disk_signature'] == hardware['disk_signature']]
                for match in drive_letters_matches:
                    found = True
                    data.last_known_drive_letter = match['drive_letter']
                    data.disk_signature = match['disk_signature']
                    data.partition_offset = match['partition_offset']
                    data.volume_guid = match['volume_guid']
                    info.append(data.to_dict())

            # match driver letter on partition guid for GPT partitioned devices
            if data.partition_type == AbstractBo._PARTITION_GPT:
                drive_letters_matches = [elt for elt in registry_usb['drive_letters'] if elt['partition_guid'] in hardware['partitions_guid']]
                for match in drive_letters_matches:
                    found = True
                    data.last_known_drive_letter = match['drive_letter']
                    data.partition_guid = match['partition_guid']
                    data.volume_guid = match['volume_guid']
                    info.append(data.to_dict())

            # if device was not listed in mounted devices subkey
            if found is False:
                info.append(data.to_dict())

        return info

    def __assemble_info_msc_storage(self, evtx_storage_info, registry_usb):
        info = []
        for device in registry_usb['connections']:
            # identify MSC device
            if device['driver'] != self._STORAGE_DRIVERS[self._STORAGE_MSC]:
                continue

            hardware = next((
                elt for elt in evtx_storage_info
                if elt.get('vid_pid') == device['vid_pid'] and elt['serial_number'] == device['serial_number']), None
            )

            data = StorageInfoEntity(
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

            found = False

            # match drive letter on serial number
            drive_letters_matches = [
                elt for elt in registry_usb['drive_letters']
                if elt.get('serial_number') is not None and elt['serial_number'].startswith(device['serial_number'])
            ]
            for match in drive_letters_matches:
                found = True
                data.last_known_drive_letter = match['drive_letter']
                data.volume_guid = match['volume_guid']
                data.vendor_product = match['vendor_product']
                data.serial_number = match['serial_number']

                labels = [
                    elt for elt in registry_usb['user_labels']
                    if elt.get('vendor_product') == match['vendor_product'].upper() and elt['serial_number'] == match['serial_number']
                ]
                if len(labels) > 0:
                    data.user_label = labels[0]['user_label']
                info.append(data.to_dict())

            # or match drive letter on disk signature for MBR partitioned devices
            if hardware.partition_type == AbstractBo._PARTITION_MBR:
                drive_letters_matches = [elt for elt in registry_usb['drive_letters'] if elt['disk_signature'] == hardware['disk_signature']]
                for match in drive_letters_matches:
                    found = True
                    data.last_known_drive_letter = match['drive_letter']
                    data.disk_signature = match['disk_signature']
                    data.partition_offset = match['partition_offset']
                    data.volume_guid = match['volume_guid']
                    info.append(data.to_dict())

            # or match driver letter on partition guid for GPT partitioned devices
            if hardware.partition_type == AbstractBo._PARTITION_GPT:
                drive_letters_matches = [elt for elt in registry_usb['drive_letters'] if elt['partition_guid'] in hardware['partitions_guid']]
                for match in drive_letters_matches:
                    found = True
                    data.last_known_drive_letter = match['drive_letter']
                    data.partition_guid = match['partition_guid']
                    data.volume_guid = match['volume_guid']
                    info.append(data.to_dict())

            # if device was not listed in mounted devices subkey
            if found is False:
                info.append(data.to_dict())

        return info

    def __assemble_info_mtp_storage(self, registry_usb):
        info = []
        for device in registry_usb['connections']:
            # identify MTP device
            if device['driver'] != self._STORAGE_DRIVERS[self._STORAGE_MTP]:
                continue

            labels = [
                elt for elt in registry_usb['user_labels']
                if elt['vid_pid'] == device['vid_pid'] and elt['serial_number'] == device['serial_number'].upper()
            ]

            info.append(StorageInfoEntity(
                device_type=device['device_type'],
                driver=device['driver'],
                device_label=device['device_label'],
                vid_pid=device['vid_pid'],
                serial_number=device['serial_number'],
                user_label=labels[0]['user_label']
            ).to_dict())

        return info

    def __assemble_info_virtual_storage(self, registry_usb):
        info = []

        for device in registry_usb['drive_letters']:
            # identify virtual device
            if device['device_type'] != self._STORAGE_VIRTUAL:
                continue

            info.append(StorageInfoEntity(
                virtual_volume=device['instance_id'],
                last_known_drive_letter=device['drive_letter'],
                volume_guid=device['volume_guid']
            ).to_dict())

        return info
