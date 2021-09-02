from facs.entity.report import ReportEntity
import json
from xml.dom import minidom
from facs.entity.timeline import TimelineEntity
from facs.analyzer.abstract import AbstractAnalyzer


class EvtxAnalyzer(AbstractAnalyzer):
    __CHANNELS_MIN = [
        'Security',
        'System',
        'Application',
        'Microsoft-Windows-TaskScheduler/Operational',
        'Microsoft-Windows-TerminalServices-RDPClient/Operational',
        'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational',
        'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational',
        'Microsoft-Windows-Partition/Diagnostic',
        'Microsoft-Windows-Kernel-PnP/Configuration',
    ]

    def collect_common_events(self, fd_evtx):
        collection = {
            'app_uninstalled': [],
            'storage_info': [],
            'pnp_connections': [],
        }
        log_start_end = {channel: {'start': None, 'end': None} for channel in self.__CHANNELS_MIN}
        timeline = []
        computer_name = None
        report = {}

        nb_events = 0
        for line in fd_evtx:
            nb_events += 1
            if nb_events % 1000 == 0:
                print('.', end='', flush=True)

            event = json.loads(line)
            info = self.__extract_common(event['xml_string'])

            if info is None:
                continue

            channel = info['channel']
            provider = info['provider']
            event_id = info['event_id']

            if computer_name is None:
                computer_name = info['computer']

            # collect start/end of logs
            if channel in self.__CHANNELS_MIN:
                if log_start_end[channel]['start'] is None or info['datetime'] < log_start_end[channel]['start']:
                    log_start_end[channel]['start'] = info['datetime']

                if log_start_end[channel]['end'] is None or info['datetime'] > log_start_end[channel]['end']:
                    log_start_end[channel]['end'] = info['datetime']

            # check time changes, logging tampered and windows start/stop from Security channel
            if channel == 'Security':
                if provider == 'Microsoft-Windows-Security-Auditing' and event_id == '4616':
                    data = self.__extract_security_4616(event['xml_string'])
                    event_processed = self.__process_security_4616(info, data)
                    timeline = self._append_to_timeline(event_processed, timeline)

                if provider == 'Microsoft-Windows-Security-Auditing' and event_id in ['4608', '4609']:
                    event_processed = self.__process_security_4608_4609(info)
                    timeline = self._append_to_timeline(event_processed, timeline)

                if provider == 'Microsoft-Windows-Eventlog' and event_id in ['1100', '1102', '1104']:
                    data = self.__extract_security_1100_1102_1104(event['xml_string'])
                    event_processed = self.__process_security_1100_1102_1104(info, data)
                    timeline = self._append_to_timeline(event_processed, timeline)

            # check time changes, logging tampered and system start/stop/sleep/wake_up from System channel
            if channel == 'System':
                if provider == 'Microsoft-Windows-Kernel-General' and event_id == '1':
                    data = self.__extract_system_1(event['xml_string'])
                    event_processed = self.__process_system_1(info, data)
                    timeline = self._append_to_timeline(event_processed, timeline)

                if provider == 'Microsoft-Windows-Kernel-General' and event_id in ['12', '13']:
                    data = self.__extract_system_12_13(event['xml_string'])
                    event_processed = self.__process_system_12_13(info, data)
                    timeline = self._append_to_timeline(event_processed, timeline)

                if provider == 'Microsoft-Windows-Power-Troubleshooter' and event_id == '1':
                    data = self.__extract_system_power_1(event['xml_string'])
                    event_processed = self.__process_system_power_1(info, data)
                    timeline = self._append_to_timeline(event_processed, timeline)

                if provider == 'User32' and event_id == '1074':
                    data = self.__extract_system_1074(event['xml_string'])
                    event_processed = self.__process_system_1074(info, data)
                    timeline = self._append_to_timeline(event_processed, timeline)

                if provider == 'EventLog' and event_id in ['6005', '6006']:
                    event_processed = self.__process_system_6005_6006(info)
                    timeline = self._append_to_timeline(event_processed, timeline)

            # look for app_uninstalled applications
            if channel == 'Application':
                if provider == 'MsiInstaller' and event_id == '11724':
                    data = self.__extract_application_11724(event['xml_string'])
                    event_processed = self.__process_application_11724(info, data)
                    collection['app_uninstalled'] = self._append_to_timeline(event_processed, collection['app_uninstalled'])

            # collect info on storage devices (internal, external drives, USB MSC keys)
            if channel == 'Microsoft-Windows-Partition/Diagnostic':
                if provider == 'Microsoft-Windows-Partition' and event_id == '1006':
                    device = self.__extract_partition_1006(event['xml_string'])
                    if device is not None and device not in collection['storage_info']:
                        collection['storage_info'].append(device)

            # collect device connections to an USB port
            if channel == 'Microsoft-Windows-Kernel-PnP/Configuration':
                if provider == 'Microsoft-Windows-Kernel-PnP' and event_id in ['410', '430']:
                    data = self.__extract_kernel_pnp_410_430(event['xml_string'])
                    event_processed = self.__process_kernel_pnp_410_430(info, data)
                    collection['pnp_connections'] = self._append_to_timeline(event_processed, collection['pnp_connections'])

        # insert log start/end in the timeline
        report['log_start_end'] = ReportEntity(
            title='Checked start/end of windows event log for main channels',
            details=[]
        )
        for channel in self.__CHANNELS_MIN:
            if log_start_end[channel]['start'] is None:
                report['log_start_end'].details.append('{:80}: not found'.format(channel))
                continue

            report['log_start_end'].details.append('{:80}: found'.format(channel))

            event = TimelineEntity(
                start=log_start_end[channel]['start'],
                end=log_start_end[channel]['end'],
                host=computer_name,
                event='log start/end',
                event_type=TimelineEntity.TIMELINE_TYPE_LOG,
                source='{}.evtx'.format(channel)
            )

            timeline.append(event.to_dict())

        # list what was done
        report['time_changed'] = ReportEntity(
            title='Checked evidences of system backdating',
            details=[
                'looked for clock drifts bigger than 10 minutes',
                'from Security channel, provider Microsoft-Windows-Security-Auditing, EID 4616 where user is not "LOCAL SERVICE" or "SYSTEM"',
                'from System channel, provider Microsoft-Windows-Kernel-General, EID 1 where reason is not 2',
            ]
        )

        report['log_tampered'] = ReportEntity(
            title='Checked evidences of log tampering',
            details=[
                'from Security channel, provider Microsoft-Windows-Eventlog, EID 1100/1102/1104',
                'from System channel, provider Eventlog, EID 6005/6006',
            ]
        )

        report['host_start_stop'] = ReportEntity(
            title='Checked evidences of host start/stop/sleep/wake up',
            details=[
                'from Security channel, provider Microsoft-Windows-Eventlog, EID 4608/4609',
                'from System channel, provider Microsoft-Windows-Kernel-General, EID 12/13',
                'from System channel, provider Microsoft-Windows-Power-Troubleshooter, EID 1',
                'from System channel, provider User32, EID 1074',
            ]
        )

        return nb_events, report, timeline, collection

    def __extract_common(self, evtx_xml):
        try:
            # because plaso create sometimes but rarely invalid xml string
            event = minidom.parseString(evtx_xml)
        except Exception:
            return None

        system = event.getElementsByTagName('System')[0]
        info = {
            'datetime': self._isoformat_to_datetime(system.getElementsByTagName('TimeCreated')[0].getAttribute('SystemTime')),
            'channel': system.getElementsByTagName('Channel')[0].firstChild.data,
            'provider': system.getElementsByTagName('Provider')[0].getAttribute('Name'),
            'event_id': system.getElementsByTagName('EventID')[0].firstChild.data,
            'computer': system.getElementsByTagName('Computer')[0].firstChild.data,
            'sid': system.getElementsByTagName('Security')[0].getAttribute('UserID'),
        }

        return info

    def __extract_security_4616(self, evtx_xml):
        event = minidom.parseString(evtx_xml)
        data = event.getElementsByTagName('EventData')[0].getElementsByTagName('Data')
        info = {}
        for elt in data:
            attribute = elt.getAttribute('Name')
            if attribute == 'SubjectUserSid':
                info['sid'] = elt.firstChild.data

            if attribute == 'SubjectUserName':
                info['username'] = elt.firstChild.data

            if attribute == 'SubjectDomainName':
                info['domain'] = elt.firstChild.data

            if attribute == 'PreviousTime':
                info['previous_time'] = self._isoformat_to_datetime(elt.firstChild.data)

            if attribute == 'NewTime':
                info['current_time'] = self._isoformat_to_datetime(elt.firstChild.data)

            if attribute == 'ProcessName':
                info['process'] = elt.firstChild.data

        return info

    def __process_security_4616(self, info, data):
        keep_it = True

        # discard legitimate clock drift (NTP sync)
        if data['username'] in ['LOCAL SERVICE', 'SYSTEM']:
            keep_it = False

        # discard minor clock drift (10 min)
        delta = data['current_time'] - data['previous_time']
        if delta.total_seconds() < 600:
            keep_it = False

        if keep_it is False:
            return None

        user = '{}\\{} (SID {})'.format(data['domain'], data['username'], data['sid'])
        note = 'before {} ; after {} ; process {}'.format(str(data['previous_time']), str(data['current_time']), data['process'])
        source = 'EID {}; channel {} ; provider {}'.format(info['event_id'], info['channel'], info['provider'])

        return TimelineEntity(
            start=info['datetime'],
            host=info['computer'],
            user=user,
            event='system time changed',
            event_type=TimelineEntity.TIMELINE_TYPE_EVENT,
            source=source,
            note=note
        )

    def __extract_security_1100_1102_1104(self, evtx_xml):
        event = minidom.parseString(evtx_xml)
        data = event.getElementsByTagName('UserData')[0]
        info = {}

        # EID 1100
        shutdown = data.getElementsByTagName('ServiceShutdown')
        if len(shutdown) > 0:
            info['event'] = 'event logging service was shut down'

        # EID 1104
        full = data.getElementsByTagName('FileIsFull')
        if len(full) > 0:
            info['event'] = 'security log is full'

        # EID 1102
        cleared = data.getElementsByTagName('LogFileCleared')
        if len(cleared) > 0:
            info['event'] = 'security log was cleared'
            info['sid'] = cleared[0].getElementsByTagName('SubjectUserSid').firstChild.data
            info['username'] = cleared[0].getElementsByTagName('SubjectUserName').firstChild.data
            info['domain'] = cleared[0].getElementsByTagName('SubjectDomainName').firstChild.data

        return info

    def __process_security_1100_1102_1104(self, info, data):
        user = info['sid']
        if 'sid' in data.keys():
            user = '{}\\{} (SID {})'.format(data['domain'], data['username'], data['sid'])
        source = 'EID {}; channel {} ; provider {}'.format(info['event_id'], info['channel'], info['provider'])

        return TimelineEntity(
            start=info['datetime'],
            host=info['computer'],
            user=user,
            event=data['event'],
            event_type=TimelineEntity.TIMELINE_TYPE_EVENT,
            source=source
        )

    def __process_security_4608_4609(self, info):
        event = ''
        if info['event_id'] == '4608':
            event = 'Windows is starting up'

        if info['event_id'] == '4609':
            event = 'Windows is shutting down'

        source = 'EID {}; channel {} ; provider {}'.format(info['event_id'], info['channel'], info['provider'])

        return TimelineEntity(
            start=info['datetime'],
            host=info['computer'],
            user=info['sid'],
            event=event,
            event_type=TimelineEntity.TIMELINE_TYPE_EVENT,
            source=source
        )

    def __extract_system_1(self, evtx_xml):
        event = minidom.parseString(evtx_xml)
        data = event.getElementsByTagName('EventData')[0].getElementsByTagName('Data')
        info = {}
        for elt in data:
            attribute = elt.getAttribute('Name')
            if attribute == 'OldTime':
                info['previous_time'] = self._isoformat_to_datetime(elt.firstChild.data)

            if attribute == 'NewTime':
                info['current_time'] = self._isoformat_to_datetime(elt.firstChild.data)

            if attribute == 'Reason':
                info['reason'] = elt.firstChild.data

        return info

    def __process_system_1(self, info, data):
        keep_it = True

        # discard legitimate clock drift (2=System time synchronized with the hardware clock)
        if data['reason'] == '2':
            keep_it = False

        # discard minor clock drift (10 min)
        delta = data['current_time'] - data['previous_time']
        if delta.total_seconds() < 600:
            keep_it = False

        if keep_it is False:
            return None

        note = 'before {} ; after {} ; reason {}'.format(str(data['previous_time']), str(data['current_time']), data['reason'])
        source = 'EID {}; channel {} ; provider {}'.format(info['event_id'], info['channel'], info['provider'])

        return TimelineEntity(
            start=info['datetime'],
            host=info['computer'],
            user=info['sid'],
            event='system time changed',
            event_type=TimelineEntity.TIMELINE_TYPE_EVENT,
            source=source,
            note=note
        )

    def __extract_system_power_1(self, evtx_xml):
        event = minidom.parseString(evtx_xml)
        data = event.getElementsByTagName('EventData')[0].getElementsByTagName('Data')
        info = {}
        for elt in data:
            attribute = elt.getAttribute('Name')
            if attribute == 'SleepTime':
                info['sleep_start'] = self._isoformat_to_datetime(elt.firstChild.data)

            if attribute == 'WakeTime':
                info['sleep_end'] = self._isoformat_to_datetime(elt.firstChild.data)

        return info

    def __process_system_power_1(self, info, data):
        source = 'EID {}; channel {} ; provider {}'.format(info['event_id'], info['channel'], info['provider'])

        return TimelineEntity(
            start=data['sleep_start'],
            end=data['sleep_end'],
            host=info['computer'],
            user=info['sid'],
            event='sleeping time',
            event_type=TimelineEntity.TIMELINE_TYPE_EVENT,
            source=source,
        )

    def __extract_system_12_13(self, evtx_xml):
        event = minidom.parseString(evtx_xml)
        data = event.getElementsByTagName('EventData')[0].getElementsByTagName('Data')
        info = {}
        for elt in data:
            attribute = elt.getAttribute('Name')
            if attribute == 'StopTime':
                info['event'] = 'system stopped'
                info['time'] = self._isoformat_to_datetime(elt.firstChild.data)

            if attribute == 'StartTime':
                info['event'] = 'system started'
                info['time'] = self._isoformat_to_datetime(elt.firstChild.data)

        return info

    def __process_system_12_13(self, info, data):
        source = 'EID {}; channel {} ; provider {}'.format(info['event_id'], info['channel'], info['provider'])

        note = ''
        if info['event_id'] == '12':
            note = 'start time: '
        if info['event_id'] == '13':
            note = 'stop time: '
        note += str(data['time'])

        return TimelineEntity(
            start=info['datetime'],
            host=info['computer'],
            user=info['sid'],
            event=data['event'],
            event_type=TimelineEntity.TIMELINE_TYPE_EVENT,
            source=source,
            note=note
        )

    def __extract_system_1074(self, evtx_xml):
        event = minidom.parseString(evtx_xml)
        data = event.getElementsByTagName('EventData')[0].getElementsByTagName('Data')
        info = {}
        for elt in data:
            attribute = elt.getAttribute('Name')
            if attribute == 'param1':
                info['process'] = elt.firstChild.data

            if attribute == 'param3':
                info['reason'] = elt.firstChild.data

            if attribute == 'param4':
                info['reason'] += '(code {})'.format(elt.firstChild.data)

            if attribute == 'param5':
                info['event'] = elt.firstChild.data

            if attribute == 'param7':
                info['user'] = elt.firstChild.data
        return info

    def __process_system_1074(self, info, data):
        source = 'EID {}; channel {} ; provider {}'.format(info['event_id'], info['channel'], info['provider'])
        note = 'reason: {}, process: {}'.format(data['reason'], data['process'])

        return TimelineEntity(
            start=info['datetime'],
            host=info['computer'],
            user=data['user'],
            event=data['event'],
            event_type=TimelineEntity.TIMELINE_TYPE_EVENT,
            source=source,
            note=note
        )

    def __process_system_6005_6006(self, info):
        source = 'EID {}; channel {} ; provider {}'.format(info['event_id'], info['channel'], info['provider'])

        event = 'event log service '
        if info['event_id'] == '6005':
            event += 'started'

        if info['event_id'] == '6006':
            event += 'stopped'

        return TimelineEntity(
            start=info['datetime'],
            host=info['computer'],
            user=info['sid'],
            event=event,
            event_type=TimelineEntity.TIMELINE_TYPE_EVENT,
            source=source
        )

    def __extract_application_11724(self, evtx_xml):
        event = minidom.parseString(evtx_xml)
        data = event.getElementsByTagName('EventData')[0].getElementsByTagName('Data')[0]
        return {
            'event': 'application successfully removed',
            'product': data.firstChild.data,
        }

    def __process_application_11724(self, info, data):
        source = 'EID {}; channel {} ; provider {}'.format(info['event_id'], info['channel'], info['provider'])

        return TimelineEntity(
            start=info['datetime'],
            host=info['computer'],
            user=info['sid'],
            event=data['event'],
            event_type=TimelineEntity.TIMELINE_TYPE_EVENT,
            source=source,
            note=data['product']
        )

    def __extract_partition_1006(self, evtx_xml):
        event = minidom.parseString(evtx_xml)
        data = event.getElementsByTagName('EventData')[0].getElementsByTagName('Data')
        info = {}

        for elt in data:
            attribute = elt.getAttribute('Name')

            # when capacity is zero, it is just an unplug
            if info.get('bytes_capacity') is not None and info['bytes_capacity'] == 0:
                return None

            if attribute == 'Capacity' and elt.firstChild is not None:
                info['bytes_capacity'] = elt.firstChild.data

            if attribute == 'Manufacturer' and elt.firstChild is not None:
                info['manufacturer'] = elt.firstChild.data

            if attribute == 'Model' and elt.firstChild is not None:
                info['model'] = elt.firstChild.data

            if attribute == 'Revision' and elt.firstChild is not None:
                info['revision'] = elt.firstChild.data

            if attribute == 'SerialNumber' and elt.firstChild is not None:
                info['disk_serial_number'] = elt.firstChild.data

            if attribute == 'ParentId':
                parent_id = elt.firstChild.data.split('\\')
                if parent_id[0] == 'PCI':
                    info['vendor_product'] = parent_id[1]

                if parent_id[0] == 'USB':
                    info['vid_pid'] = parent_id[1]
                info['serial_number'] = parent_id[2]

            if attribute == 'DiskId':
                info['disk_guid'] = elt.firstChild.data

            if attribute == 'AdapterId':
                info['adapter_guid'] = elt.firstChild.data

            if attribute == 'RegistryId':
                info['registry_guid'] = elt.firstChild.data

            if attribute == 'PartitionTable' and elt.firstChild is not None:
                table = elt.firstChild.data
                partition_type = table[0:8]
                if partition_type == '00000000':
                    info['partition_type'] = self._PARTITION_MBR
                    info['disk_signature'] = table[16:24].lower()

                if partition_type == '01000000':
                    info['partition_type'] = self._PARTITION_GPT
                    info['partitions_guid'] = []
                    for i in range(0, len(table)-1, 32):
                        # collect the partition GUID if its header is "Basic Data Partition"
                        if table[i:i+32].lower() == 'a2a0d0ebe5b9334487c068b6b72699c7':
                            info['partitions_guid'].append(table[i+32:i+64].lower())
        return info

    def __extract_kernel_pnp_410_430(self, evtx_xml):
        event = minidom.parseString(evtx_xml)
        data = event.getElementsByTagName('EventData')[0].getElementsByTagName('Data')
        info = {}

        for elt in data:
            attribute = elt.getAttribute('Name')

            if attribute == 'DeviceInstanceId' and elt.firstChild.data.startswith('USB\\'):
                # pattern is USB\VID_XXX&PID_YYY\<SN>
                instance_id = elt.firstChild.data.split('\\')
                info['vid_pid'] = instance_id[1]
                info['serial_number'] = instance_id[2]

        return info

    def __process_kernel_pnp_410_430(self, info, data):
        if len(data) == 0:
            return None

        source = 'EID {}; channel {} ; provider {}'.format(info['event_id'], info['channel'], info['provider'])
        note = '{}#{}'.format(data['vid_pid'], data['serial_number'])

        return TimelineEntity(
            start=info['datetime'],
            host=info['computer'],
            user=info['sid'],
            event='USB device started',
            event_type=TimelineEntity.TIMELINE_TYPE_EVENT,
            source=source,
            note=note
        )
