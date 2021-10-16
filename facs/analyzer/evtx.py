from facs.entity.report import ReportEntity
import json
import pyevtx
import xmltodict
import re
import collections
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
    ]

    __RE_EVTX_COMMON = re.compile(r'(<System>.*?</System>)', re.S)

    def collect_profiling_events(self, fd_evtx):
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

            # discard events that could not be parsed
            if event['epoch'] == 0.0:
                continue

            channel = event['channel']
            provider = event['provider']
            event_id = event['eid']

            if computer_name is None:
                computer_name = event['computer']

            # collect start/end of logs
            if channel not in log_start_end.keys():
                log_start_end[channel] = {'start': None, 'end': None}

            if log_start_end[channel]['start'] is None or event['datetime'] < log_start_end[channel]['start']:
                log_start_end[channel]['start'] = event['datetime']

            if log_start_end[channel]['end'] is None or event['datetime'] > log_start_end[channel]['end']:
                log_start_end[channel]['end'] = event['datetime']

            # check time changes, logging tampered and windows start/stop from Security channel
            if channel == 'Security':
                if provider == 'Microsoft-Windows-Security-Auditing' and event_id == '4616':
                    event_processed = self.__collect_security_4616(event)
                    timeline = self._append_to_timeline(event_processed, timeline)

                if provider == 'Microsoft-Windows-Security-Auditing' and event_id in ['4608', '4609']:
                    event_processed = self.__collect_security_4608_4609(event)
                    timeline = self._append_to_timeline(event_processed, timeline)

                if provider == 'Microsoft-Windows-Eventlog' and event_id in ['1100', '1102', '1104']:
                    event_processed = self.__collect_security_1100_1102_1104(event)
                    timeline = self._append_to_timeline(event_processed, timeline)

            # check time changes, logging tampered and system start/stop/sleep/wake_up from System channel
            if channel == 'System':
                if provider == 'Microsoft-Windows-Kernel-General' and event_id == '1':
                    event_processed = self.__collect_system_kernel_general_1(event)
                    timeline = self._append_to_timeline(event_processed, timeline)

                if provider == 'Microsoft-Windows-Kernel-General' and event_id in ['12', '13']:
                    event_processed = self.__collect_system_kernel_general_12_13(event)
                    timeline = self._append_to_timeline(event_processed, timeline)

                if provider == 'Microsoft-Windows-Power-Troubleshooter' and event_id == '1':
                    event_processed = self.__collect_system_power_1(event)
                    timeline = self._append_to_timeline(event_processed, timeline)

                if provider == 'User32' and event_id == '1074':
                    event_processed = self.__collect_system_user32_1074(event)
                    timeline = self._append_to_timeline(event_processed, timeline)

                if provider == 'EventLog' and event_id in ['6005', '6006']:
                    event_processed = self.__collect_system_eventlog_6005_6006(event)
                    timeline = self._append_to_timeline(event_processed, timeline)

            # look for app_uninstalled applications
            if channel == 'Application':
                if provider == 'MsiInstaller' and event_id == '11724':
                    event_processed = self.__collect_application_msiinstaller_11724(event)
                    collection['app_uninstalled'] = self._append_to_timeline(event_processed, collection['app_uninstalled'])

            # collect info on storage devices (internal, external drives, USB MSC keys)
            if channel == 'Microsoft-Windows-Partition/Diagnostic':
                if provider == 'Microsoft-Windows-Partition' and event_id == '1006':
                    device = self.__collect_partition_diagnostic_1006(event)
                    if device is not None and device not in collection['storage_info']:
                        collection['storage_info'].append(device)

            # collect device connections to an USB port
            if channel == 'Microsoft-Windows-Kernel-PnP/Configuration':
                if provider == 'Microsoft-Windows-Kernel-PnP' and event_id in ['410', '430']:
                    event_processed = self.__collect_kernel_pnp_410_430(event)
                    collection['pnp_connections'] = self._append_to_timeline(event_processed, collection['pnp_connections'])

        # report if major evtx were found
        report['log_start_end'] = ReportEntity(
            title='Checked start/end of windows event log for main channels',
            details=[]
        )
        for channel in self.__CHANNELS_MIN:
            found = 'found'
            if log_start_end[channel]['start'] is None:
                found = 'not found'

            report['log_start_end'].details.append('{:80}: {}'.format(channel, found))

        # insert all evtx start/end in the timeline
        for channel in log_start_end:
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

    def extract_generic(self, evtx_file, tags=None):
        evtx = pyevtx.file()
        evtx.open(evtx_file)

        nb_events = evtx.get_number_of_records()
        if nb_events == 0:
            return 0, None

        events = []
        for record in evtx.records:
            xml = record.get_xml_string()
            try:
                xml_dict = xmltodict.parse(xml)
            except Exception:
                # some xml are malformed (namespace missing, text value not properly escaped)
                # only parse system data for them
                matches = self.__RE_EVTX_COMMON.search(xml)
                partial = matches.group(1)
                partial_dict = xmltodict.parse(partial)
                event = {'raw': xml, 'source': 'log_evtx', 'tags': ['xml_not_parsed']}
                event.update(self.__parse_system_data(partial_dict, True))
                events.append(event)
                continue

            # extract keys from the xml
            event = {'raw': xml, 'source': 'log_evtx'}
            event.update(self.__parse_system_data(xml_dict))
            if xml_dict['Event'].get('EventData', None) is not None:
                event.update(self.__parse_event_or_user_data(xml_dict['Event']['EventData']))
            if xml_dict['Event'].get('ProcessingErrorData', None) is not None:
                event.update(self.__parse_error_data(xml_dict['Event']['ProcessingErrorData']))
            if xml_dict['Event'].get('UserData', None) is not None:
                event.update(self.__parse_event_or_user_data(xml_dict['Event']['UserData']))

            # enrich with tags
            if tags is None:
                event['tags'] = ['no_tags']
            else:
                event = self.__enrich(event, tags)

            events.append(event)

        evtx.close()

        return nb_events, events

    def __parse_system_data(self, xml_dict, partial=False):
        if partial is False:
            system = xml_dict['Event']['System']
        else:
            system = xml_dict['System']
        writer_sid = ''
        if system.get('Security', None) is not None:
            writer_sid = system['Security'].get('@UserID', '')

        eid = system['EventID']
        if isinstance(eid, collections.OrderedDict):
            eid = eid['#text']

        return {
            'datetime': str(self._isoformat_to_datetime(system['TimeCreated']['@SystemTime'])),
            'epoch': self._isoformat_to_unixepoch(system['TimeCreated']['@SystemTime']),
            'channel': system['Channel'],
            'provider': system['Provider']['@Name'],
            'eid': eid,
            'computer': system['Computer'],
            'writer_sid': writer_sid,
        }

    def __parse_event_or_user_data(self, data_dict):
        event_data = {}

        for key, values in data_dict.items():
            if key.startswith('@'):
                continue

            if isinstance(values, list):
                event_data[key] = []
                for item in values:
                    if item is None:
                        continue

                    if isinstance(item, collections.OrderedDict) and item.get('@Name', None) is not None:
                        event_data[item['@Name']] = item.get('#text', '')
                        object = [item[key] for key in item if key not in ['@Name', '#text']]
                        if len(object) > 0:
                            event_data[item['@Name']] = object
                    else:
                        event_data[key].append(item)

                if len(event_data[key]) == 0:
                    del event_data[key]

            elif isinstance(values, collections.OrderedDict):
                if values.get('@Name', None) is not None:
                    event_data[values['@Name']] = values.get('#text', '')
                    object = [values[key] for key in values if key not in ['@Name', '#text']]
                    if len(object) > 0:
                        event_data[values['@Name']] = object
                else:
                    event_data[key] = values
            else:
                event_data[key] = values

        return event_data

    def __parse_error_data(self, error_data):
        return {
            'error_code': error_data['ErrorCode'],
            'item_name':  error_data['DataItemName'],
            'payload':  error_data['EventPayload'],
        }

    def __enrich(self, event, known_tags):
        event['tags'] = []

        for known in known_tags:
            if known['channel'] == event['channel'] and event['eid'] in known['eids']:
                if known.get('provider', None) is not None and known['provider'] != event['provider']:
                    continue
                event['tags'].extend(known['tags'])

        if len(event['tags']) == 0:
            event['tags'].append('no_tags')

        return event

    def __collect_security_4616(self, event):
        keep_it = True

        # discard legitimate clock drift (NTP sync)
        if event['SubjectUserName'] in ['LOCAL SERVICE', 'SYSTEM']:
            keep_it = False

        # discard minor clock drift (10 min)
        current_time = self._isoformat_to_datetime(event['NewTime'])
        previous_time = self._isoformat_to_datetime(event['PreviousTime'])
        delta = current_time - previous_time
        if delta.total_seconds() < 600:
            keep_it = False

        if keep_it is False:
            return None

        user = '{}\\{} (SID {})'.format(event['SubjectDomainName'], event['SubjectUserName'], event['SubjectUserSid'])
        note = 'before {} ; after {} ; process {}'.format(str(previous_time), str(current_time), event['ProcessName'])
        source = 'EID {}; channel {} ; provider {}'.format(event['eid'], event['channel'], event['provider'])

        return TimelineEntity(
            start=event['datetime'],
            host=event['computer'],
            user=user,
            event='system time changed',
            event_type=TimelineEntity.TIMELINE_TYPE_EVENT,
            source=source,
            note=note
        )

    def __collect_security_1100_1102_1104(self, event):
        user = event['writer_sid']
        if 'SubjectUserSid' in event.keys():
            user = '{}\\{} (SID {})'.format(event['SubjectDomainName'], event['SubjectUserName'], event['SubjectUserSid'])
        source = 'EID {}; channel {} ; provider {}'.format(event['eid'], event['channel'], event['provider'])
        event_desc = 'Logging altered '
        if event['eid'] == '1100':
            event_desc += '(logging service was shut down)'
        if event['eid'] == '1104':
            event_desc += '(security log is full)'
        if event['eid'] == '1102':
            event_desc += '(security log was cleared)'

        return TimelineEntity(
            start=event['datetime'],
            host=event['computer'],
            user=user,
            event=event_desc,
            event_type=TimelineEntity.TIMELINE_TYPE_EVENT,
            source=source
        )

    def __collect_security_4608_4609(self, event):
        event_desc = ''
        if event['eid'] == '4608':
            event_desc = 'Windows is starting up'

        if event['eid'] == '4609':
            event_desc = 'Windows is shutting down'

        source = 'EID {}; channel {} ; provider {}'.format(event['eid'], event['channel'], event['provider'])

        return TimelineEntity(
            start=event['datetime'],
            host=event['computer'],
            user=event['writer_sid'],
            event=event_desc,
            event_type=TimelineEntity.TIMELINE_TYPE_EVENT,
            source=source
        )

    def __collect_system_kernel_general_1(self, event):
        keep_it = True

        # discard legitimate clock drift (2=System time synchronized with the hardware clock)
        if event['Reason'] == '2':
            keep_it = False

        # discard minor clock drift (10 min)
        current_time = self._isoformat_to_datetime(event['NewTime'])
        previous_time = self._isoformat_to_datetime(event['OldTime'])
        delta = current_time - previous_time
        if delta.total_seconds() < 600:
            keep_it = False

        if keep_it is False:
            return None

        note = 'before {} ; after {} ; reason {}'.format(str(previous_time), str(current_time), event['Reason'])
        source = 'EID {}; channel {} ; provider {}'.format(event['eid'], event['channel'], event['provider'])

        return TimelineEntity(
            start=event['datetime'],
            host=event['computer'],
            user=event['writer_sid'],
            event='system time changed',
            event_type=TimelineEntity.TIMELINE_TYPE_EVENT,
            source=source,
            note=note
        )

    def __collect_system_power_1(self, event):
        source = 'EID {}; channel {} ; provider {}'.format(event['eid'], event['channel'], event['provider'])

        return TimelineEntity(
            start=self._isoformat_to_datetime(event['SleepTime']),
            end=self._isoformat_to_datetime(event['WakeTime']),
            host=event['computer'],
            user=event['writer_sid'],
            event='sleeping time',
            event_type=TimelineEntity.TIMELINE_TYPE_EVENT,
            source=source,
        )

    def __collect_system_kernel_general_12_13(self, event):
        source = 'EID {}; channel {} ; provider {}'.format(event['eid'], event['channel'], event['provider'])

        note = ''
        event_desc = ''
        if event['eid'] == '12':
            note = 'start time: {}'.format(str(self._isoformat_to_datetime(event['StartTime'])))
            event_desc = 'system started'
        if event['eid'] == '13':
            note = 'stop time: {}'.format(str(self._isoformat_to_datetime(event['StopTime'])))
            event_desc = 'system started'

        return TimelineEntity(
            start=event['datetime'],
            host=event['computer'],
            user=event['writer_sid'],
            event=event_desc,
            event_type=TimelineEntity.TIMELINE_TYPE_EVENT,
            source=source,
            note=note
        )

    def __collect_system_user32_1074(self, event):
        source = 'EID {}; channel {} ; provider {}'.format(event['eid'], event['channel'], event['provider'])
        note = 'reason: {} (code {}); process: {}'.format(event['param3'], event['param4'], event['param1'])

        return TimelineEntity(
            start=event['datetime'],
            host=event['computer'],
            user=event['param7'],
            event=event['param5'],
            event_type=TimelineEntity.TIMELINE_TYPE_EVENT,
            source=source,
            note=note
        )

    def __collect_system_eventlog_6005_6006(self, event):
        source = 'EID {}; channel {} ; provider {}'.format(event['eid'], event['channel'], event['provider'])

        event_desc = 'event log service '
        if event['eid'] == '6005':
            event_desc += 'started'

        if event['eid'] == '6006':
            event_desc += 'stopped'

        return TimelineEntity(
            start=event['datetime'],
            host=event['computer'],
            user=event['writer_sid'],
            event=event_desc,
            event_type=TimelineEntity.TIMELINE_TYPE_EVENT,
            source=source
        )

    def __collect_application_msiinstaller_11724(self, event):
        source = 'EID {}; channel {} ; provider {}'.format(event['eid'], event['channel'], event['provider'])

        return TimelineEntity(
            start=event['datetime'],
            host=event['computer'],
            user=event['writer_sid'],
            event='application successfully removed',
            event_type=TimelineEntity.TIMELINE_TYPE_EVENT,
            source=source,
            note=event['Data'][0]
        )

    def __collect_partition_diagnostic_1006(self, event):
        # when capacity is zero, it is just an unplug
        if event['Capacity'] == "0":
            return None

        info = {
            'bytes_capacity': event['Capacity'],
            'manufacturer': event['Manufacturer'],
            'model': event['Model'],
            'revision': event['Revision'],
            'disk_serial_number': event['SerialNumber'],
            'disk_guid': event['DiskId'],
            'adapter_guid': event['AdapterId'],
            'registry_guid': event['RegistryId'],
        }

        parent_id = event['ParentId'].split('\\')
        if parent_id[0] == 'PCI':
            info['vendor_product'] = parent_id[1]

        if parent_id[0] == 'USB':
            info['vid_pid'] = parent_id[1]
        info['serial_number'] = parent_id[2]

        partition_table = event['PartitionTable']
        partition_type = partition_table[0:8]
        if partition_type == '00000000':
            info['partition_type'] = self._PARTITION_MBR
            info['disk_signature'] = partition_table[16:24].lower()

        if partition_type == '01000000':
            info['partition_type'] = self._PARTITION_GPT
            info['partitions_guid'] = []
            for i in range(0, len(partition_table)-1, 32):
                # collect the partition GUID if its header is "Basic Data Partition"
                if partition_table[i:i+32].lower() == 'a2a0d0ebe5b9334487c068b6b72699c7':
                    info['partitions_guid'].append(partition_table[i+32:i+64].lower())
        return info

    def __collect_kernel_pnp_410_430(self, event):
        if not event['DeviceInstanceId'].startswith('USB\\'):
            return None

        # pattern is USB\VID_XXX&PID_YYY\<SN>
        instance_id = event['DeviceInstanceId'].split('\\')
        vid_pid = instance_id[1]
        serial_number = instance_id[2]

        source = 'EID {}; channel {} ; provider {}'.format(event['eid'], event['channel'], event['provider'])
        note = '{}#{}'.format(vid_pid, serial_number)

        return TimelineEntity(
            start=event['datetime'],
            host=event['computer'],
            user=event['writer_sid'],
            event='USB device started',
            event_type=TimelineEntity.TIMELINE_TYPE_EVENT,
            source=source,
            note=note
        )
