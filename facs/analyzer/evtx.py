from facs.entity.report import ReportEntity
import json
from xml.dom import minidom
import pyevtx
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

    def extract_generic(self, evtx_file):
        evtx = pyevtx.file()
        evtx.open(evtx_file)

        nb_events = evtx.get_number_of_records()
        if nb_events == 0:
            return 0, 0, None

        events = []
        nb_dropped = 0
        for record in evtx.records:
            try:
                xml = record.get_xml_string()
                dom = minidom.parseString(xml)
            except Exception:
                # when xmlns is missing, an error is raised
                nb_dropped += 1
                continue

            event = {'raw': xml}

            # system info
            event.update(self.__parse_common_data(dom))

            # specific info
            if len(dom.getElementsByTagName('EventData')) > 0:
                parsed = self.__parse_event_data(dom)
                if parsed is not None:
                    event.update(parsed)
            elif len(dom.getElementsByTagName('ProcessingErrorData')) > 0:
                event.update(self.__parse_error_data(dom))
            elif len(dom.getElementsByTagName('UserData')) > 0:
                parsed = self.__parse_user_data(dom)
                if parsed is not None:
                    event.update(parsed)

            # enrich with tags
            event = self.__enrich(event)

            events.append(event)

        evtx.close()

        return nb_events, nb_dropped, events

    def __parse_common_data(self, dom):
        return {
            'datetime': str(self._isoformat_to_datetime(dom.getElementsByTagName('TimeCreated')[0].getAttribute('SystemTime'))),
            'channel': dom.getElementsByTagName('Channel')[0].firstChild.data,
            'provider': dom.getElementsByTagName('Provider')[0].getAttribute('Name'),
            'eid': dom.getElementsByTagName('EventID')[0].firstChild.data,
            'computer': dom.getElementsByTagName('Computer')[0].firstChild.data,
            'writer_sid': dom.getElementsByTagName('Security')[0].getAttribute('UserID'),
        }

    def __parse_event_data(self, dom):
        data = dom.getElementsByTagName('EventData')[0]
        event_data = {
            'misc': [],
        }
        for child in data.childNodes:
            if child.nodeType != minidom.Node.ELEMENT_NODE:
                continue

            if child.tagName == 'Data':
                if child.hasAttribute('Name') is True:
                    event_data[child.getAttribute('Name')] = child.firstChild.data if child.firstChild is not None else ''
                else:
                    event_data['misc'].append(child.firstChild.data if child.firstChild is not None else '')
            else:
                event_data[child.tagName] = child.firstChild.data if child.firstChild is not None else ''

        event_data['misc'] = ';'.join(event_data['misc'])
        if event_data['misc'] == '':
            del event_data['misc']

        if len(event_data) == 0:
            return None

        return event_data

    def __parse_error_data(self, dom):
        data = dom.getElementsByTagName('ProcessingErrorData')[0]
        return {
            'error_code': data.getElementsByTagName('ErrorCode')[0].firstChild.data,
            'item_name':  data.getElementsByTagName('DataItemName')[0].firstChild.data,
            'payload':  data.getElementsByTagName('EventPayload')[0].firstChild.data,
        }

    def __parse_user_data(self, dom):
        data = dom.getElementsByTagName('UserData')[0]
        event = {}

        content = None
        for child in data.childNodes:
            if child.nodeType == minidom.Node.ELEMENT_NODE:
                content = child
                break

        if content is None or content.hasChildNodes() is False:
            return None

        for child in content.childNodes:
            if child.nodeType != minidom.Node.ELEMENT_NODE:
                continue

            if child.hasChildNodes() is False:
                event[child.tagName] = ''
            if child.hasChildNodes() is True and child.firstChild.nodeType == minidom.Node.TEXT_NODE:
                event[child.tagName] = child.firstChild.data
            if child.hasChildNodes() is True and child.firstChild.nodeType == minidom.Node.ELEMENT_NODE:
                elts = []
                for subchild in child.childNodes:
                    text = subchild.firstChild.data if subchild.firstChild is not None else ''
                    elts.append(text)
                event[child.tagName] = ';'.join([elt for elt in elts if elt != ''])

        return event

    def __enrich(self, event):
        event['timestamp'] = self._isoformat_to_unixepoch(event['datetime'])
        event['source'] = 'log_evtx'

        # add tags for known events
        event['tags'] = []

        if event['channel'] == 'Security' and event['provider'] == 'Microsoft-Windows-Security-Auditing' and event['eid'] in ['4608', '4609']:
            event['tags'].append('os_start_stop')

        if event['channel'] == 'Security' and event['provider'] == 'Microsoft-Windows-Eventlog' and event['eid'] in ['1100', '1102', '1104']:
            event['tags'].append('logging_altered')

        if event['channel'] == 'Security' and event['provider'] == 'Microsoft-Windows-Security-Auditing' and event['eid'] in ['4624', '4625', '4648']:
            event['tags'].append('authn')

        if event['channel'] == 'Security' and event['provider'] == 'Microsoft-Windows-Security-Auditing' and event['eid'] in ['4634', '4647']:
            event['tags'].append('logoff')

        if event['channel'] == 'Security' and event['provider'] == 'Microsoft-Windows-Security-Auditing' and event['eid'] in ['4672', '4964']:
            event['tags'].extend(['authn', 'authn_privileged'])

        if event['channel'] == 'Security' and event['provider'] == 'Microsoft-Windows-Security-Auditing' and event['eid'] in ['4768', '4771', '4772']:
            event['tags'].extend(['dc', 'authn', 'authn_domain_kerberos', 'tgt_request'])

        if event['channel'] == 'Security' and event['provider'] == 'Microsoft-Windows-Security-Auditing' and event['eid'] in ['4769', '4770', '4773']:
            event['tags'].extend(['dc', 'authz', 'authz_domain_kerberos', 'tgs_request'])

        if event['channel'] == 'Security' and event['provider'] == 'Microsoft-Windows-Security-Auditing' and event['eid'] in ['4776', '4777']:
            event['tags'].extend(['dc', 'authn', 'authn_domain_ntlm'])

        if event['channel'] == 'Security' and event['provider'] == 'Microsoft-Windows-Security-Auditing' and event['eid'] in ['4825', '4778', '4779']:
            event['tags'].extend(['rdp', 'rdp_incoming'])

        if event['channel'] == 'Security' and event['provider'] == 'Microsoft-Windows-Security-Auditing' and event['eid'] == '4720':
            event['tags'].extend('user_new')

        if event['channel'] == 'Security' and event['provider'] == 'Microsoft-Windows-Security-Auditing' and event['eid'] in ['4728', '4732', '4756']:
            event['tags'].extend(['user_groups_modified'])

        if event['channel'] == 'Security' and event['provider'] == 'Microsoft-Windows-Security-Auditing' and event['eid'] in ['4798', '4799']:
            event['tags'].extend(['user_groups_enumeration'])

        if event['channel'] == 'Security' and event['provider'] == 'Microsoft-Windows-Security-Auditing' and event['eid'] in ['5140', '5141', '5142', '5143', '5144', '5145']:
            event['tags'].extend(['network_share_access'])

        if event['channel'] == 'Security' and event['provider'] == 'Microsoft-Windows-Security-Auditing' and event['eid'] in ['4688', '4689']:
            event['tags'].extend(['service_process', 'process_execution'])

        if event['channel'] == 'Security' and event['provider'] == 'Microsoft-Windows-Security-Auditing' and event['eid'] == '4697':
            event['tags'].extend(['service_new'])

        if event['channel'] == 'Security' and event['provider'] == 'Microsoft-Windows-Security-Auditing' and event['eid'] == '4698':
            event['tags'].extend(['scheduled_jobs', 'scheduled_jobs_new'])

        if event['channel'] == 'Security' and event['provider'] == 'Microsoft-Windows-Security-Auditing' and event['eid'] in ['5024', '5025']:
            event['tags'].extend(['local_firewall_start_stop'])

        if event['channel'] == 'Security' and event['provider'] == 'Microsoft-Windows-Security-Auditing' and event['eid'] in ['5156', '5157']:
            event['tags'].extend(['network_connection_allowed_blocked'])

        if event['channel'] == 'Security' and event['provider'] == 'Microsoft-Windows-Security-Auditing' and event['eid'] == '6416':
            event['tags'].extend(['external_device_new'])

        if event['channel'] == 'Security' and event['provider'] == 'Microsoft-Windows-Security-Auditing' and event['eid'] == '4693':
            event['tags'].extend(['dc', 'dc_dpapi_key_recovery'])

        if event['channel'] == 'Security' and event['provider'] == 'Microsoft-Windows-Security-Auditing' and event['eid'] in ['4932', '4933']:
            event['tags'].extend(['dc', 'dc_replication_start_stop'])

        if event['channel'] == 'Security' and event['provider'] == 'Microsoft-Windows-Security-Auditing' and event['eid'] == '4657':
            event['tags'].extend(['reg_key_modified'])

        if event['channel'] == 'Security' and event['provider'] == 'Microsoft-Windows-Security-Auditing' and event['eid'] == '6416':
            event['tags'].extend(['external_device_new'])

        if event['channel'] == 'System' and event['provider'] == 'Microsoft-Windows-Kernel-General' and event['eid'] in ['12', '13']:
            event['tags'].extend(['system_start_stop'])

        if event['channel'] == 'System' and event['provider'] == 'Service Control Manager' and event['eid'] == '7045':
            event['tags'].extend(['service_process', 'service_new'])

        if event['channel'] == 'System' and event['provider'] == 'Service Control Manager' and event['eid'] in ['7034', '7035', '7040']:
            event['tags'].extend(['service_process', 'service_start_stop'])

        if event['channel'] == 'Microsoft-Windows-TaskScheduler/Operational' and event['eid'] == '106':
            event['tags'].extend(['scheduled_jobs', 'scheduled_jobs_new'])

        if event['channel'] == 'Microsoft-Windows-TaskScheduler/Operational' and event['eid'] in ['200', '201']:
            event['tags'].extend(['scheduled_jobs', 'scheduled_jobs_execution'])

        if event['channel'] == 'Microsoft-Windows-TerminalServices-RDPClient/Operational' and event['eid'] in ['1024', '1029', '1102']:
            event['tags'].extend(['rdp', 'rdp_outgoing'])

        if event['channel'] == 'Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational' and event['eid'] == '131':
            event['tags'].extend(['rdp', 'rdp_incoming'])

        if event['channel'] == 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational' and event['eid'] == '1149':
            event['tags'].extend(['rdp', 'rdp_incoming'])

        if event['channel'] == 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational' and event['eid'] in ['21', '22', '24', '25']:
            event['tags'].extend(['rdp', 'rdp_incoming'])

        if event['channel'] == 'Microsoft-Windows-WinRM/Operational' and event['eid'] == '6':
            event['tags'].extend(['winrm_source_execution'])

        if event['channel'] == 'Microsoft-Windows-WinRM/Operational' and event['eid'] == '169':
            event['tags'].extend(['winrm_destination_execution'])

        if event['channel'] == 'Windows Powershell' and event['eid'] in ['400', '403']:
            event['tags'].extend(['powershell', 'powershell_start_stop'])

        if event['channel'] == 'Microsoft-Windows-PowerShell/Operational' and event['eid'] in ['4013', '4104']:
            event['tags'].extend(['powershell', 'powershell_execution'])

        if event['channel'] == 'Microsoft-Windows-Shell-Core/Operational' and event['eid'] in ['9707', '9708']:
            event['tags'].extend(['reg_runkey_execution'])

        if event['channel'] == 'Microsoft-Windows-Bits-Client/Operational' and event['eid'] == '59':
            event['tags'].extend(['bits_download_upload'])

        if event['channel'] == 'Microsoft-Windows-DNS-Client/Operational' and event['eid'] == '3006':
            event['tags'].append('dns_query')

        if event['channel'] == 'Microsoft-Windows-DriverFrameworks-UserMode/Operational' and event['eid'] in ['2101', '2102']:
            event['tags'].extend(['external_device_connection'])

        if event['channel'] == 'Microsoft-Windows-MBAM/Operational' and event['eid'] in ['39', '40']:
            event['tags'].extend(['external_device_mounting'])

        if event['channel'] == 'OAlerts' and event['eid'] == '300':
            event['tags'].extend(['graphical', 'office_doc_access'])

        # catch all
        if len(event['tags']) == 0:
            event['tags'] = 'no_tags'

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
            note=event['misc']
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
