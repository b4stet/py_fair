import json
from xml.dom import minidom
from dateutil import parser
from facs.entity.timeline import TimelineEntity
from facs.bo.abstract import AbstractBo


class EvtxBo(AbstractBo):
    CHANNELS_MIN = [
        'Security',
        'System',
        'Microsoft-Windows-TaskScheduler/Operational',
        'Microsoft-Windows-TerminalServices-RDPClient/Operational',
        'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational',
        'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational',
    ]

    def get_profiling_from_evtx(self, fd_evtx):
        computer = None
        cleaning = []
        backdating = []
        start_stop = []
        start_end = {channel: {'start': None, 'end': None} for channel in self.CHANNELS_MIN}

        nb_events = 0
        for line in fd_evtx:
            nb_events += 1
            event = json.loads(line)
            info = self.__extract_common(event['xml_string'])
            channel = info['channel']
            provider = info['provider']
            event_id = info['event_id']

            if computer is None:
                computer = info['computer']

            # collect start/end of logs
            if channel in self.CHANNELS_MIN:
                if start_end[channel]['start'] is None or info['datetime'] < start_end[channel]['start']:
                    start_end[channel]['start'] = info['datetime']

                if start_end[channel]['end'] is None or info['datetime'] > start_end[channel]['end']:
                    start_end[channel]['end'] = info['datetime']

            # check time changes, logging tampered and windows start/stop from Security channel
            if channel == 'Security':
                if provider == 'Microsoft-Windows-Security-Auditing' and event_id == '4616':
                    data = self.__extract_security_4616(event['xml_string'])
                    event_processed = self.__process_security_4616(info, data)
                    backdating = self._append_to_timeline(event_processed, backdating)

                if provider == 'Microsoft-Windows-Security-Auditing' and event_id in ['4608', '4609']:
                    event_processed = self.__process_security_4608_4609(info)
                    start_stop = self._append_to_timeline(event_processed, start_stop)

                if provider == 'Microsoft-Windows-Eventlog' and event_id in ['1100', '1102', '1104']:
                    data = self.__extract_security_1100_1102_1104(event['xml_string'])
                    event_processed = self.__process_security_1100_1102_1104(info, data)
                    cleaning = self._append_to_timeline(event_processed, cleaning)

            # check time changes, logging tampered and windows start/stop from System channel
            if channel == 'System':
                if provider == 'Microsoft-Windows-Kernel-General' and event_id == '1':
                    data = self.__extract_system_1(event['xml_string'])
                    event_processed = self.__process_system_1(info, data)
                    backdating = self._append_to_timeline(event_processed, backdating)

                if provider == 'Microsoft-Windows-Kernel-General' and event_id in ['12', '13']:
                    data = self.__extract_system_12_13(event['xml_string'])
                    event_processed = self.__process_system_12_13(info, data)
                    start_stop = self._append_to_timeline(event_processed, start_stop)

                if provider == 'User32' and event_id == '1074':
                    data = self.__extract_system_1074(event['xml_string'])
                    event_processed = self.__process_system_1074(info, data)
                    start_stop = self._append_to_timeline(event_processed, start_stop)

                if provider == 'EventLog' and event_id in ['6005', '6006']:
                    event_processed = self.__process_system_6005_6006(info)
                    cleaning = self._append_to_timeline(event_processed, cleaning)

        return nb_events, computer, backdating, cleaning, start_stop, start_end

    def __extract_common(self, evtx_xml):
        event = minidom.parseString(evtx_xml)
        system = event.getElementsByTagName('System')[0]
        info = {
            'datetime': self._isoformat_to_datetime(system.getElementsByTagName('TimeCreated')[0].getAttribute('SystemTime')),
            'channel': system.getElementsByTagName('Channel')[0].firstChild.data,
            'provider': system.getElementsByTagName('Provider')[0].getAttribute('Name'),
            'event_id': system.getElementsByTagName('EventID')[0].firstChild.data,
            'computer': system.getElementsByTagName('Computer')[0].firstChild.data,
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
            start=str(info['datetime']),
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
        user = ''
        if 'sid' in data.keys():
            user = '{}\\{} (SID {})'.format(data['domain'], data['username'], data['sid'])
        source = 'EID {}; channel {} ; provider {}'.format(info['event_id'], info['channel'], info['provider'])

        return TimelineEntity(
            start=str(info['datetime']),
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
            start=str(info['datetime']),
            host=info['computer'],
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
            start=str(info['datetime']),
            host=info['computer'],
            event='system time changed',
            event_type=TimelineEntity.TIMELINE_TYPE_EVENT,
            source=source,
            note=note
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
            start=str(info['datetime']),
            host=info['computer'],
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
            start=str(info['datetime']),
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
            start=str(info['datetime']),
            host=info['computer'],
            event=event,
            event_type=TimelineEntity.TIMELINE_TYPE_EVENT,
            source=source
        )
