from xml.dom import minidom
from dateutil import parser
from facs.entity.timeline import TimelineEntity


class EvtxBo():
    def __init__(self):
        pass

    def extract_system_info(self, evtx_xml):
        event = minidom.parseString(evtx_xml)
        system = event.getElementsByTagName('System')[0]
        info = {
            'datetime': parser.isoparse(system.getElementsByTagName('TimeCreated')[0].getAttribute('SystemTime')),
            'channel': system.getElementsByTagName('Channel')[0].firstChild.data,
            'provider': system.getElementsByTagName('Provider')[0].getAttribute('Name'),
            'event_id': system.getElementsByTagName('EventID')[0].firstChild.data,
            'computer': system.getElementsByTagName('Computer')[0].firstChild.data,
        }

        return info

    def extract_security_4616(self, evtx_xml):
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
                info['previous_time'] = parser.isoparse(elt.firstChild.data)

            if attribute == 'NewTime':
                info['current_time'] = parser.isoparse(elt.firstChild.data)

            if attribute == 'ProcessName':
                info['process'] = elt.firstChild.data

        return info

    def process_security_4616(self, info, data):
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

    def extract_security_1100_1102_1104(self, evtx_xml):
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

    def process_security_1100_1102_1104(self, info, data):
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

    def process_security_4608_4609(self, info):
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

    def extract_system_1(self, evtx_xml):
        event = minidom.parseString(evtx_xml)
        data = event.getElementsByTagName('EventData')[0].getElementsByTagName('Data')
        info = {}
        for elt in data:
            attribute = elt.getAttribute('Name')
            if attribute == 'OldTime':
                info['previous_time'] = parser.isoparse(elt.firstChild.data)

            if attribute == 'NewTime':
                info['current_time'] = parser.isoparse(elt.firstChild.data)

            if attribute == 'Reason':
                info['reason'] = elt.firstChild.data

        return info

    def process_system_1(self, info, data):
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

    def extract_system_12_13(self, evtx_xml):
        event = minidom.parseString(evtx_xml)
        data = event.getElementsByTagName('EventData')[0].getElementsByTagName('Data')
        info = {}
        for elt in data:
            attribute = elt.getAttribute('Name')
            if attribute == 'StopTime':
                info['event'] = 'system stopped'
                info['time'] = parser.isoparse(elt.firstChild.data)

            if attribute == 'StartTime':
                info['event'] = 'system started'
                info['time'] = parser.isoparse(elt.firstChild.data)

        return info

    def process_system_12_13(self, info, data):
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
