import click
import json
import sys
from facs.command.abstract import AbstractCommand
from facs.entity.timeline import TimelineEntity


class ProcessingCommand(AbstractCommand):
    __CHANNELS_MIN = [
        'Security',
        'System',
        'Microsoft-Windows-TaskScheduler/Operational',
        'Microsoft-Windows-TerminalServices-RDPClient/Operational',
        'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational',
        'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational',
    ]

    def __init__(self, evtx_bo):
        super().__init__('processing.yaml')
        self.__evtx_bo = evtx_bo

    def get_commands(self):
        group = click.Group(
            'processing',
            help='cheat sheets and scripts to forensicate',
            context_settings=dict(terminal_width=120)
        )

        group.add_command(click.Command(
            name='misc', help='cheat sheets for other possible steps in the analysis (manual mining, ...)',
            callback=self.get_cheat_sheet_misc
        ))

        group.add_command(click.Command(
            name='tool_patterns', help='cheat sheets of known artifacts left by attacker toolbox (psexec, mimikatz, ...)',
            callback=self.get_tool_patterns
        ))

        group.add_command(click.Command(
            name='list_defaults', help='list of default values in tool configuration (RAT, reverse shells, ...)',
            callback=self.list_defaults
        ))

        group.add_command(click.Command(
            name='win_profiling', help='profile users and system based on evtx and registry',
            callback=self.do_win_profiling,
            params=[self._get_option_evtx()]
        ))

        return group

    def get_cheat_sheet_misc(self):
        manual = []
        for elt in self._data['manual_mining']:
            line = '{:80}: {}'.format(elt['description'], elt['note'])
            manual.append(line)
        self._print_text('Manual mining', manual)

    def get_tool_patterns(self):
        patterns = []
        for elt in self._data['patterns']:
            for pattern in elt['detection']:
                line = 'tool: {:40} pattern: {}'.format(elt['tool'], pattern)
                patterns.append(line)
        self._print_text('Known/Possible patterns of adversaries tools', patterns)

    def list_defaults(self):
        defaults = []
        for elt in self._data['defaults']:
            line = '{:60}: {}'.format(elt['description'], elt['value'])
            defaults.append(line)
        self._print_text('Some default values of software', defaults)

    def do_win_profiling(self, evtx):
        fd_in = open(evtx, mode='r', encoding='utf8')

        # loop on events
        computer = None
        cleaning = []
        backdating = []
        start_stop = []
        start_end = {channel: {'start': None, 'end': None} for channel in self.__CHANNELS_MIN}
        for line in fd_in:
            event = json.loads(line)
            info = self.__evtx_bo.extract_system_info(event['xml_string'])
            channel = info['channel']
            provider = info['provider']
            event_id = info['event_id']

            if computer is None:
                computer = info['computer']

            # collect start/end of logs
            if channel in self.__CHANNELS_MIN:
                if start_end[channel]['start'] is None or info['datetime'] < start_end[channel]['start']:
                    start_end[channel]['start'] = info['datetime']

                if start_end[channel]['end'] is None or info['datetime'] > start_end[channel]['end']:
                    start_end[channel]['end'] = info['datetime']

            # check time changes, logging tampered and windows start/stop from Security channel
            if channel == 'Security':
                if provider == 'Microsoft-Windows-Security-Auditing' and event_id == '4616':
                    data = self.__evtx_bo.extract_security_4616(event['xml_string'])
                    event_processed = self.__evtx_bo.process_security_4616(info, data)
                    backdating = self.__append_to_timeline(event_processed, backdating)

                if provider == 'Microsoft-Windows-Security-Auditing' and event_id in ['4608', '4609']:
                    event_processed = self.__evtx_bo.process_security_4608_4609(info)
                    start_stop = self.__append_to_timeline(event_processed, start_stop)

                if provider == 'Microsoft-Windows-Eventlog' and event_id in ['1100', '1102', '1104']:
                    data = self.__evtx_bo.extract_security_1100_1102_1104(event['xml_string'])
                    event_processed = self.__evtx_bo.process_security_1100_1102_1104(info, data)
                    cleaning = self.__append_to_timeline(event_processed, cleaning)

            # check time changes, logging tampered and windows start/stop from System channel
            if channel == 'System':
                if provider == 'Microsoft-Windows-Kernel-General' and event_id == '1':
                    data = self.__evtx_bo.extract_system_1(event['xml_string'])
                    event_processed = self.__evtx_bo.process_system_1(info, data)
                    backdating = self.__append_to_timeline(event_processed, backdating)

                if provider == 'Microsoft-Windows-Kernel-General' and event_id in ['12', '13']:
                    data = self.__evtx_bo.extract_system_12_13(event['xml_string'])
                    event_processed = self.__evtx_bo.process_system_12_13(info, data)
                    start_stop = self.__append_to_timeline(event_processed, start_stop)

        fd_in.close()

        # assemble timeline
        timeline = []
        print('[+] Checked start/end of windows event log for main channels ')
        for channel in self.__CHANNELS_MIN:
            print(' | {}'.format(channel))
        missing_channels = []
        for channel, values in start_end.items():
            if values['start'] is None:
                missing_channels.append(channel)
                continue

            event = TimelineEntity(
                start=str(values['start']),
                end=str(values['end']),
                host=computer,
                event='log start/end for channel {}'.format(channel),
                event_type=TimelineEntity.TIMELINE_TYPE_LOG,
                source='channel {}.evtx'.format(channel)
            )

            timeline.append(event.to_dict())

        if len(missing_channels) > 0:
            print(' | No events found from channels [{}]'.format(','.join(missing_channels)))

        print('\n[+] Checked backdating evidences')
        print(' | Looked for clock drift bigger than 10 minutes')
        print(' | From Security channel, looked for provider Microsoft-Windows-Security-Auditing, EID 4616 where user is not "LOCAL SERVICE" or "SYSTEM"')
        print(' | From System channel, looked for provider Microsoft-Windows-Kernel-General, EID 1 where reason is not 2')
        print(' | Found: {} matching event(s)'.format(len(backdating)))
        timeline += backdating

        print('\n[+] Checked log tampering')
        print(' | From Security channel, looked for provider Microsoft-Windows-Eventlog, EID 1100/1102/1104')
        print(' | Found {} event(s)'.format(len(cleaning)))
        timeline += cleaning

        print('\n[+] Checked start/stop of the host')
        print(' | From Security channel, looked for provider Microsoft-Windows-Eventlog, EID 4608/4609')
        print(' | From System channel, looked for provider Microsoft-Windows-Kernel-General, EID 12/13')
        print(' | Found {} event(s)'.format(len(start_stop)))
        timeline += start_stop

        timeline = sorted(timeline, key=lambda k: k['start'])

        print('\n[+] Timeline')
        self._print_formatted(self.OUTPUT_CSV, timeline)

    def __append_to_timeline(self, event, timeline):
        if event is None:
            return timeline

        formatted = event.to_dict()

        # ensure no duplicates
        if formatted not in timeline:
            timeline.append(formatted)

        return timeline
