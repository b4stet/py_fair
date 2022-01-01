import click
from fair.command.abstract import AbstractCommand


class LogsCommand(AbstractCommand):
    def __init__(self):
        super().__init__('logs.yaml')

    def get_commands(self):
        group = click.Group(
            'logs',
            help='list fields/artifacts of interest from various sources (firewall, mail, windows, ...)',
            context_settings=dict(terminal_width=120)
        )

        group.add_command(click.Command(
            name='fields', help='list fields of interest from firewall logs',
            callback=self.list_fields
        ))

        group.add_command(click.Command(
            name='windows', help='list path of artifacts on Windows and useful event IDs',
            callback=self.list_logs_windows
        ))

        return group

    def list_fields(self):
        for source in self._data['fields']:
            self._print_text('Fields from {} logs'.format(source['name']), source['fields'])

    def list_logs_windows(self):
        paths = []
        for elt in self._data['windows']['artifacts_paths']:
            line = '{:80}: {}'.format(elt['description'], elt['path'])
            paths.append(line)
        self._print_text('On windows, main artifacts paths', paths)

        meaning = []
        for elt in self._data['windows']['artifacts_meaning']:
            line = '{:60}: {}'.format(elt['description'], elt['note'])
            meaning.append(line)
        self._print_text('On windows, some artifacts meaning', meaning)

        source = self._data['windows']['evtx_security']
        events = ['EIDs: {:30} desc: {:65} audit to enable: {}'.format(event['eid'], event['description'], event['policy']) for event in source]
        self._print_text('Events from Security channel', events)

        source = self._data['windows']['evtx_system']
        events = ['EIDs: {:30} desc: {}'.format(event['eid'], event['description']) for event in source]
        self._print_text('Events from System channel', events)

        source = self._data['windows']['evtx_app_services']
        events = ['EIDs: {:30} channel: {:80} desc: {}'.format(event['eid'], event['channel'], event['description']) for event in source]
        self._print_text('Events from channels under Application and Services Logs', events)
