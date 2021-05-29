import click
from facs.command.abstract import AbstractCommand


class LogsCommand(AbstractCommand):
    def __init__(self):
        super().__init__('logs.yaml')

    def get_commands(self):
        group = click.Group(
            'logs',
            help='list fields/events of interest from various sources (firewall, proxy, mail, ...)',
            context_settings=dict(terminal_width=120)
        )

        group.add_command(click.Command(
            name='firewall', help='list fields of interest from firewall logs',
            callback=self.list_firewall
        ))
        group.add_command(click.Command(
            name='proxy', help='list fields of interest from proxy logs',
            callback=self.list_proxy
        ))
        group.add_command(click.Command(
            name='mail', help='list fields of interest from mail gateway logs',
            callback=self.list_mail
        ))
        group.add_command(click.Command(
            name='av_edr', help='list fields of interest from antivirus/edr logs',
            callback=self.list_antivirus
        ))

        group.add_command(click.Command(
            name='windows', help='list path of artifacts on Windows and useful event IDs',
            callback=self.list_logs_windows
        ))

        group.add_command(click.Command(
            name='defaults', help='list default values in some software configuration (teamviewer, vns, ...)',
            callback=self.list_defaults
        ))

        return group

    def list_firewall(self):
        self._print_text('From firewall logs', self._data['firewall'])

    def list_proxy(self):
        self._print_text('From proxy logs', self._data['proxy'])

    def list_mail(self):
        self._print_text('From mail gateway logs', self._data['mail'])

    def list_antivirus(self):
        self._print_text('From antivirus/edr logs', self._data['av_edr'])

    def list_logs_windows(self):
        paths = []
        for elt in self._data['windows']['artifacts_paths']:
            line = '{:80}: {}'.format(elt['description'], elt['path'])
            paths.append(line)
        self._print_text('On windows, main artifacts paths', paths)

        for source in self._data['windows']['evtx']:
            events = []
            if source['channel'].lower() == 'security':
                events = ['EIDs: {:30} desc: {:65} audit to enable: {}'.format(event['eid'], event['description'], event['policy']) for event in source['eids']]
            else:
                events = ['EIDs: {:30} desc: {}'.format(event['eid'], event['description']) for event in source['eids']]
            self._print_text('Events from channel {}'.format(source['channel']), events)

    def list_defaults(self):
        defaults = []
        for elt in self._data['defaults']:
            line = '{:40}: {}'.format(elt['description'], elt['value'])
            defaults.append(line)
        self._print_text('Some default values of software', defaults)
