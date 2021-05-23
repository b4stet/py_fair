import click
from facs.command.abstract import AbstractCommand


class LogfileCommand(AbstractCommand):
    def __init__(self):
        super().__init__('logs.yaml')

    def get_commands(self):
        group = click.Group(
            'logs',
            help='List fields of interest for various sources (firewall, proxy, mail, ...)',
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
            name='evtx', help='list events of interest from evtx logs',
            params=[self._get_option_pattern()],
            callback=self.list_evtx
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

    def list_evtx(self, pattern=None):
        keywords = []
        if pattern is not None:
            keywords = pattern.split(',')

        for source in self._data['evtx']:
            events = []
            if source['channel'].lower() == 'security':
                events = ['EIDs: {:30} desc: {:65} audit to enable: {}'.format(event['eid'], event['description'], event['policy']) for event in source['eids']]
            else:
                events = ['EIDs: {:30} desc: {}'.format(event['eid'], event['description']) for event in source['eids']]

            if len(keywords) > 0:
                events = [event for event in events if any(keyword.lower() in event.lower() for keyword in keywords)]

            if len(events) > 0:
                self._print_text('Events from channel {}'.format(source['channel']), events)
