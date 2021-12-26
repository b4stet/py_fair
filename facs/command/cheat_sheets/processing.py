import click
from facs.command.abstract import AbstractCommand


class ProcessingCommand(AbstractCommand):

    def __init__(self):
        super().__init__('processing.yaml')

    def get_commands(self):
        group = click.Group(
            'processing',
            help='cheat sheets to forensicate a target system',
        )

        group.add_command(click.Command(
            name='windows', help='manual mining ideas',
            callback=self.windows_mining
        ))

        group.add_command(click.Command(
            name='analyse_ip', help='check points for an IP address',
            callback=self.ip_analysis
        ))

        group.add_command(click.Command(
            name='analyse_url_shortener', help='tips to uncover real site behind a shortened link',
            callback=self.url_shortener_analysis
        ))

        group.add_command(click.Command(
            name='known_patterns', help='some known artifacts left by attacker toolbox',
            callback=self.get_tool_patterns
        ))

        group.add_command(click.Command(
            name='default_values', help='some default configuration values observed',
            callback=self.list_defaults
        ))

        return group

    def windows_mining(self):
        manual = []
        for elt in self._data['windows_mining']:
            line = '{:80}: {}'.format(elt['description'], elt['note'])
            manual.append(line)
        self._print_text('Windows artifacts', manual)

    def get_tool_patterns(self):
        patterns = []
        for elt in self._data['patterns']:
            for pattern in elt['detection']:
                line = 'tool: {:40} pattern: {}'.format(elt['tool'], pattern)
                patterns.append(line)
        self._print_text('Known/Possible patterns of adversaries tools', patterns)

    def list_defaults(self):
        defaults = []
        for elt in self._data['default_values']:
            line = '{:60}: {}'.format(elt['description'], elt['value'])
            defaults.append(line)
        self._print_text('Some default values of software', defaults)

    def ip_analysis(self):
        self._print_text('Information related to an IP address', self._data['ip_address'])

    def url_shortener_analysis(self):
        self._print_text('Uncover shortened links', self._data['url_shortener'])
