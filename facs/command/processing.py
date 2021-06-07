import click
from facs.command.abstract import AbstractCommand


class ProcessingCommand(AbstractCommand):
    def __init__(self):
        super().__init__('processing.yaml')

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
                line = 'tool: {:20} pattern: {}'.format(elt['tool'], pattern)
                patterns.append(line)
        self._print_text('Known/Possible patterns of adversaries tools', patterns)

    def list_defaults(self):
        defaults = []
        for elt in self._data['defaults']:
            line = '{:60}: {}'.format(elt['description'], elt['value'])
            defaults.append(line)
        self._print_text('Some default values of software', defaults)
