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

        return group

    def get_cheat_sheet_misc(self):
        manual = []
        for elt in self._data['manual_mining']:
            line = '{:80}: {}'.format(elt['description'], elt['note'])
            manual.append(line)
        self._print_text('Manual mining', manual)

    def get_tool_patterns(self):
        for pattern in self._data['patterns']:
            self._print_text('Known/Possible patterns for the tool: {}'.format(pattern['tool']), pattern['detection'])
