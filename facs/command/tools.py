import click
from facs.command.abstract import AbstractCommand


class ToolsCommand(AbstractCommand):
    def __init__(self):
        super().__init__('tools.yaml')

    def get_commands(self):
        group = click.Group(
            'tools',
            help='cheat sheets on some tools',
            context_settings=dict(terminal_width=120)
        )

        group.add_command(click.Command(
            name='sleuthkit', help='notes about tsk',
            callback=self.get_notes_tsk
        ))

        group.add_command(click.Command(
            name='volatility2', help='notes about volatility2',
            callback=self.get_notes_vol2
        ))

        group.add_command(click.Command(
            name='plaso', help='notes about plaso',
            callback=self.get_notes_plaso
        ))

        group.add_command(click.Command(
            name='tshark', help='notes about tshark',
            callback=self.get_notes_tshark
        ))

        group.add_command(click.Command(
            name='yara', help='notes about yara',
            callback=self.get_notes_yara
        ))

        group.add_command(click.Command(
            name='nsrl', help='cheat sheet to extract nsrl datasets',
            callback=self.get_notes_nsrl
        ))

        group.add_command(click.Command(
            name='misc', help='cheat sheet on some useful bash commands',
            callback=self.get_notes_misc
        ))

        return group

    def get_notes_tsk(self):
        cheat_sheet = []
        cheat_sheet.append('reference: {}'.format(self._data['sleuthkit']['ref']))
        for elt in self._data['sleuthkit']['cheat_sheet']:
            line = '{:80}: {}'.format(elt['description'], elt['note'])
            cheat_sheet.append(line)
        self._print_text('Cheat Sheet', cheat_sheet)

    def get_notes_plaso(self):
        cheat_sheet = []
        cheat_sheet.append('reference: {}'.format(self._data['plaso']['ref']))
        for elt in self._data['plaso']['cheat_sheet']:
            line = '{:80}: {}'.format(elt['description'], elt['note'])
            cheat_sheet.append(line)
        self._print_text('Cheat Sheet', cheat_sheet)

    def get_notes_vol2(self):
        cheat_sheet = []
        cheat_sheet.append('reference: {}'.format(self._data['volatility2']['ref']))
        for elt in self._data['volatility2']['cheat_sheet']:
            line = '{:80}: {}'.format(elt['description'], elt['note'])
            cheat_sheet.append(line)
        self._print_text('Cheat Sheet', cheat_sheet)

    def get_notes_tshark(self):
        cheat_sheet = []
        cheat_sheet.append('reference: {}'.format(self._data['tshark']['ref']))
        for elt in self._data['tshark']['cheat_sheet']:
            line = '{:80}: {}'.format(elt['description'], elt['note'])
            cheat_sheet.append(line)
        self._print_text('Cheat Sheet', cheat_sheet)

    def get_notes_yara(self):
        cheat_sheet = []
        cheat_sheet.append('reference: {}'.format(self._data['yara']['ref']))
        for elt in self._data['yara']['cheat_sheet']:
            line = '{:80}: {}'.format(elt['description'], elt['note'])
            cheat_sheet.append(line)
        self._print_text('Cheat Sheet', cheat_sheet)

    def get_notes_nsrl(self):
        cheat_sheet = []
        cheat_sheet.append('reference: {}'.format(self._data['nsrl']['ref']))
        for elt in self._data['nsrl']['cheat_sheet']:
            line = '{:80}: {}'.format(elt['description'], elt['note'])
            cheat_sheet.append(line)
        self._print_text('Cheat Sheet', cheat_sheet)

    def get_notes_misc(self):
        cheat_sheet = []
        for elt in self._data['misc']:
            line = '{:80}: {}'.format(elt['description'], elt['note'])
            cheat_sheet.append(line)
        self._print_text('Cheat Sheet', cheat_sheet)
