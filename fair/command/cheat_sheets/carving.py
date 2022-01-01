import click
from fair.command.abstract import AbstractCommand


class CarvingCommand(AbstractCommand):
    def __init__(self):
        super().__init__('carving.yaml')

    def get_commands(self):
        return click.Command(
            name='carving', help='cheat sheet to carve files from (un)allocated data blocks',
            callback=self.carve
        )

    def carve(self):
        tools = self._data['tools']
        tools.sort()
        self._print_text('Tools', tools)

        cheat_sheet = []
        for elt in self._data['cheat_sheet']:
            line = '{:80}: {}'.format(elt['description'], elt['command'])
            cheat_sheet.append(line)
        self._print_text('Cheat Sheet', cheat_sheet)
