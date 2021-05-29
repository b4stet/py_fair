import click
from facs.command.abstract import AbstractCommand


class ExtractionCommand(AbstractCommand):
    def __init__(self):
        super().__init__('extraction.yaml')

    def get_commands(self):
        group = click.Group(
            'extraction',
            help='cheat sheets related to artifacts extraction for further analysis (timelines, vss, carving, ...)',
            context_settings=dict(terminal_width=120)
        )

        group.add_command(click.Command(
            name='recover', help='cheat sheet to carve files from unallocated data blocks',
            callback=self.recover
        ))

        group.add_command(click.Command(
            name='timeline', help='cheat sheet to create disk timelines (tsk, plaso, ...)',
            callback=self.create_timelines
        ))

        group.add_command(click.Command(
            name='win_artifacts', help='cheat sheet of windows specific artifacts (evtx, registry hives, shell items, ...)',
            callback=self.list_artifacts_windows
        ))

        return group

    def recover(self):
        tools = self._data['recovery']['tools']
        tools.sort()
        self._print_text('Tools', tools)

        behaviors = []
        for elt in self._data['recovery']['behaviors']:
            line = '{:10}: {}'.format(elt['fs'], elt['behavior'])
            behaviors.append(line)
        self._print_text('File System behavior when deleting', behaviors)

        cheat_sheet = []
        for elt in self._data['recovery']['cheat_sheet']:
            line = '{:80}: {}'.format(elt['description'], elt['command'])
            cheat_sheet.append(line)
        self._print_text('Cheat Sheet', cheat_sheet)

    def create_timelines(self):
        tools = self._data['timelines']['tools']
        tools.sort()
        self._print_text('Tools', tools)

        cheat_sheet = []
        for elt in self._data['timelines']['cheat_sheet']:
            line = '{:80}: {}'.format(elt['description'], elt['command'])
            cheat_sheet.append(line)
        self._print_text('Cheat Sheet', cheat_sheet)

    def list_artifacts_windows(self):
        tools = self._data['windows']['tools']
        tools.sort()
        self._print_text('Tools', tools)

        cheat_sheet = []
        for elt in self._data['windows']['cheat_sheet']:
            line = '{:80}: {}'.format(elt['description'], elt['command'])
            cheat_sheet.append(line)
        self._print_text('Cheat Sheet', cheat_sheet)

        paths = []
        for elt in self._data['windows']['paths']:
            line = '{:80}: {}'.format(elt['description'], elt['path'])
            paths.append(line)
        self._print_text('On windows, other logs path ', paths)
