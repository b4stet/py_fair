import click
from facs.command.abstract import AbstractCommand


class PreprocessingCommand(AbstractCommand):
    def __init__(self):
        super().__init__('preprocessing.yaml')

    def get_commands(self):
        group = click.Group(
            'preprocessing',
            help='cheat sheets for cumbersome/time intensive preparation tasks (timelines, vss, registries, av/yara scan etc)',
            context_settings=dict(terminal_width=120)
        )

        group.add_command(click.Command(
            name='timeline', help='to create disk timelines (tsk, plaso, etc)',
            callback=self.list_timelines_creation
        ))

        group.add_command(click.Command(
            name='windows', help='to extract windows specific artifacts (shadow copies, usnjrnl, registry, evtx, etc)',
            callback=self.list_artifacts_windows
        ))

        group.add_command(click.Command(
            name='known_bads', help='tools to check against known bads',
            callback=self.list_known_bads_checks
        ))

        return group

    def list_timelines_creation(self):
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

    def list_known_bads_checks(self):
        tools = self._data['known_bads']['tools']
        tools.sort()
        self._print_text('Tools', tools)

        cheat_sheet = []
        for elt in self._data['known_bads']['cheat_sheet']:
            line = '{:80}: {}'.format(elt['description'], elt['command'])
            cheat_sheet.append(line)
        self._print_text('Cheat Sheet', cheat_sheet)
