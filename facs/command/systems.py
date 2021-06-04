import click
from facs.command.abstract import AbstractCommand


class SystemsCommand(AbstractCommand):
    def __init__(self):
        super().__init__('systems.yaml')

    def get_commands(self):
        group = click.Group(
            'systems',
            help='some notes on operating systems',
            context_settings=dict(terminal_width=120)
        )

        group.add_command(click.Command(
            name='unix', help='notes about Unix systems',
            callback=self.get_notes_unix
        ))

        group.add_command(click.Command(
            name='windows', help='notes about Windows system',
            callback=self.get_notes_windows
        ))

        return group

    def get_notes_unix(self):
        self._print_text('References', self._data['unix']['references'])
        self._print_text('General notes', self._data['unix']['notes'])

        fs_ext = []
        for elt in self._data['unix']['fs_ext']:
            line = '{:40}: {}'.format(elt['name'], elt['description'])
            fs_ext.append(line)
        self._print_text('Notes about ext file systems', fs_ext)

    def get_notes_windows(self):
        self._print_text('References', self._data['windows']['references'])

        fs_ntfs = []
        for elt in self._data['windows']['ntfs']:
            line = '{:40}: {}'.format(elt['name'], elt['description'])
            fs_ntfs.append(line)
        self._print_text('Cheat Sheet', fs_ntfs)

        fs_fat = []
        for elt in self._data['windows']['fat']:
            line = '{:40}: {}'.format(elt['name'], elt['description'])
            fs_fat.append(line)
        self._print_text('Cheat Sheet', fs_fat)
