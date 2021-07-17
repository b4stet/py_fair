import click
from facs.command.abstract import AbstractCommand


class SystemsCommand(AbstractCommand):
    def __init__(self):
        super().__init__('systems.yaml')

    def get_commands(self):
        group = click.Group(
            'systems',
            help='some notes on operating systems behaviors/structure',
        )

        group.add_command(click.Command(
            name='unix', help='about Unix systems',
            callback=self.get_notes_unix
        ))

        group.add_command(click.Command(
            name='windows', help='about Windows system',
            callback=self.get_notes_windows
        ))

        group.add_command(click.Command(
            name='macb', help='about macb timestamp rules (well, the theory :))',
            callback=self.get_notes_macb
        ))

        group.add_command(click.Command(
            name='deletion', help='about deletion effects on inodes (well, the theory :))',
            callback=self.get_notes_deletion
        ))

        group.add_command(click.Command(
            name='common', help='about common behaviors across systems',
            callback=self.get_notes_common
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
        for elt in self._data['windows']['fs_ntfs']:
            line = '{:40}: {}'.format(elt['name'], elt['description'])
            fs_ntfs.append(line)
        self._print_text('Cheat Sheet NTFS', fs_ntfs)

        fs_fat = []
        for elt in self._data['windows']['fs_fat']:
            line = '{:40}: {}'.format(elt['name'], elt['description'])
            fs_fat.append(line)
        self._print_text('Cheat Sheet FAT', fs_fat)

    def get_notes_macb(self):
        self._print_text('References', self._data['macb_theory']['references'])

        win10 = self._data['macb_theory']['ntfs_win10']
        rules = []
        for rule in win10:
            line = '$FN: {:20} $SI: {:40} desc: {}'.format(rule['file_name'], rule['std_info'], rule['description'])
            rules.append(line)
        self._print_text('Theoretical rules on NTFS - tested on Windows 10 build 1903', rules)

        win78 = self._data['macb_theory']['ntfs_win7_8']
        rules = []
        for rule in win78:
            line = '$FN: {:20} $SI: {:40} desc: {}'.format(rule['file_name'], rule['std_info'], rule['description'])
            rules.append(line)
        self._print_text('Theoretical rules on NTFS - Windows 7/8', rules)

    def get_notes_deletion(self):
        behaviors = []
        for elt in self._data['deletion_behaviors']:
            line = '{:10}: {}'.format(elt['fs'], elt['behavior'])
            behaviors.append(line)
        self._print_text('File System behavior when deleting', behaviors)

    def get_notes_common(self):
        general = []
        for elt in self._data['general']:
            line = '{:40}: {}'.format(elt['name'], elt['description'])
            general.append(line)
        self._print_text('Common behaviors', general)
