import click
from facs.command.abstract import AbstractCommand


class LibraryCommand(AbstractCommand):
    __KBS = [
        'lolbin',
        'malware',
        'files',
        'ioc_ttp',
        'evtx',
        'artifacts',
        'system',
        'cves',
    ]

    def __init__(self):
        super().__init__('library.yaml')

    def get_commands(self):
        group = click.Group(
            'library',
            help='knowledge base, references, ...',
        )

        group.add_command(click.Command(
            name='dfir', help='knowledge bases for forensic (IoCs, TTPs, CVEs, event IDs, artifacts, ...)',
            callback=self.get_dfir
        ))

        group.add_command(click.Command(
            name='misc', help='other resources (tools, blogs, challenges, ...)',
            callback=self.get_misc
        ))

        return group

    def get_dfir(self):
        for key in self.__KBS:
            if key == 'cves':
                items = ['{:40} desc: {}'.format(item['cve'], item['description']) for item in self._data['cves']]
                self._print_text('Notable CVEs', items)
            else:
                self._print_text(key, self._data[key])

    def get_misc(self):
        items = {k: v for k, v in self._data.items() if k not in self.__KBS}
        for category, item in items.items():
            self._print_text(category, item)
