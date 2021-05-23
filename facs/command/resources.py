import click
from facs.command.abstract import AbstractCommand


class ResourcesCommand(AbstractCommand):
    def __init__(self):
        super().__init__('resources.yaml')

    def get_commands(self):
        group = click.Group(
            'resources',
            help='kind of bibliography',
            context_settings=dict(terminal_width=120)
        )

        group.add_command(click.Command(
            name='kbs', help='knowledge bases for forensic (IoCs, event IDs, artifacts, ...)',
            callback=self.get_kbs
        ))

        group.add_command(click.Command(
            name='cves', help='list notable cves',
            callback=self.get_cves
        ))

        group.add_command(click.Command(
            name='misc', help='other resources (tools blogs, challenges, ...)',
            callback=self.get_others
        ))

        return group

    def get_kbs(self):
        keys = [
            'executables',
            'malware',
            'iocs',
            'evtx',
            'artifacts',
            'system',
        ]
        for key in keys:
            self._print_text(key, self._data[key])

    def get_cves(self):
        items = ['{:40} desc: {}'.format(item['cve'], item['description']) for item in self._data['cves']]
        self._print_text('Notable CVEs', items)

    def get_others(self):
        keys = [
            'executables',
            'malware',
            'iocs',
            'evtx',
            'artifacts',
            'system',
            'cves',
        ]
        items = {k:v for k,v in self._data.items() if k not in keys}
        for category, item in items.items():
            self._print_text(category, item)
