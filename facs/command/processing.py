import click
from facs.command.abstract import AbstractCommand


class ProcessingCommand(AbstractCommand):
    def __init__(self):
        super().__init__('processing.yaml')

    def get_commands(self):
        group = click.Group(
            'processing',
            help='cheat sheets and automated scripts to forensicate',
            context_settings=dict(terminal_width=120)
        )

        group.add_command(click.Command(
            name='checklist', help='cheat sheets of forensic steps',
            callback=self.get_checklist
        ))

        return group

    def get_checklist(self):
        for step in self._data:
            cheat_sheet = []

            tools = step['tools']
            tools.sort()
            cheat_sheet.append('- Tools: {}'.format(', '.join(tools)))

            cheat_sheet.append('- Cheat sheet:')
            for elt in step['cheat_sheet']:
                line = '{:80}: {}'.format(elt['description'], elt['note'])
                cheat_sheet.append(line)

            self._print_text(step['step'], cheat_sheet)
