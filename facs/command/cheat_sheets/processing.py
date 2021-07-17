import click
import json
import sys
import os
from facs.command.abstract import AbstractCommand
from facs.entity.timeline import TimelineEntity


class ProcessingCommand(AbstractCommand):

    def __init__(self):
        super().__init__('processing.yaml')

    def get_commands(self):
        group = click.Group(
            'processing',
            help='cheat sheets when forensicating',
        )

        group.add_command(click.Command(
            name='misc', help='manual mining ideas',
            callback=self.get_cheat_sheet_misc
        ))

        group.add_command(click.Command(
            name='known_patterns', help='some known artifacts left by attacker toolbox',
            callback=self.get_tool_patterns
        ))

        group.add_command(click.Command(
            name='default_values', help='some default configuration values observed',
            callback=self.list_defaults
        ))

        group.add_command(click.Command(
            name='win_profiling', help='info to collect about a host and users',
            callback=self.get_win_profiling
        ))

        return group

    def get_cheat_sheet_misc(self):
        manual = []
        for elt in self._data['manual_mining']:
            line = '{:80}: {}'.format(elt['description'], elt['note'])
            manual.append(line)
        self._print_text('Manual mining', manual)

    def get_tool_patterns(self):
        patterns = []
        for elt in self._data['patterns']:
            for pattern in elt['detection']:
                line = 'tool: {:40} pattern: {}'.format(elt['tool'], pattern)
                patterns.append(line)
        self._print_text('Known/Possible patterns of adversaries tools', patterns)

    def list_defaults(self):
        defaults = []
        for elt in self._data['defaults']:
            line = '{:60}: {}'.format(elt['description'], elt['value'])
            defaults.append(line)
        self._print_text('Some default values of software', defaults)

    def get_win_profiling(self):
        self._print_text('Collection to get from the investigated host (evtx, registry)', self._data['win_profiling'])
