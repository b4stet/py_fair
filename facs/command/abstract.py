from abc import ABCMeta, abstractmethod
import click
import json
import yaml
import csv
import sys
import os


class AbstractCommand():
    OUTPUT_JSON = 'json'
    OUTPUT_CSV = 'csv'
    OUTPUT_FORMATS = [OUTPUT_JSON, OUTPUT_CSV]
    SUPPORTED_OS = [
        'archlinux',
        'bsd',
        'centos',
        'debian',
        'fedora',
        'mac os',
        'manjaro',
        'slackware',
        'suse',
        'ubuntu',
        'windows',
    ]

    def __init__(self, data):

        file_path = os.path.dirname(os.path.dirname(__file__)) + '/data/' + data
        with open(file_path, mode='r', encoding='utf-8') as f:
            self._data = yaml.safe_load(f)

    @abstractmethod
    def get_commands(self):
        raise NotImplementedError('Method get_commands must be implemented on class {}'.format(type(self)))

    def _print_formatted(self, format: str, data: list):
        if len(data) == 0:
            return

        if format == self.OUTPUT_JSON:
            print(json.dumps(data))

        if format == self.OUTPUT_CSV:
            writer = csv.DictWriter(sys.stdout, quoting=csv.QUOTE_MINIMAL, quotechar='"', fieldnames=data[0].keys())
            writer.writeheader()
            writer.writerows(data)

    def _print_text(self, title: str, data: list):
        print('[+]', title)
        for elt in data:
            print(' |', elt)
        print('')

    def _get_option_output(self):
        return click.Option(
            ['--output', '-o', 'output'],
            help='Output format for the result. Default is json',
            default='json',
            type=click.Choice(self.OUTPUT_FORMATS)
        )

    def _get_option_outdir(self):
        return click.Option(
            ['--outdir', '-d', 'outdir'],
            help='Output folder for the result',
            required=True
        )

    def _get_option_bodyfile(self):
        return click.Option(
            ['--body', '-b', 'body'],
            help='body file as output by tsk fls command, with md5 hashes',
            required=True
        )

    def _get_option_nsrl_files(self):
        return click.Option(
            ['--nsrl', '-n', 'nsrl'],
            help='a file in NSRLFile.txt format',
            required=True,
        )

    def _get_option_nsrl_folder(self):
        return click.Option(
            ['--nsrl', '-n', 'nsrl'],
            help='path of NSRL files (NSRLFile.txt.zip and NSRLProd.txt)',
            required=True,
        )

    def _get_option_os(self):
        return click.Option(
            ['--os', 'operating_system'],
            help='Operating System to filter on. Default is windows',
            default='windows',
            type=click.Choice(self.SUPPORTED_OS)
        )

    def _get_option_evtx(self):
        return click.Option(
            ['--evtx', '-e', 'evtx'],
            help='path of evtx, as output by plaso in json_line format',
            required=True,
        )
