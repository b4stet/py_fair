from abc import abstractmethod
import click
import json
import yaml
import csv
import sys
import os
import subprocess


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

    SUPPORTED_COLUMN_TYPES = ['float', 'string']

    def __init__(self, data=None):
        file_path = os.path.dirname(os.path.dirname(__file__)) + '/data/' + data
        with open(file_path, mode='r', encoding='utf-8') as f:
            self._data = yaml.safe_load(f)

    @abstractmethod
    def get_commands(self):
        raise NotImplementedError('Method get_commands must be implemented on class {}'.format(type(self)))

    def _write_formatted(self, outfile, format: str, data: list):
        if len(data) == 0:
            return

        if format == self.OUTPUT_JSON:
            with open(outfile, mode='w', encoding='utf8') as fout:
                json.dump(data, fout)

        if format == self.OUTPUT_CSV:
            with open(outfile, mode='w', encoding='utf8', newline='') as fout:
                writer = csv.DictWriter(fout, quoting=csv.QUOTE_MINIMAL, quotechar='"', fieldnames=data[0].keys(), lineterminator='\n')
                writer.writeheader()
                writer.writerows(data)

    def _print_formatted(self, format: str, data: list):
        if len(data) == 0:
            return

        if format == self.OUTPUT_JSON:
            print(json.dumps(data))

        if format == self.OUTPUT_CSV:
            writer = csv.DictWriter(sys.stdout, quoting=csv.QUOTE_MINIMAL, quotechar='"', fieldnames=data[0].keys(), lineterminator='\n')
            writer.writeheader()
            writer.writerows(data)

    def _print_text(self, title: str, data: list = [], newline=True):
        print('[+]', title)
        for elt in data:
            print(' |', elt)
        if newline is True:
            print('')

    def _sort_big_file(self, infile, outfile, column=1):
        outdir = os.path.dirname(outfile)
        # ugly but more CPU/RAM efficient than rewriting a merge external sort, even with heapq :)
        with open(infile, mode='r', encoding='utf8') as fin, open(outfile, mode='w', encoding='utf8') as fout:
            sorting = subprocess.Popen([
                'sort',
                '--parallel=6', '--temporary-directory={}'.format(outdir),
                '-n', '-t,', '-k{}'.format(column)
                ],
                stdin=fin, stdout=subprocess.PIPE
            )
            writing = subprocess.run(['cut', '-d,', '-f2-'], stdin=sorting.stdout, stdout=fout)
            sorting.stdout.close()
        if writing.returncode == 0:
            os.remove(infile)

    def _get_option_output(self):
        return click.Option(
            ['--output', '-o', 'output'],
            help='output format for the result. Default is json',
            default='json',
            type=click.Choice(self.OUTPUT_FORMATS)
        )

    def _get_option_outdir(self):
        return click.Option(
            ['--outdir', '-d', 'outdir'],
            help='output folder for the result',
            required=True
        )

    def _get_option_csv(self):
        return click.Option(
            ['--csv', '-c', 'csv_file'],
            help='path to a csv file, comma delimited and with header',
            required=True
        )

    def _get_option_workbook(self):
        return click.Option(
            ['--workbook', '-w', 'workbook'],
            help='path to a workbook, ODF format',
            required=True
        )

    def _get_option_sheetname(self):
        return click.Option(
            ['--sheet', '-s', 'sheetname'],
            help='name of the sheet to use in the workbook',
            required=True
        )

    def _get_option_column_types(self):
        return click.Option(
            ['--columns', 'column_types'],
            help='Type of columns to be enforced on cells (default is str). Can be repeated.',
            required=False,
            nargs=2, type=click.Tuple([str, click.Choice(self.SUPPORTED_COLUMN_TYPES)]), multiple=True
        )

    def _get_option_bodyfile(self):
        return click.Option(
            ['--body', '-b', 'body'],
            help='body file as output by tsk fls command, with md5 hashes',
            required=True
        )

    def _get_option_nsrl_file(self):
        return click.Option(
            ['--nsrl', '-n', 'nsrl'],
            help='a file in NSRLFile.txt format',
            required=True,
        )

    def _get_option_nsrl_folder(self):
        return click.Option(
            ['--nsrl', '-n', 'nsrl'],
            help='path to NSRL files (NSRLFile.txt.zip and NSRLProd.txt)',
            required=True,
        )

    def _get_option_os(self):
        return click.Option(
            ['--os', 'operating_system'],
            help='operating system to filter on. Default is Windows',
            default='windows',
            type=click.Choice(self.SUPPORTED_OS)
        )

    def _get_option_mount_point(self):
        return click.Option(
            ['--mount_point', 'mount_point'],
            help='path to disk mount point',
            required=True,
        )

    def _get_option_evtx_path(self):
        return click.Option(
            ['--evtx', 'evtx_path'],
            help='path to evtx folder',
            required=True,
        )

    def _get_option_prefetch_path(self):
        return click.Option(
            ['--prefetch', 'prefetch_path'],
            help='path to prefetch folder',
            required=True,
        )

    def _get_option_amcache_path(self):
        return click.Option(
            ['--amcache', 'amcache_path'],
            help='path to amcache hive',
            required=True,
        )

    def _get_option_timeline_evtx(self):
        return click.Option(
            ['--timeline_evtx', 'timeline_evtx'],
            help='path to evtx, as output by "py_fair scripts windows extract_evtx"',
            required=True,
        )

    def _get_option_timeline_plaso(self):
        return click.Option(
            ['--timeline_plaso', 'timeline_plaso'],
            help='path to timeline produced by log2timeline+psort in json_line format',
            required=False,
        )

    def _get_option_timeline_fls(self):
        return click.Option(
            ['--timeline_fls', 'timeline_fls'],
            help='path to timeline produced by TSK fls+mactime in csv format with header and ISO8601 dates (-y -d options)',
            required=True,
        )

    def _get_option_hive_sam(self):
        return click.Option(
            ['--hsam', 'hive_sam'],
            help='path to a clean SAM hive',
            required=True,
        )

    def _get_option_hive_software(self):
        return click.Option(
            ['--hsoftware', 'hive_software'],
            help='path to a clean SOFTWARE hive',
            required=True,
        )

    def _get_option_hive_system(self):
        return click.Option(
            ['--hsystem', 'hive_system'],
            help='path to a clean SYSTEM hive',
            required=True,
        )

    def _get_option_hive_ntusers(self):
        return click.Option(
            ['--huser', 'hive_users'],
            help='(ntuser.dat username) path to a clean NTUSER.DAT hive with username it belongs to. Can be repeated.',
            required=True,
            nargs=2, type=click.Tuple([str, str]), multiple=True
        )

    def _get_option_tags(self):
        return click.Option(
            ['-t', '--tags', 'tags_file'],
            help='path to a yaml file containing tags'
        )
