import click
import csv
import os
import sys
from facs.command.abstract import AbstractCommand


class PreprocessingCommand(AbstractCommand):
    def __init__(self):
        super().__init__('preprocessing.yaml')

    def get_commands(self):
        group = click.Group(
            'preprocessing',
            help='cheat sheets related to artifacts extraction for further analysis (timelines, vss, carving, ...)',
            context_settings=dict(terminal_width=120)
        )

        group.add_command(click.Command(
            name='timeline', help='cheat sheet to create disk timelines (tsk, plaso, ...)',
            callback=self.list_timelines_creation
        ))

        group.add_command(click.Command(
            name='thin_timeline', help='thin the disk timeline using a NSRL file',
            callback=self.thin_timeline,
            params=[
                self._get_option_outdir(),
                self._get_option_bodyfile(),
                self._get_option_nsrl(),
            ]
        ))

        group.add_command(click.Command(
            name='windows', help='cheat sheet related to windows specific artifacts (shadow copies, usnjrnl, ...)',
            callback=self.list_artifacts_windows
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

    def thin_timeline(self, body, nsrl, outdir):
        # prepare out files
        if not os.path.exists(outdir):
            raise ValueError('Out directory {} does not exist.'.format(outdir))

        base_body, ext_body = os.path.splitext(os.path.basename(body))
        out_body_thinned = os.path.join(outdir, base_body + '_nsrl_thinned' + ext_body)

        # index body in memory
        body_src = {}
        with open(body, mode='r', encoding='utf8') as f:
            reader = csv.reader(f, delimiter='|')
            for row in reader:
                md5 = row[0]
                rest = '|'.join(row[1:])
                if row[0] not in body_src.keys():
                    body_src[row[0]] = {
                        'data': [],
                        'nsrl': False,
                    }
                body_src[md5]['data'].append(rest)

        # loop on NSRL files list
        nsrl_headers = ['MD5', 'FileName', 'FileSize', 'ProductCode']
        out_nsrl_hits = os.path.join(outdir, 'nsrl_hits.csv')
        fd_out_nsrl_hits = open(out_nsrl_hits, mode='w', encoding='utf8')
        with open(nsrl, mode='r', encoding='utf8') as f:
            reader = csv.DictReader(f)
            header = reader.fieldnames
            if not all(col in header for col in nsrl_headers):
                raise ValueError('Invalid NSRLFiles.txt. Expect at least headers [{}]'.format(', '.join(nsrl_headers)))

            for row in reader:
                md5 = row['MD5'].lower().strip('"')
                if md5 in body_src.keys():
                    fd_out_nsrl_hits.write(','.join([row[col] for col in nsrl_headers]) + '\n')
                    body_src[md5]['nsrl'] = True
        fd_out_nsrl_hits.close()

        # save thinned body
        body_thinned = []
        for md5, values in body_src.items():
            if values['nsrl'] is False:
                for d in values['data']:
                    line = '|'.join([md5, d])
                    body_thinned.append(line)
        with open(out_body_thinned, mode='w', encoding='utf8') as f:
            f.write('\n'.join(body_thinned))

    def list_artifacts_windows(self):
        tools = self._data['windows']['tools']
        tools.sort()
        self._print_text('Tools', tools)

        cheat_sheet = []
        for elt in self._data['windows']['cheat_sheet']:
            line = '{:80}: {}'.format(elt['description'], elt['command'])
            cheat_sheet.append(line)
        self._print_text('Cheat Sheet', cheat_sheet)
