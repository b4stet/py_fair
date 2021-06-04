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
            name='enrich_timeline', help='enrich the disk timeline with md5 hashes and a tag for files in NSRL Operating System db',
            callback=self.enrich_timeline,
            params=[
                self._get_option_outdir(),
                self._get_option_bodyfile(),
                self._get_option_hashes(),
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

    def enrich_timeline(self, body, hashes, nsrl, outdir):
        # prepare out files
        if not os.path.exists(outdir):
            raise ValueError('Out directory {} does not exist.'.format(outdir))

        base_hashes, ext_hashes = os.path.splitext(os.path.basename(hashes))
        out_hashes_enriched = os.path.join(outdir, base_hashes + '_nsrl_os_enriched' + ext_hashes)

        base_body, ext_body = os.path.splitext(os.path.basename(body))
        out_body_enriched = os.path.join(outdir, base_body + '_nsrl_os_enriched' + ext_body)

        # load observed hashes in memory
        with open(hashes, mode='r', encoding='utf8') as f:
            reader = csv.DictReader(f, fieldnames=['md5', 'filepath'])
            hashes_observed = {}
            for row in reader:
                if row['md5'] not in hashes_observed.keys():
                    hashes_observed[row['md5']] = {
                        'filepaths': [],
                        'nsrl_os': False,
                    }
                hashes_observed[row['md5']]['filepaths'].append(row['filepath'].lstrip('.'))

        # loop on NSRL files list
        nsrl_headers = ['MD5', 'FileName', 'FileSize', 'ProductCode']
        out_nsrl_hits = os.path.join(outdir, 'nsrl_os_hits.csv')
        fd_out_nsrl_hits = open(out_nsrl_hits, mode='w', encoding='utf8')
        with open(nsrl, mode='r', encoding='utf8') as f:
            reader = csv.DictReader(f)
            header = reader.fieldnames
            if not all(col in header for col in nsrl_headers):
                raise ValueError('Invalid NSRLFiles.txt. Expect at least headers [{}]'.format(', '.join(nsrl_headers)))

            for row in reader:
                md5 = row['MD5'].lower().strip('"')
                if md5 in hashes_observed.keys():
                    fd_out_nsrl_hits.write(','.join([row[col] for col in nsrl_headers]) + '\n')
                    hashes_observed[md5]['nsrl_os'] = True
        fd_out_nsrl_hits.close()

        # save enriched hashes
        hashes_enriched = []
        for md5, values in hashes_observed.items():
            for filepath in values['filepaths']:
                hashes_enriched.append({
                    'md5': md5,
                    'filepath': filepath,
                    'nsrl_os': values['nsrl_os'],
                })
        with open(out_hashes_enriched, mode='w', encoding='utf8') as f:
            writer = csv.DictWriter(f, delimiter=',', fieldnames=['md5', 'nsrl_os', 'filepath'])
            writer.writeheader()
            writer.writerows(hashes_enriched)
        del(hashes_observed)

        # restructure enriched hashes for efficient search
        hashes_enriched_dict = {}
        for h in hashes_enriched:
            hashes_enriched_dict[h['filepath']] = {
                'md5': h['md5'],
                'nsrl_os': h['nsrl_os'],
            }
        del(hashes_enriched)

        # enrich the timeline based on known hashes/filenames
        fd_out_body_enriched = open(out_body_enriched, mode='w', encoding='utf8')
        fd_in_body = open(body, mode='r', encoding='utf8')
        with open(body, mode='r', encoding='utf8') as f:
            reader = csv.reader(f, delimiter='|')
            for row in reader:
                filename_body = row[1]
                # some cleaning for file name attribute and alternate data stream
                if filename_body.endswith(' ($FILE_NAME)'):
                    filename_body = filename_body[:-len(' ($FILE_NAME)')]
                if ':' in filename_body:
                    filename_body = filename_body.split(':')[0]

                nsrl_tag = 'nsrl_unknown'
                found = hashes_enriched_dict.get(filename_body, None)
                if found is not None:
                    row[0] = found['md5']
                    nsrl_tag = found['nsrl_os']

                enriched_row = '{}|{}\n'.format(nsrl_tag, '|'.join(row))
                fd_out_body_enriched.write(enriched_row)
        fd_out_body_enriched.close()

    def list_artifacts_windows(self):
        tools = self._data['windows']['tools']
        tools.sort()
        self._print_text('Tools', tools)

        cheat_sheet = []
        for elt in self._data['windows']['cheat_sheet']:
            line = '{:80}: {}'.format(elt['description'], elt['command'])
            cheat_sheet.append(line)
        self._print_text('Cheat Sheet', cheat_sheet)
