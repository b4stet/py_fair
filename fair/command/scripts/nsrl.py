import click
import csv
import os
import io
import zipfile
from fair.command.abstract import AbstractCommand


class NsrlCommand(AbstractCommand):
    def __init__(self):
        pass

    def get_commands(self):
        group = click.Group(
            'nsrl',
            help='scripts to play with nsrl database',
        )

        group.add_command(click.Command(
            name='prepare', help='extract NSRL good knowns for OS and Office Suite files',
            callback=self.prepare,
            params=[
                self._get_option_outdir(),
                self._get_option_nsrl_folder(),
                self._get_option_os(),
            ]
        ))

        group.add_command(click.Command(
            name='thin', help='thin a disk timeline using a NSRL db',
            callback=self.thin,
            params=[
                self._get_option_outdir(),
                self._get_option_bodyfile(),
                self._get_option_nsrl_file(),
            ]
        ))

        return group

    def prepare(self, nsrl, operating_system, outdir):
        # prepare out files
        if not os.path.exists(outdir):
            raise ValueError('Out directory {} does not exist.'.format(outdir))

        out_nsrl_filtered = os.path.join(outdir, 'nsrl_os_office.csv')

        # build product codes of interest in memory
        print('[+] Extracting products for OS and Office Suite related files ... ', end='', flush=True)
        nsrl_code_headers = ['ProductCode', 'ProductName', 'ApplicationType']
        codes = []
        nsrl_product = os.path.join(nsrl, 'NSRLProd.txt')
        with open(nsrl_product, mode='r', encoding='utf8') as f:
            reader = csv.DictReader(f)
            header = reader.fieldnames
            if not all(col in header for col in nsrl_code_headers):
                raise ValueError('Invalid NSRLProd.txt. Expect at least headers [{}]'.format(', '.join(nsrl_code_headers)))

            for row in reader:
                if 'Operating System' in row['ApplicationType'] and operating_system in row['ProductName'].lower():
                    codes.append({
                        'code': row['ProductCode'],
                        'name': row['ProductName'],
                        'type': row['ApplicationType'],
                    })

                if 'Office Suite' in row['ApplicationType']:
                    codes.append({
                        'code': row['ProductCode'],
                        'name': row['ProductName'],
                        'type': row['ApplicationType'],
                    })

        codes_indexed = {}
        for code in codes:
            if code['code'] not in codes_indexed.keys():
                codes_indexed[code['code']] = ''
            info = '{}/{} ; '.format(code['name'], code['type'])
            info = info.replace('"', '')
            info = info.replace(',', ':')
            codes_indexed[code['code']] += info
        print('done')

        # loop on NSRL files list
        print('[+] Filtering NSRL files ... ', end='', flush=True)
        nsrl_headers = ['MD5', 'FileName', 'FileSize', 'ProductCode']
        nsrl_files_archive = os.path.join(nsrl, 'NSRLFile.txt.zip')
        archive = zipfile.ZipFile(nsrl_files_archive, 'r')
        fd_out_nsrl_filtered = open(out_nsrl_filtered, mode='w', encoding='utf8')
        fd_out_nsrl_filtered.write(','.join(nsrl_headers) + ',ProductInfo\n')
        with archive.open('NSRLFile.txt', mode='r') as f:
            f = io.TextIOWrapper(f, encoding='utf8')
            reader = csv.DictReader(f)
            header = reader.fieldnames
            if not all(col in header for col in nsrl_headers):
                raise ValueError('Invalid NSRLFile.txt. Expect at least headers [{}]'.format(', '.join(nsrl_headers)))

            for row in reader:
                if row['ProductCode'] in codes_indexed.keys():
                    line = '{},{}\n'.format(','.join([row[col] for col in nsrl_headers]), codes_indexed[row['ProductCode']])
                    fd_out_nsrl_filtered.write(line)
        fd_out_nsrl_filtered.close()
        print('done')
        print(' | Wrote result in {}'.format(out_nsrl_filtered))

    def thin(self, body, nsrl, outdir):
        # prepare out files
        if not os.path.exists(outdir):
            raise ValueError('Out directory {} does not exist.'.format(outdir))

        base_body, ext_body = os.path.splitext(os.path.basename(body))
        out_body_thinned = os.path.join(outdir, base_body + '_nsrl_thinned' + ext_body)

        # index body in memory
        print('[+] Indexing body file on md5 hashes ... ', end='', flush=True)
        body_indexed = {}
        with open(body, mode='r', encoding='utf8') as f:
            reader = csv.reader(f, delimiter='|')
            for row in reader:
                md5 = row[0]
                rest = '|'.join(row[1:])
                if row[0] not in body_indexed.keys():
                    body_indexed[row[0]] = {
                        'data': [],
                        'nsrl': False,
                    }
                body_indexed[md5]['data'].append(rest)
        print('done')

        # loop on NSRL files list
        print('[+] Scanning NSRL files ... ', end='', flush=True)
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
                if md5 in body_indexed.keys():
                    line = ','.join([row[col] for col in nsrl_headers])
                    if 'ProductInfo' in header:
                        line += ',' + row['ProductInfo']
                    line += '\n'
                    fd_out_nsrl_hits.write(line)
                    body_indexed[md5]['nsrl'] = True
        fd_out_nsrl_hits.close()
        print('done')
        print(' | Wrote hits in {}'.format(out_nsrl_hits))

        # save thinned body
        print('[+] Thinning the body file ... ', end='', flush=True)
        body_thinned = []
        for md5, values in body_indexed.items():
            if values['nsrl'] is False:
                for d in values['data']:
                    line = '|'.join([md5, d])
                    body_thinned.append(line)
        with open(out_body_thinned, mode='w', encoding='utf8') as f:
            f.write('\n'.join(body_thinned))
        print('done')
        print(' | Wrote result in {}'.format(out_body_thinned))
