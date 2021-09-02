import click
import os
from datetime import datetime

from facs.command.abstract import AbstractCommand


class ReportCommand(AbstractCommand):
    def __init__(self, ods_loader):
        self.__ods_loader = ods_loader

    def get_commands(self):
        group = click.Group(
            'report',
            help='scripts to create, update, visualize results from csv files (timeline, IoCs, other info)',
        )

        group.add_command(click.Command(
            name='create_workbook', help='initiate a workbook (ods format).',
            callback=self.create,
            params=[
                self._get_option_outdir(),
                self._get_option_csv(),
                self._get_option_sheetname(),
            ]
        ))

        group.add_command(click.Command(
            name='update_workbook', help='update a workbook (update/add a sheet)',
            callback=self.update,
            params=[
                self._get_option_workbook(),
                self._get_option_csv(),
                self._get_option_sheetname(),
            ]
        ))

        return group

    def create(self, csv_file, sheetname, outdir):
        if not os.path.exists(outdir):
            raise ValueError('Out directory {} does not exist.'.format(outdir))

        out_workbook = os.path.join(outdir, 'report_' + datetime.now().strftime('%Y%m%d%H%M%S') + '.ods')
        if os.path.exists(out_workbook):
            raise ValueError('Output file {} already exist. Aborting.'.format(out_workbook))

        book = self.__ods_loader.get_book()
        book = self.__ods_loader.add_sheet(book, sheetname, csv_file)
        book.save(out_workbook)
        print('[+] Saved the report in {}'.format(out_workbook))

    def update(self, csv_file, workbook, sheetname):
        book = self.__ods_loader.get_book(workbook)

        sheet = self.__ods_loader.get_sheet_by_name(book, sheetname)
        if sheet is None:
            print('[+] Adding new sheet {}'.format(sheetname))
            book = self.__ods_loader.add_sheet(book, sheetname, csv_file)
        else:
            print('[+] Updating sheet {}'.format(sheetname))
            book = self.__ods_loader.update_sheet(book, sheet, csv_file)

        book.save(workbook)
        print('[+] Saved the report in {}'.format(workbook))
