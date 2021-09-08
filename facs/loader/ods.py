import csv
from odf.opendocument import OpenDocumentSpreadsheet, load
from odf import style, text, table


class OdsBo():
    def __init__(self):
        pass

    def get_book(self, book_path=None):
        book = None
        if book_path is None:
            book = OpenDocumentSpreadsheet()
            book = self.__define_styles(book)
        else:
            book = load(book_path)

        return book

    def get_sheet_by_name(self, book, sheetname):
        sheets = book.spreadsheet.getElementsByType(table.Table)
        return next((sheet for sheet in sheets if sheet.getAttribute('name') == sheetname), None)

    def add_sheet(self, book, sheetname, csv_file, column_types=None):
        sheet = table.Table(name=sheetname)
        with open(csv_file, mode='r', encoding='utf-8') as f:
            reader = csv.DictReader(f, delimiter=',')

            max_row = 0
            max_col = len(reader.fieldnames)

            # header
            row = table.TableRow()
            for header in reader.fieldnames:
                cell = table.TableCell(valuetype='string', stylename=book.getStyleByName('Header'))
                cell.addElement(text.P(text=header))
                row.addElement(cell)
            sheet.addElement(row)
            max_row += 1

            # data
            for line in reader:
                row = table.TableRow()
                for col in reader.fieldnames:
                    value_type = column_types.get(col, 'string')
                    if value_type == 'float':
                        cell = table.TableCell(valuetype=value_type, value=int(line[col]))
                    else:
                        cell = table.TableCell(valuetype='string')
                        cell.addElement(text.P(text=line[col]))
                    row.addElement(cell)
                sheet.addElement(row)
                max_row += 1
        book.spreadsheet.addElement(sheet)

        # define table range
        top_left = '$A$1'
        bottom_right = '${}${}'.format(self.__sheet_index_to_letters(max_col), max_row)
        db_name = 'tbl_{}'.format(sheetname)
        db_range = '{}.{}:{}.{}'.format(sheetname, top_left, sheetname, bottom_right)
        db = table.DatabaseRange(name=db_name, targetrangeaddress=db_range, onupdatekeepstyles=True)

        dbs = table.DatabaseRanges()
        dbs.addElement(db)
        book.spreadsheet.addElement(dbs)
        return book

    def update_sheet(self, book, sheet, csv_file, column_types=None):
        # retrieve table limits
        sheetname = sheet.getAttribute('name')

        rows = sheet.getElementsByType(table.TableRow)
        max_row = len(rows)

        # get header, might be different from csv header
        sheet_header = [cell.getElementsByType(text.P)[0].firstChild.data for cell in rows[0].childNodes]
        max_col = len(sheet_header)

        # update sheet content
        with open(csv_file, mode='r', encoding='utf-8') as f:
            reader = csv.DictReader(f, delimiter=',')

            # check all column in csv exist in sheet_header
            if not all(col in sheet_header for col in reader.fieldnames):
                raise ValueError('Invalid csv header. Expected a subset of [{}]. Got [{}]'.format(','.join(sheet_header), ','.join(reader.fieldnames)))

            # append data
            for line in reader:
                row = table.TableRow()
                line_matched = [line[col] if col in reader.fieldnames else '' for col in sheet_header]
                value_types = [column_types.get(col, 'string') for col in sheet_header]
                for value, value_type in zip(line_matched, value_types):
                    if value_type == 'float':
                        cell = table.TableCell(valuetype=value_type, value=int(value))
                    else:
                        cell = table.TableCell(valuetype='string')
                        cell.addElement(text.P(text=value))
                    row.addElement(cell)
                sheet.addElement(row)
                max_row += 1

        # update table range
        db_name = 'tbl_{}'.format(sheetname)
        dbs = book.spreadsheet.getElementsByType(table.DatabaseRanges)[0]
        db = next((db for db in dbs.childNodes if db.getAttribute('name') == db_name), None)
        if db is None:
            raise RuntimeError('Could not retrieve {} in sheet {}'.format(db_name, sheetname))

        top_left = '$A$1'
        bottom_right = '${}${}'.format(self.__sheet_index_to_letters(max_col), max_row)
        db_range = '{}.{}:{}.{}'.format(sheetname, top_left, sheetname, bottom_right)
        db.setAttribute('targetrangeaddress', db_range)

        return book

    def __define_styles(self, book: OpenDocumentSpreadsheet):
        base = style.DefaultStyle(family='table-cell')
        base.addElement(style.TextProperties(fontfamily='Arial', fontstyle='normal', fontsize='10pt', color='#000000'))
        book.styles.addElement(base)

        header = style.Style(name='Header', family='table-cell')
        header.addElement(style.TextProperties(fontstyle='normal', fontweight='bold', color='#ffffff'))
        header.addElement(style.ParagraphProperties(textalign='center'))
        header.addElement(style.TableCellProperties(backgroundcolor='#000000'))
        book.styles.addElement(header)

        bad = style.Style(name='Bad', family='table-cell')
        bad.addElement(style.TextProperties(fontstyle='normal', fontweight='normal', color='#cc0000'))
        bad.addElement(style.ParagraphProperties(textalign='left'))
        bad.addElement(style.TableCellProperties(backgroundcolor='#fcd3c1'))
        book.styles.addElement(bad)

        warning = style.Style(name='Warning', family='table-cell')
        warning.addElement(style.TextProperties(fontstyle='normal', fontweight='normal', color='#985006'))
        warning.addElement(style.ParagraphProperties(textalign='left'))
        warning.addElement(style.TableCellProperties(backgroundcolor='#ffffcc'))
        book.styles.addElement(warning)

        good = style.Style(name='Good', family='table-cell')
        good.addElement(style.TextProperties(fontstyle='normal', fontweight='normal', color='#006600'))
        good.addElement(style.ParagraphProperties(textalign='left'))
        good.addElement(style.TableCellProperties(backgroundcolor='#e0efd4'))
        book.styles.addElement(good)

        info = style.Style(name='Info', family='table-cell')
        info.addElement(style.TextProperties(fontstyle='normal', fontweight='normal', color='#21409a'))
        info.addElement(style.ParagraphProperties(textalign='left'))
        info.addElement(style.TableCellProperties(backgroundcolor='#adc5e7'))
        book.styles.addElement(info)

        return book

    def __sheet_index_to_letters(self, index):
        alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'

        # convert from base 10 to base 26
        letters = []
        r = 0
        q = index
        while q > 0:
            r = q % 26
            q = q // 26
            letters.append(alphabet[r-1])

        return ''.join(reversed(letters))
