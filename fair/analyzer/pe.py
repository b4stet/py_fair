import pefile

from fair.analyzer.abstract import AbstractAnalyzer


class PEAnalyzer(AbstractAnalyzer):
    def parse_message_table(self, providers, file_candidates):
        message_table = None
        message_table_file = None
        for file_path in file_candidates:
            pe = pefile.PE(file_path)

            for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                if entry.id == 11:
                    message_table = entry
                    message_table_file = file_path

            if message_table is not None:
                break

        # no message table found
        if message_table is None:
            return None

        # language_identifier = message_table.directory.entries[0].directory.entries[0].id
        # codepage = message_table.directory.entries[0].directory.entries[0].data.struct
        offset = message_table.directory.entries[0].directory.entries[0].data.struct.OffsetToData
        size = message_table.directory.entries[0].directory.entries[0].data.struct.Size
        data = pe.get_memory_mapped_image()[offset:offset+size]

        nb_blocks = int.from_bytes(data[0:4], byteorder='little')
        blocks = []
        for i in range(0, nb_blocks):
            blocks.append({
                'first_eid': int.from_bytes(data[4 + 12*i: 4 + 12*i + 4], byteorder='little'),
                'last_eid': int.from_bytes(data[4 + 12*i + 4: 4 + 12*i + 8], byteorder='little'),
                'first_message_offset': int.from_bytes(data[4 + 12*i + 8: 4 + 12*i + 12], byteorder='little'),
            })
        
        messages = []
        for block in blocks:
            offset = block['first_message_offset']
            for eid in range(block['first_eid'], block['last_eid'] + 1):
                message_size = int.from_bytes(data[offset: offset+2], byteorder='little')
                message = data[offset + 4: offset + message_size].decode('utf-16le')

                messages.append({
                    'providers': '|'.join(providers),
                    'eid': eid & 0xFFFF,
                    'file': message_table_file,
                    'message': message,
                })

                offset += message_size

        return messages