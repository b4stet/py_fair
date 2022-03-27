import csv
import json
from dateutil import parser
from datetime import datetime, timezone

from fair.analyzer.abstract import AbstractAnalyzer


class TimelineAnalyzer(AbstractAnalyzer):
    # def do_analyze_prefetchs(self, prefetch, outdir, output):
    #     if not os.path.exists(outdir):
    #         raise ValueError('Out directory {} does not exist.'.format(outdir))

    #     fd_prefetchs = open(prefetch, mode='r', encoding='utf8')
    #     prefetchs = self.__artifact_analyzer.analyze_prefetchs(fd_prefetchs)
    #     fd_prefetchs.close()

    #     outfile = 'prefetchs.{}'.format(output)
    #     outfile = os.path.join(outdir, outfile)
    #     self._write_formatted(outfile, output, prefetchs)
    #     self._print_text(title='Wrote results in {}'.format(outfile))

    def prepare_fls(self, timeline_fls, fd_out, tags=False):
        with open(timeline_fls, mode='r', encoding='utf8') as f:
            reader = csv.DictReader(f)

            header = reader.fieldnames
            expected_header = ['Date', 'Size', 'Type', 'Mode', 'UID', 'GID', 'Meta', 'File Name']
            if not all(col in header for col in expected_header):
                raise ValueError('Invalid FLS timeline. Expect at least headers [{}]'.format(', '.join(expected_header)))

            for row in reader:
                event = {
                    'source': 'mft',
                    'datetime': parser.isoparse(row['Date']).isoformat(timespec='seconds'),
                    'timestamp': parser.isoparse(row['Date']).timestamp(),
                    'timestamp_desc': row['Type'],
                    'filename': row['File Name'],
                    'raw': row['File Name'],
                    'inode': row['Meta'],
                    'size_bytes': row['Size'],
                    'misc': 'mode: {}; uid: {}; gid: {}'.format(row['Mode'], row['UID'], row['GID']),
                }

                if tags is True:
                    event['fair_tags'] = ['mft', 'mft_{}'.format(row['Type'])]
                fd_out.write('{},{}\n'.format(event['timestamp'], json.dumps(event)))

    def prepare_evtx(self, timeline_evtx, fd_out, tags_kb):
        with open(timeline_evtx, mode='r', encoding='utf8') as f:
            for line in f:
                event = json.loads(line)
                event['datetime'] = parser.isoparse(event['datetime']).isoformat(timespec='seconds')
                event['source'] = 'evtx_{}'.format(event['channel'])

                if tags_kb is not None:
                    event_tags = self.__get_evtx_tags(event, tags_kb['kb'])
                    if len(event_tags) > 0:
                        event['fair_tags'] = event_tags

                fd_out.write('{},{}\n'.format(event['timestamp'], json.dumps(event)))

    def __get_evtx_tags(self, event, tags):
        possible_tags = [
            tag
            for tag in tags
            if tag['channel'] == event['channel'] and event['eid'] in tag['eids'] and (tag.get('provider') is None or tag['provider'] == event['provider'])
        ]

        event_tags = []
        for tag in possible_tags:
            # process conditions
            conditions = tag.get('conditions', None)
            if conditions is None:
                event_tags.extend(tag['tags'])
            else:
                fulfilled = self.__apply_tag_conditions(event, conditions)
                if fulfilled is True:
                    event_tags.extend(tag['tags'])

            # process tags refinement
            additions = tag.get('additions', None)
            if additions is not None:
                refinement = self.__apply_tag_refinement(event, additions)
                event_tags.extend(refinement)

        return event_tags

    def prepare_plaso(self, timeline_plaso, fd_out, tags_kb):
        with open(timeline_plaso, mode='r', encoding='utf8') as f:
            for line in f:
                event = json.loads(line)
                event['timestamp'] = event['timestamp']/1000000
                event['datetime'] = datetime.fromtimestamp(event['timestamp'], timezone.utc).isoformat(timespec='seconds')
                event['source'] = 'plaso_' + event['parser']
                event['raw'] = event.pop('message')

                if tags_kb is not None:
                    event_tags, source = self.__get_plaso_tags(event, tags_kb)
                    if len(event_tags) > 0:
                        event['fair_tags'] = event_tags
                        event['source'] = source

                fd_out.write('{},{}\n'.format(event['timestamp'], json.dumps(event)))

    def __get_plaso_tags(self, event, tags):
        possible_tags = [tag for tag in tags if tag['plaso_parser'] == event['parser']]

        event_tags = []
        source = None
        for tag in possible_tags:
            # process conditions
            conditions = tag.get('conditions', None)
            if conditions is None:
                event_tags.extend(tag['tags'])
                source = tag['source']
            else:
                fulfilled = self.__apply_tag_conditions(event, conditions)
                if fulfilled is True:
                    event_tags.extend(tag['tags'])
                    source = tag['source']

            # process tags refinement
            additions = tag.get('additions', None)
            if additions is not None:
                refinement = self.__apply_tag_refinement(event, additions)
                event_tags.extend(refinement)

        return event_tags, source

    def __apply_tag_refinement(self, event, additions):
        refinement = []

        for addition in additions:
            key = addition['key'].split('.')
            event_value = event[key[0]]
            for subkey in key[1:]:
                event_value = event_value[subkey]

            if any(event_value.startswith(value) for value in addition['values']):
                refinement.extend(addition['tags'])

        return refinement

    def __apply_tag_conditions(self, event, conditions):
        fulfilled = True

        for condition in conditions:
            key = condition['key'].split('.')
            event_value = event[key[0]]
            for subkey in key[1:]:
                event_value = event_value[subkey]

            values_on = [value for value in condition['values'] if not value.startswith('!')]
            values_off = [value[1:] for value in condition['values'] if value.startswith('!')]
            fulfilled_or = any(event_value.startswith(value) for value in values_on)
            fulfilled_or = fulfilled_or or any(not event_value.startswith(value) for value in values_off)
            fulfilled = fulfilled and fulfilled_or

        return fulfilled

        # prefetchs = {}
        # for line in fd_prefetch:
        #     execution = json.loads(line)
        #     prefetch_name = execution['filename']

        #     if prefetch_name not in prefetchs.keys():
        #         prefetchs[prefetch_name] = {
        #             'first_known_execution': None,
        #             'executions_time': []
        #         }

        #     # plaso timestamp in 'Creation Time' relates to volumne creation time (not first execution)
        #     if execution['timestamp_desc'] == 'Previous Last Time Executed':
        #         exec_time = self._filetime_to_datetime(execution['date_time']['timestamp'])
        #         if prefetchs[prefetch_name]['first_known_execution'] is None or exec_time < prefetchs[prefetch_name]['first_known_execution']:
        #             prefetchs[prefetch_name]['first_known_execution'] = exec_time
        #             prefetchs[prefetch_name]['executions_time'].append(str(exec_time))

        #     if execution['timestamp_desc'] == 'Last Time Executed':
        #         exec_time = self._filetime_to_datetime(execution['date_time']['timestamp'])
        #         prefetchs[prefetch_name]['last_known_execution'] = exec_time
        #         prefetchs[prefetch_name]['nb_executions'] = execution['run_count']
        #         prefetchs[prefetch_name]['exe_path'] = ';'.join(execution['path_hints'])
        #         prefetchs[prefetch_name]['mapped_files'] = execution['mapped_files']
        #         prefetchs[prefetch_name]['executions_time'].append(str(exec_time))
