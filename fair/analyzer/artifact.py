import json
from fair.analyzer.abstract import AbstractAnalyzer


class ArtifactAnalyzer(AbstractAnalyzer):
    def analyze_prefetchs(self, fd_prefetch):
        # collect info
        prefetchs = {}
        for line in fd_prefetch:
            execution = json.loads(line)
            prefetch_name = execution['filename']

            if prefetch_name not in prefetchs.keys():
                prefetchs[prefetch_name] = {
                    'first_known_execution': None,
                    'executions_time': []
                }

            # plaso timestamp in 'Creation Time' relates to volumne creation time (not first execution)
            if execution['timestamp_desc'] == 'Previous Last Time Executed':
                exec_time = self._filetime_to_datetime(execution['date_time']['timestamp'])
                if prefetchs[prefetch_name]['first_known_execution'] is None or exec_time < prefetchs[prefetch_name]['first_known_execution']:
                    prefetchs[prefetch_name]['first_known_execution'] = exec_time
                    prefetchs[prefetch_name]['executions_time'].append(str(exec_time))

            if execution['timestamp_desc'] == 'Last Time Executed':
                exec_time = self._filetime_to_datetime(execution['date_time']['timestamp'])
                prefetchs[prefetch_name]['last_known_execution'] = exec_time
                prefetchs[prefetch_name]['nb_executions'] = execution['run_count']
                prefetchs[prefetch_name]['exe_path'] = ';'.join(execution['path_hints'])
                prefetchs[prefetch_name]['mapped_files'] = execution['mapped_files']
                prefetchs[prefetch_name]['executions_time'].append(str(exec_time))

        # flatten results per mapped file
        prefetchs_flattened = []
        for prefetch, info in prefetchs.items():
            for file in info['mapped_files']:
                prefetchs_flattened.append({
                    'prefetch_path': prefetch,
                    'exe_path': info['exe_path'],
                    'first_known_execution': str(info['first_known_execution']) if info['nb_executions'] > 1 else str(info['last_known_execution']),
                    'last_known_execution': str(info['last_known_execution']),
                    'nb_executions': '{} (run_count: {})'.format(len(info['executions_time']), info['nb_executions']),
                    'exec_times': ';'.join(info['executions_time']),
                    'mapped_file': file,
                })

        return prefetchs_flattened
