import json
from facs.analyzer.abstract import AbstractAnalyzer


class ArtifactAnalyzer(AbstractAnalyzer):
    def analyze_prefetchs(self, fd_prefetch):
        # collect info
        prefetchs = {}
        for line in fd_prefetch:
            execution = json.loads(line)
            prefetch_name = execution['filename']

            if prefetch_name not in prefetchs.keys():
                prefetchs[prefetch_name] = {}

            if execution['timestamp_desc'] == 'Creation Time':
                prefetchs[prefetch_name]['first_execution'] = self._filetime_to_datetime(execution['date_time']['timestamp'])

            if execution['timestamp_desc'] == 'Last Time Executed':
                prefetchs[prefetch_name]['last_execution'] = self._filetime_to_datetime(execution['date_time']['timestamp'])
                prefetchs[prefetch_name]['nb_executions'] = execution['run_count']
                prefetchs[prefetch_name]['mapped_files'] = execution['mapped_files']

        # flatten results per mapped file
        prefetchs_flattened = []
        for prefetch, info in prefetchs.items():
            for file in info['mapped_files']:
                prefetchs_flattened.append({
                    'prefetch_path': prefetch,
                    'first_execution': str(info['first_execution']),
                    'last_execution': str(info['last_execution']),
                    'nb_executions': info['nb_executions'],
                    'mapped_file': file,
                })

        return prefetchs_flattened
