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
                prefetchs[prefetch_name] = {
                    'oldest_recorded_execution': None,
                }

            # because of plaso timestamp in 'Creation Time' is wrong
            if execution['timestamp_desc'] == 'Previous Last Time Executed':
                exec_time = self._filetime_to_datetime(execution['date_time']['timestamp'])
                if prefetchs[prefetch_name]['oldest_recorded_execution'] is None or exec_time < prefetchs[prefetch_name]['oldest_recorded_execution']:
                    prefetchs[prefetch_name]['oldest_recorded_execution'] = exec_time

            if execution['timestamp_desc'] == 'Last Time Executed':
                prefetchs[prefetch_name]['earliest_execution'] = self._filetime_to_datetime(execution['date_time']['timestamp'])
                prefetchs[prefetch_name]['nb_executions'] = execution['run_count']
                prefetchs[prefetch_name]['mapped_files'] = execution['mapped_files']

        # flatten results per mapped file
        prefetchs_flattened = []
        for prefetch, info in prefetchs.items():
            for file in info['mapped_files']:
                prefetchs_flattened.append({
                    'prefetch_path': prefetch,
                    'oldest_recorded_execution': str(info['oldest_recorded_execution']) if info['nb_executions'] > 1 else str(info['earliest_execution']),
                    'earliest_execution': str(info['earliest_execution']),
                    'nb_executions': info['nb_executions'],
                    'mapped_file': file,
                })

        return prefetchs_flattened
