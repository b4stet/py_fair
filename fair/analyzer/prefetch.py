import pyscca
from fair.analyzer.abstract import AbstractAnalyzer


class PrefetchAnalyzer(AbstractAnalyzer):
    def extract(self, pf_file):
        prefetch = pyscca.file()
        prefetch.open(pf_file)

        extracted = {
            'prefetch_file': pf_file,
            'executable': prefetch.get_executable_filename(),
        }

        # run times and count
        extracted['run_count'] = prefetch.get_run_count()
        extracted['executions_time'] = []
        for i in range(0, 8):
            if prefetch.get_last_run_time_as_integer(i) > 0:
                extracted['executions_time'].append(prefetch.get_last_run_time(i).isoformat())
            else:
                extracted['executions_time'].append('n/a')

        # volumes information
        extracted['volumes_information'] = []
        for i in range(0, prefetch.get_number_of_volumes()):
            extracted['volumes_information'].append({
                'creation_time': prefetch.get_volume_information(i).get_creation_time().isoformat(),
                'device_path': prefetch.get_volume_information(i).get_device_path(),
                'serial_number': prefetch.get_volume_information(i).get_serial_number(),
            })

        # files loaded
        extracted['files_loaded'] = [prefetch.get_filename(i) for i in range(0, prefetch.get_number_of_filenames())]

        prefetch.close()

        return extracted

    def flatten(self, prefetch):
        flattened = []
        for file in prefetch['files_loaded']:
            nb_executions = sum( date != 'n/a' for date in prefetch['executions_time'])
            volumes_info = ['{}(created at {}, SN {})'.format(
                volume['device_path'], volume['creation_time'], volume['serial_number']) for volume in prefetch['volumes_information']
            ]
            info = {
                'prefetch_file': prefetch['prefetch_file'],
                'executable': prefetch['executable'],
                'file_loaded': file,
                'nb_executions': '{} (run_count: {})'.format(nb_executions, prefetch['run_count']),
                'volumes_info': '|'.join(volumes_info),
            }

            for i in range(0, 8):
                info[f'last_run_time_{i+1}'] = prefetch['executions_time'][i]

            flattened.append(info)
        return flattened
