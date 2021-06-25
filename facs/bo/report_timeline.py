from facs.entity.timeline import TimelineEntity
from facs.bo.abstract import AbstractBo


class ReportTimelineBO(AbstractBo):
    def get_profiling(self, results_evtx, results_registry, channels):
        timeline_global = []
        report_global = []

        timeline, report = self.__get_profiling_log_start_end(results_evtx['computer_name'], results_evtx['log_start_end'], channels)
        timeline_global += timeline
        report_global.append(report)

        timeline, report = self.__get_profiling_system_backdating(results_evtx['time_changed'])
        timeline_global += timeline
        report_global.append(report)

        timeline, report = self.__get_profiling_log_cleaning(results_evtx['log_tampered'])
        timeline_global += timeline
        report_global.append(report)

        timeline, report = self.__get_profiling_system_start_stop(results_evtx['host_start_stop'])
        timeline_global += timeline
        report_global.append(report)

        profiling_host, report = self.__get_profiling_host_info(results_registry)
        report_global.append(report)

        profiling_users, report = self.__get_profiling_local_users(results_registry)
        report_global.append(report)

        profiling_applications, report = self.__get_profiling_applications(results_evtx['app_uninstalled'], results_registry)
        report_global.append(report)

        timeline, profiling_nic, profiling_interfaces, report = self.__get_profiling_networks(results_registry)
        timeline_global += timeline
        profiling_host += profiling_nic
        report_global.append(report)

        return {
            'timeline': timeline_global,
            'report': report_global,
            'profiling': {
                'host': profiling_host,
                'users': profiling_users,
                'interfaces': profiling_interfaces,
                'applications': profiling_applications,
            }
        }

    def __get_profiling_log_start_end(self, computer, start_end, channels):
        timeline = []
        report = {
            'title': '',
            'data': [],
        }

        report['title'] = 'Checked start/end of windows event log for main channels'
        for channel in channels:
            found = 'ok'
            if start_end[channel]['start'] is None:
                found = 'not found'

            report['data'].append('{:80}: {}'.format(channel, found))
            if start_end[channel]['start'] is None:
                continue

            event = TimelineEntity(
                start=str(start_end[channel]['start']),
                end=str(start_end[channel]['end']),
                host=computer,
                event='log start/end',
                event_type=TimelineEntity.TIMELINE_TYPE_LOG,
                source='{}.evtx'.format(channel)
            )

            timeline.append(event.to_dict())

        return timeline, report

    def __get_profiling_system_backdating(self, backdating):
        report = {
            'title': '',
            'data': [],
        }

        report['title'] = 'Checked evidences of system backdating'
        report['data'].append('Looked for clock drift bigger than 10 minutes')
        report['data'].append('From Security channel, provider Microsoft-Windows-Security-Auditing, EID 4616 where user is not "LOCAL SERVICE" or "SYSTEM"')
        report['data'].append('From System channel, provider Microsoft-Windows-Kernel-General, EID 1 where reason is not 2')
        report['data'].append('Found: {} event(s)'.format(len(backdating)))

        return backdating, report

    def __get_profiling_log_cleaning(self, cleaning):
        report = {
            'title': '',
            'data': [],
        }

        report['title'] = 'Checked evidences of log tampering'
        report['data'].append('From Security channel, provider Microsoft-Windows-Eventlog, EID 1100/1102/1104')
        report['data'].append('From System channel, provider Eventlog, EID 6005/6006')
        report['data'].append('Found {} event(s)'.format(len(cleaning)))

        return cleaning, report

    def __get_profiling_system_start_stop(self, start_stop):
        report = {
            'title': '',
            'data': [],
        }

        report['title'] = 'Checked evidences of host start/stop'
        report['data'].append('From Security channel, provider Microsoft-Windows-Eventlog, EID 4608/4609')
        report['data'].append('From System channel, provider Microsoft-Windows-Kernel-General, EID 12/13')
        report['data'].append('From System channel, provider User32, EID 1074')
        report['data'].append('Found {} event(s)'.format(len(start_stop)))

        return start_stop, report

    def __get_profiling_host_info(self, results_registry):
        profiling = []
        report = {
            'title': '',
            'data': [],
        }

        report['title'] = 'Collected system information'
        report['data'].append('computer name from key SYSTEM\\Control\\ComputerName\\ComputerName')
        report['data'].append('OS info from key SYSTEM\\Microsoft\\Windows NT\\CurrentVersion')
        report['data'].append('time zone info from key SYSTEM\\Control\\TimeZoneInformation')
        report['data'].append('control sets from key SYSTEM\\Select')

        profiling.append({
            'name': 'computer name',
            'value': results_registry['computer_name'],
        })
        profiling.append({
            'name': 'OS',
            'value': '{}; installed on {}'.format(results_registry['os']['version'], results_registry['os']['install_date']),
        })
        profiling.append({
            'name': 'local time',
            'value': '{} (UTC = local time + {} min)'.format(results_registry['time_zone']['name'], results_registry['time_zone']['active_time_bias']),
        })
        profiling.append({
            'name': 'control sets',
            'value': 'current is {}; last known good is {}; available are [{}]'.format(
                results_registry['control_sets']['current'], results_registry['control_sets']['last_known_good'],
                ','.join(results_registry['control_sets']['available'])
            )
        })
        return profiling, report

    def __get_profiling_networks(self, results_registry):
        timeline = []
        profiling_nic = []
        profiling_parameters = []
        report = {
            'title': '',
            'data': [],
        }

        report['title'] = 'Collected network connections'
        report['data'].append('NIC from subkeys of SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkCards')
        report['data'].append('interface parameters from subkeys of SOFTWARE\\Services\\Tcpip\\Parameters\\Interfaces\\')
        report['data'].append('connections history from subkeys of SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Signatures\\')

        for nic in results_registry['networks']['nics']:
            profiling_nic.append({
                'name': 'NIC',
                'value': 'GUID {} ({})'.format(nic['guid'], nic['description'])
            })

        for parameters in results_registry['networks']['parameters']:
            profiling_parameters.append({'name': 'Last known interface parameters', **parameters})

        for connection in results_registry['networks']['connections']:
            source = 'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Signatures\\'
            note = 'connection type {}; gateway MAC {}; profile GUID {}'.format(
                connection['connection_type'], connection['gateway_mac'], connection['profile_guid']
            )
            event_desc = 'connection to {} network (SSID: {})'.format(connection['dns_suffix'], connection['ssid'])

            host_first = results_registry['computer_name']
            if connection['ip_first'] is not None:
                host_first += ' ({})'.format(connection['ip_first'])
            host_last = results_registry['computer_name']
            if connection['ip_last'] is not None:
                host_last += ' ({})'.format(connection['ip_last'])

            event = TimelineEntity(
                start=str(connection['first_connected_at']),
                host=host_first,
                event='First ' + event_desc,
                event_type=TimelineEntity.TIMELINE_TYPE_EVENT,
                source=source,
                note=note
            )
            timeline = self._append_to_timeline(event, timeline)

            event = TimelineEntity(
                start=str(connection['last_connected_at']),
                host=host_last,
                event='Last ' + event_desc,
                event_type=TimelineEntity.TIMELINE_TYPE_EVENT,
                source=source,
                note=note
            )
            timeline = self._append_to_timeline(event, timeline)

        return timeline, profiling_nic, profiling_parameters, report

    def __get_profiling_local_users(self, results_registry):
        profiling = []
        report = {
            'title': '',
            'data': [],
        }

        report['title'] = 'Collected local accounts information'
        report['data'].append('accounts from key \\SAM\\Domains\\Account\\Users')
        report['data'].append('groups membership from key \\SAM\\Domains\\Builtin\\Aliases')
        report['data'].append('account creation from key \\SAM\\Domains\\Account\\Users\\Names')

        for user in results_registry['local_users']:
            profiling.append({'name': 'Local user', **user})

        return profiling, report

    def __get_profiling_applications(self, evtx_uninstalled, results_registry):
        profiling = []
        report = {
            'title': '',
            'data': [],
        }

        report['title'] = 'Collected application installed system wide and uninstalled'
        report['data'].append('system wide installation from key \\Microsoft\\Windows\\CurrentVersion\\Uninstall')
        report['data'].append('uninstalled from Application channel, provider MsiInstaller, EID 11724')

        for application in results_registry['applications']:
            profiling.append({'name': 'system wide application', **application})

        for application in evtx_uninstalled:
            profiling.append({
                'name': 'uninstalled application',
                'app_name': application['note'],
            })

        return profiling, report
