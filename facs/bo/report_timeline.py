from facs.entity.timeline import TimelineEntity
from facs.bo.abstract import AbstractBo


class ReportTimelineBO(AbstractBo):
    def get_profiling(self, computer, backdating, cleaning, start_stop, start_end, host, channels):
        timeline_global = []
        report_global = []

        timeline, report = self.__get_profiling_log_start_end(computer, start_end, channels)
        timeline_global += timeline
        report_global.append(report)

        timeline, report = self.__get_profiling_system_backdating(backdating)
        timeline_global += timeline
        report_global.append(report)

        timeline, report = self.__get_profiling_log_cleaning(cleaning)
        timeline_global += timeline
        report_global.append(report)

        timeline, report = self.__get_profiling_system_start_stop(start_stop)
        timeline_global += timeline
        report_global.append(report)

        timeline, report = self.__get_profiling_host_info(host)
        timeline_global += timeline
        report_global.append(report)

        timeline, report = self.__get_profiling_networks(host)
        timeline_global += timeline
        report_global.append(report)

        return timeline_global, report_global

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

    def __get_profiling_host_info(self, host):
        report = {
            'title': '',
            'data': [],
        }

        report['title'] = 'Collected system information'
        report['data'].append('- Got:')
        report['data'].append('  computer name from key SYSTEM\\Control\\ComputerName\\ComputerName')
        report['data'].append('  OS info from key SYSTEM\\Microsoft\\Windows NT\\CurrentVersion')
        report['data'].append('  time zone info from key SYSTEM\\Control\\TimeZoneInformation')
        report['data'].append('  control sets from key SYSTEM\\Select')
        report['data'].append('- Results:')
        report['data'].append('  computer name: {}'.format(host['computer_name']))
        report['data'].append('  OS:            {}, installed on {}'.format(host['os']['version'], host['os']['install_date']))
        report['data'].append('  local time:    {} (UTC = local time + {} min)'.format(host['time_zone']['name'], host['time_zone']['active_time_bias']))
        report['data'].append('  control sets:  current is {}, last known good is {}, available are [{}]'.format(
            host['control_sets']['current'], host['control_sets']['last_known_good'], ','.join(host['control_sets']['available'])
        ))
        return [], report

    def __get_profiling_networks(self, host):
        timeline = []
        report = {
            'title': '',
            'data': [],
        }

        report['title'] = 'Collected network connections'
        report['data'].append('- Got:')
        report['data'].append('  NIC from subkeys of SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkCards')
        report['data'].append('  interface parameters from subkeys of SOFTWARE\\Services\\Tcpip\\Parameters\\Interfaces\\')
        report['data'].append('  connections history from subkeys of SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Signatures\\')
        report['data'].append('- Results:')
        for nic in host['networks']['nics']:
            report['data'].append('  NIC GUID {}: {}'.format(nic['guid'], nic['description']))
        for parameters in host['networks']['parameters']:
            report['data'].append('  IP {}/{}: {}, {}, gateway {}, DHCP {}, DNS {}, NIC {}, lease {}/{}'.format(
                parameters['ip'], parameters['subnet_mask'], parameters['domain'], parameters['network_hint'], parameters['gateway'],
                parameters['dhcp_server'], parameters['dns_servers'], parameters['nic_guid'], str(parameters['lease_start']), str(parameters['lease_end'])
            ))

        for connection in host['networks']['connections']:
            source = 'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Signatures\\'
            note = 'connection type {}; gateway MAC {}; profile GUID {}'.format(
                connection['connection_type'], connection['gateway_mac'], connection['profile_guid']
            )
            event_desc = 'connection to {} network (SSID: {})'.format(connection['dns_suffix'], connection['ssid'])

            host_first = host['computer_name']
            if connection['ip_first'] is not None:
                host_first += ' ({})'.format(connection['ip_first'])
            host_last = host['computer_name']
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

        return timeline, report
