import click
import os
from regipy.registry import RegistryHive

from facs.command.abstract import AbstractCommand
from facs.entity.report import ReportEntity


class WindowsCommand(AbstractCommand):

    def __init__(self, evtx_analyzer, host_registry_analyzer, user_registry_analyzer):
        self.__evtx_analyzer = evtx_analyzer
        self.__host_reg_analyzer = host_registry_analyzer
        self.__user_reg_analyzer = user_registry_analyzer

    def get_commands(self):
        group = click.Group(
            'windows',
            help='forensicating a Windows host',
        )

        group.add_command(click.Command(
            name='profile_host', help='profile the subject system from evtx and registry',
            callback=self.do_profile_host,
            params=[
                self._get_option_evtx(),
                self._get_option_hive_sam(),
                self._get_option_hive_system(),
                self._get_option_hive_software(),
                self._get_option_outdir(),
                self._get_option_output(),
            ]
        ))

        group.add_command(click.Command(
            name='profile_users', help='profile the users on the subject system from their ntuser.dat hive',
            callback=self.do_profile_users,
            params=[
                self._get_option_hive_ntusers(),
                self._get_option_outdir(),
                self._get_option_output(),
            ]
        ))

        return group

    def do_profile_host(self, evtx, hive_sam, hive_system, hive_software, outdir, output):
        if not os.path.exists(outdir):
            raise ValueError('Out directory {} does not exist.'.format(outdir))

        # extract info from windows events
        print('[+] Analyzing evtx ', end='', flush=True)
        fd_evtx = open(evtx, mode='r', encoding='utf8')
        nb_events, report, timeline, collection = self.__evtx_analyzer.collect_common_events(fd_evtx)
        fd_evtx.close()
        print(' done. Processed {} events'.format(nb_events))

        # extract info from hives, and correlate with evtx in some cases
        print('[+] Analyzing registry hives ', end='', flush=True)

        analysis = {}
        reg_system = RegistryHive(hive_system)
        reg_software = RegistryHive(hive_software)
        reg_sam = RegistryHive(hive_sam)
        self.__host_reg_analyzer.set_current_control_set(reg_system)
        self.__host_reg_analyzer.set_computer_name(reg_system)

        report['host_info'], analysis['host_info'] = self.__host_reg_analyzer.collect_host_info(reg_system, reg_software)
        analysis['host_info'] = [a.to_dict() for a in analysis['host_info']]
        print('.', end='', flush=True)

        report['local_users'], analysis['local_users'] = self.__host_reg_analyzer.collect_local_users(reg_sam)
        analysis['local_users'] = [a.to_dict() for a in analysis['local_users']]
        print('.', end='', flush=True)

        report['applications'], analysis['applications'] = self.__host_reg_analyzer.collect_applications(collection['app_uninstalled'], reg_software)
        analysis['applications'] = [a.to_dict() for a in analysis['applications']]
        print('.', end='', flush=True)

        report['autoruns'], analysis['autoruns'] = self.__host_reg_analyzer.analyze_autoruns(reg_system, reg_software)
        analysis['autoruns'] = [a.to_dict() for a in analysis['autoruns']]
        print('.', end='', flush=True)

        report['networks'], timeline_networks, analysis['networks'] = self.__host_reg_analyzer.analyze_networks(reg_system, reg_software)
        analysis['networks'] = [a.to_dict() for a in analysis['networks']]
        timeline.extend(timeline_networks)
        print('.', end='', flush=True)

        report['usb'], timeline_usb, analysis['usb'] = self.__host_reg_analyzer.analyze_usb(collection['storage_info'], collection['pnp_connections'], reg_system, reg_software)
        analysis['usb'] = [a.to_dict() for a in analysis['usb']]
        timeline.extend(timeline_usb)
        print('.', end='', flush=True)

        print(' done.')

        # list what was analyzed
        for paragraph in report.values():
            self._print_text(paragraph.title, paragraph.details)

        # write analysis
        output_files = ReportEntity(
            title='Output files',
            details=[]
        )
        for topic, results in analysis.items():
            outfile = 'profile_host_{}.{}'.format(topic, output)
            outfile = os.path.join(outdir, outfile)
            output_files.details.append('{}'.format(outfile))
            self._write_formatted(outfile, output, results)

        # write timeline
        timeline = sorted(timeline, key=lambda k: k['start'])
        outfile = 'timeline.{}'.format(output)
        outfile = os.path.join(outdir, outfile)
        output_files.details.append('{}'.format(outfile))
        self._write_formatted(outfile, output, timeline)

        self._print_text(output_files.title, output_files.details)

    def do_profile_users(self, hive_users, outdir, output):
        if not os.path.exists(outdir):
            raise ValueError('Out directory {} does not exist.'.format(outdir))

        first = True
        for hive_user, username in hive_users:
            # process
            print('[+] Analyzing registry hive for user {} '.format(username), end='', flush=True)

            reg_user = RegistryHive(hive_user)
            report = {}
            analysis = {}
            report['rdp_connections'], analysis['rdp_connections'] = self.__user_reg_analyzer.analyze_rdp_connections(reg_user)
            analysis['rdp_connections'] = [a.to_dict() for a in analysis['rdp_connections']]
            print('.', end='', flush=True)

            report['usb_shares_usage'], analysis['usb_shares_usage'] = self.__user_reg_analyzer.analyze_usb_shares_usage(reg_user)
            analysis['usb_shares_usage'] = [a.to_dict() for a in analysis['usb_shares_usage']]
            print('.', end='', flush=True)

            report['autoruns'], analysis['autoruns'] = self.__user_reg_analyzer.analyze_autoruns(reg_user)
            analysis['autoruns'] = [a.to_dict() for a in analysis['autoruns']]
            print('.', end='', flush=True)

            report['applications'], analysis['applications'] = self.__user_reg_analyzer.analyze_applications(reg_user)
            analysis['applications'] = [a.to_dict() for a in analysis['applications']]
            print('.', end='', flush=True)

            report['cloud_accounts'], analysis['cloud_accounts'] = self.__user_reg_analyzer.analyze_cloud_accounts(reg_user)
            analysis['cloud_accounts'] = [a.to_dict() for a in analysis['cloud_accounts']]
            print('.', end='', flush=True)

            print(' done.\n')

            # list what was analyzed
            if first is True:
                for paragraph in report.values():
                    self._print_text(paragraph.title, paragraph.details)

            # write analysis
            output_files = ReportEntity(
                title='Output files for user {}'.format(username),
                details=[]
            )
            for topic, results in analysis.items():
                outfile = 'profile_user_{}_{}.{}'.format(username, topic, output)
                outfile = os.path.join(outdir, outfile)
                output_files.details.append('{}'.format(outfile))
                self._write_formatted(outfile, output, results)
            self._print_text(output_files.title, output_files.details)

            first = False
