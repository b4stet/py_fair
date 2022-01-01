from regipy.exceptions import RegistryKeyNotFoundException, NoRegistrySubkeysException

from fair.analyzer.abstract import AbstractAnalyzer
from fair.entity.report import ReportEntity
from fair.entity.user_terminal_server_client import UserTerminalServerClientEntity
from fair.entity.user_mount_point import UserMountPointEntity
from fair.entity.user_app_compat import UserAppCompatEntity
from fair.entity.cloud_account import CloudAccountEntity
from fair.entity.autorun import AutorunEntity


class UserRegistryAnalyzer(AbstractAnalyzer):
    def set_registry_codepage(self, codepage):
        self.__codepage = codepage

    def analyze_rdp_connections(self, reg_user):
        # describe what is done
        report = ReportEntity(
            title='Collected RDP connections',
            details=[
                'destination servers from key HKU\\software\\Microsoft\\Terminal Server Client\\Default',
                'username from subkeys of HKU\\software\\Microsoft\\Terminal Server Client\\Servers',
            ]
        )

        # analyze
        analysis = []
        base_path = '\\software\\Microsoft\\Terminal Server Client'
        try:
            key = reg_user.get_key(base_path + '\\Default')
            values = {value.name: value.value for value in key.get_values()}
            for name, value in values.items():
                subkey = reg_user.get_key(base_path + '\\Servers\\' + value)

                analysis.append(UserTerminalServerClientEntity(
                    destination=value,
                    username=subkey.get_value('UsernameHint'),
                    mru=name.replace('MRU', ''),
                    last_connected_at=self._filetime_to_datetime(key.header.last_modified) if name == 'MRU0' else ''
                ))

        except (NoRegistrySubkeysException, RegistryKeyNotFoundException):
            pass

        return report, analysis

    def analyze_usb_shares_usage(self, reg_user):
        # describe what is done
        report = ReportEntity(
            title='Collected connections to network shares and USB devices',
            details=[
                'from HKU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2'
            ]
        )

        # analyze
        analysis = []
        path = '\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2'
        try:
            key = reg_user.get_key(path)
            for subkey in key.iter_subkeys():
                # process only subkeys which name is a volume GUID
                if subkey.header.key_name_string.decode(self.__codepage).startswith('{') is False:
                    continue

                # a connection implies the creation of a subsubkey 'shell'
                if subkey.header.subkey_count == 0:
                    continue

                analysis.append(UserMountPointEntity(
                    volume_guid=subkey.header.key_name_string.decode(self.__codepage),
                    last_connected_at=self._filetime_to_datetime(subkey.header.last_modified)
                ))
        except RegistryKeyNotFoundException:
            pass

        return report, analysis

    def analyze_autoruns(self, reg_user):
        # describe what is done
        report = ReportEntity(
            title='Collected autostart services and applications',
            details=[
                'shell value at logon from key NTUSER\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon',
                'commands executed at each run of cmd.exe from key NTUSER\\Software\\Microsoft\\Command Processor',
                'autostart app and service from key NTUSER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
                'autostart app and service from key NTUSER\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
            ]
        )

        # analyze
        analysis = []

        # collect winlogon shell value
        path = '\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon'
        key = reg_user.get_key(path)
        values = {value.name: value.value for value in key.get_values()}
        analysis.append(AutorunEntity(
            reg_key='HKU' + path,
            last_modified_at=self._filetime_to_datetime(key.header.last_modified),
            description='Shell value expected to be explorer.exe',
            name='Shell',
            value=values.get('Shell', '')
        ))

        # collect command processor values (executed when cmd run)
        path = '\\Software\\Microsoft\\Command Processor'
        try:
            key = reg_user.get_key(path)
            for value in key.get_values():
                analysis.append(AutorunEntity(
                    reg_key='HKU' + path,
                    last_modified_at=self._filetime_to_datetime(key.header.last_modified),
                    description='Executed at each run of cmd.exe',
                    name=value.name,
                    value=value.value
                ))
        except RegistryKeyNotFoundException:
            pass

        # collect run/run once subkeys
        path = '\\Software\\Microsoft\\Windows\\CurrentVersion\\Run'
        key = reg_user.get_key(path)
        for value in key.get_values():
            analysis.append(AutorunEntity(
                reg_key='HKU' + path,
                last_modified_at=self._filetime_to_datetime(key.header.last_modified),
                description='Program automatically started at user logon',
                name=value.name,
                value=value.value
            ))

        path = '\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce'
        try:
            key = reg_user.get_key(path)
            for value in key.get_values():
                analysis.append(AutorunEntity(
                    reg_key='HKU' + path,
                    last_modified_at=self._filetime_to_datetime(key.header.last_modified),
                    description='Program automatically started atuser logon',
                    name=value.name,
                    value=value.value
                ))
        except RegistryKeyNotFoundException:
            pass

        return report, analysis

    def analyze_applications(self, reg_user):
        # describe what is done
        report = ReportEntity(
            title='Collected applications executed by the user',
            details=[
                'from key HKU\\Software\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Compatibility Assistant\\Store',
            ]
        )

        # analyze
        analysis = []

        path = '\\Software\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Compatibility Assistant\\Store'
        try:
            key = reg_user.get_key(path)
            analysis.append(UserAppCompatEntity(
                info_type='key last modification',
                value=str(self._filetime_to_datetime(key.header.last_modified))
            ))

            for value in key.get_values():
                analysis.append(UserAppCompatEntity(
                    info_type='key value',
                    value=value.name
                ))
        except RegistryKeyNotFoundException:
            pass

        return report, analysis

    def analyze_cloud_accounts(self, reg_user):
        # describe what is done
        report = ReportEntity(
            title='Collected Cloud accounts and synchronisation information',
            details=[
                'Microsoft accounts from subkeys of HKU\\Software\\Microsoft\\IdentityCRL\\UserExtendedProperties',
                'Google DriveFS from key HKU\\Software\\Google\\DriveFS\\Share',
                'Google Backup and Sync from key HKU\\Software\\Google\\Drive',
                'OneDrive personal from key HKU\\Software\\Microsoft\\OneDrive\\Accounts\\Personal',
                'OneDrive for Business from key HKU\\\\Software\\Microsoft\\OneDrive\\Accounts\\Business1',
            ]
        )

        # analyze
        analysis = []

        # collect Microsoft accounts if any
        path = '\\Software\\Microsoft\\IdentityCRL\\UserExtendedProperties'
        try:
            key = reg_user.get_key(path)
            for subkey in key.iter_subkeys():
                analysis.append(CloudAccountEntity(
                    provider='Microsoft',
                    info='email:{} ; cid:{}'.format(subkey.header.key_name_string.decode(self.__codepage), subkey.get_value('cid'))
                ))
        except (RegistryKeyNotFoundException, NoRegistrySubkeysException):
            pass

        # collect Google accounts if any
        base_path = '\\Software\\Google'
        try:
            key = reg_user.get_key(base_path + '\\DriveFS\\Share')
            values = {value.name: value.value for value in key.get_values()}
            analysis.append(CloudAccountEntity(
                provider='Google DriveFS',
                info='mount point:{} ; metadata path:{}'.format(values['MountPoint'], values['BasePath'])
            ))
        except RegistryKeyNotFoundException:
            pass

        try:
            key = reg_user.get_key(base_path + '\\Drive')
            values = {value.name: value.value for value in key.get_values()}
            analysis.append(CloudAccountEntity(
                provider='Google Backup and Sync',
                info='metadata path: {}'.format(values['Path'])
            ))
        except RegistryKeyNotFoundException:
            pass

        # collect OneDrive accounts if any
        base_path = '\\Software\\Microsoft\\OneDrive\\Accounts'
        try:
            key = reg_user.get_key(base_path + '\\Personal')
            values = {value.name: value.value for value in key.get_values()}
            if values.get('UserEmail', None) is not None:
                key_synced = key.get_subkey('Tenants')
                synced_folders = []
                for subkey in key_synced.iter_subkeys():
                    synced_folders.extend([value.name for value in subkey.get_values()])

                analysis.append(CloudAccountEntity(
                    provider='OneDrive Personal',
                    info='email:{} ; cid:{} ; synced folders:{}'.format(values['UserEmail'], values['cid'], '|'.join(synced_folders))
                ))
        except (RegistryKeyNotFoundException, NoRegistrySubkeysException):
            pass

        try:
            key = reg_user.get_key(base_path + '\\Business1')
            values = {value.name: value.value for value in key.get_values()}
            if values.get('UserEmail', None) is not None:
                key_synced = key.get_subkey('Tenants')
                synced_folders = []
                for subkey in key_synced.iter_subkeys():
                    synced_folders += [value.name for value in subkey.get_values()]

                analysis.append(CloudAccountEntity(
                    provider='OneDrive Business',
                    info='email:{} ; cid:{} ; sharepoint URL:{} ; synced folders:{}'.format(values['UserEmail'], values['cid'], values['SPOResourceId'], '|'.join(synced_folders))
                ))
        except (RegistryKeyNotFoundException, NoRegistrySubkeysException):
            pass

        return report, analysis
