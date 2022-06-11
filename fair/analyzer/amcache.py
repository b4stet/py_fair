from regipy.exceptions import RegistryParsingException
from fair.analyzer.abstract import AbstractAnalyzer


class AmcacheAnalyzer(AbstractAnalyzer):
    def extract(self, reg_amcache):
        results = {}

        # drivers
        results['drivers'] = []
        path = '\\Root\\InventoryDriverBinary'
        key = reg_amcache.get_key(path)
        for subkey in key.iter_subkeys():
            values = {value.name: value.value for value in subkey.get_values()}

            results['drivers'].append({
                'key': subkey.header.key_name_string.decode('utf8'),
                'last_modified_at': self._filetime_to_datetime(subkey.header.last_modified).isoformat(),
                'compilation_time': self._unixepoch_to_datetime(values['DriverTimeStamp']).isoformat(),
                'name': values['DriverName'],
                'version': values['DriverVersion'],
                'sha1': values['DriverId'][4:] if values.get('DriverId', None) is not None else None,
                'is_signed': values.get('DriverSigned', None),
                'service_name': values['Service'],
                'company': values['DriverCompany'],
                'product_name': values['Product'],
                'product_version': values['ProductVersion']
            })

        # PnP devices
        results['pnp'] = []
        path = '\\Root\\InventoryDevicePnp'
        key = reg_amcache.get_key(path)
        for subkey in key.iter_subkeys():
            try:
                values = {value.name: value.value for value in subkey.get_values()}
                if len(values) == 0:
                    continue

                results['pnp'].append({
                    'key': subkey.header.key_name_string.decode('utf8'),
                    'last_modified_at': self._filetime_to_datetime(subkey.header.last_modified).isoformat(),
                    'class': values['Class'],
                    'manufacturer': values['Manufacturer'],
                    'model': values['Model'],
                    'Provider': values['Provider'],
                    'Description': values['Description'],
                    'driver_inf': values['Inf'],
                    'driver_sha1': values['DriverId'][4:] if values['DriverId'] != 0 else 0,
                    'driver_date': values['DriverVerDate'],
                    'driver_version': values['DriverVerVersion'],
                })
            except RegistryParsingException:
                continue

        # Programs executed
        results['executed_programs'] = []
        path = '\\Root\\InventoryApplication'
        key = reg_amcache.get_key(path)
        for subkey in key.iter_subkeys():
            values = {value.name: value.value for value in subkey.get_values()}

            results['executed_programs'].append({
                'key': subkey.header.key_name_string.decode('utf8'),
                'last_modified_at': self._filetime_to_datetime(subkey.header.last_modified).isoformat(),
                'path': values['RootDirPath'],
                'language': values['Language'],
                'version': values['Version'],
                'publisher': values['Publisher'],
                'installed_at': values['InstallDate'],
                'installed_on_os_version': values['OSVersionAtInstallTime'],
            })

        # Files used by executable programs
        results['files_used_by_binaries'] = []
        path = '\\Root\\InventoryApplicationFile'
        key = reg_amcache.get_key(path)
        for subkey in key.iter_subkeys():
            values = {value.name: value.value for value in subkey.get_values()}
            if len(values) == 0:
                continue

            results['files_used_by_binaries'].append({
                'key': subkey.header.key_name_string.decode('utf8'),
                'last_modified_at': self._filetime_to_datetime(subkey.header.last_modified).isoformat(),
                'path': values['LowerCaseLongPath'],
                'language': values['Language'],
                'version': values['Version'],
                'publisher': values['Publisher'],
                'product_name': values['ProductName'],
                'product_version': values['ProductVersion'],
                'sha1': values['FileId'][4:] if values['FileId'] != 0 else 0,
                'link_date': values['LinkDate'],
                'is_pe': values.get('IsPeFile', None),
                'is_os_component': values.get('IsOsComponent', None),
            })

        return results
