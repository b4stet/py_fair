class StorageInfoEntity():
    def __init__(
        self, last_known_drive_letter='', user_label='', device_type='', driver='',
        manufacturer='', model='', revision='', bytes_capacity='', disk_serial_number='',
        partition_type='', disk_signature='', partition_offset='', partition_guid='',
        disk_guid='', adapter_guid='', registry_guid='', volume_guid='',
        vendor_product='', vid_pid='', serial_number='', device_label='',
        virtual_volume=''
    ):
        self.last_known_drive_letter = last_known_drive_letter
        self.user_label = user_label
        self.device_label = device_label
        self.device_type = device_type
        self.driver = driver
        self.manufacturer = manufacturer
        self.model = model
        self.revision = revision
        self.bytes_capacity = bytes_capacity
        self.disk_serial_number = disk_serial_number
        self.partition_type = partition_type
        self.disk_signature = disk_signature
        self.partition_offset = partition_offset
        self.partition_guid = partition_guid
        self.disk_guid = disk_guid
        self.adapter_guid = adapter_guid
        self.registry_guid = registry_guid
        self.vendor_product = vendor_product
        self.vid_pid = vid_pid
        self.serial_number = serial_number
        self.virtual_volume = virtual_volume
        self.volume_guid = volume_guid

    def to_dict(self):
        return {
            'last_known_drive_letter': self.last_known_drive_letter,
            'user_label': self.user_label,
            'device_label': self.device_label,
            'device_type': self.device_type,
            'driver': self.driver,
            'manufacturer': self.manufacturer,
            'model': self.model,
            'revision': self.revision,
            'bytes_capacity': self.bytes_capacity,
            'disk_serial_number': self.disk_serial_number,
            'partition_type': self.partition_type,
            'disk_signature': self.disk_signature,
            'partition_offset': self.partition_offset,
            'partition_guid': self.partition_guid,
            'disk_guid': self.disk_guid,
            'adapter_guid': self.adapter_guid,
            'registry_guid': self.registry_guid,
            'vendor_product': self.vendor_product,
            'vid_pid': self.vid_pid,
            'serial_number': self.serial_number,
            'virtual_volume': self.virtual_volume,
            'volume_guid': self.volume_guid,
        }
