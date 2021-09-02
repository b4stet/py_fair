class UserMountPointEntity():
    def __init__(self, volume_guid, last_connected_at):
        self.volume_guid = volume_guid
        self.last_connected_at = last_connected_at

    def to_dict(self):
        return {
            'volume_guid': self.volume_guid,
            'last_connected_at': str(self.last_connected_at),
        }
