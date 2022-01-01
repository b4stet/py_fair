class UserTerminalServerClientEntity():
    def __init__(self, destination, username, mru, last_connected_at=''):
        self.destination = destination
        self.username = username
        self.mru = mru
        self.last_connected_at = last_connected_at

    def to_dict(self):
        return {
            'destination': self.destination,
            'username': self.username,
            'mru_position': self.mru,
            'last_connected_at': str(self.last_connected_at),
        }
