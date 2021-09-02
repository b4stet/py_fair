class UserAppCompatEntity():
    def __init__(self, info_type, value):
        self.info_type = info_type
        self.value = value

    def to_dict(self):
        return {
            'info_type': self.info_type,
            'value': self.value,
        }
