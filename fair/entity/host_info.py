class HostInfoEntity():
    def __init__(self, title, value):
        self.title = title
        self.value = value

    def to_dict(self):
        return {
            'title': self.title,
            'value': self.value,
        }
