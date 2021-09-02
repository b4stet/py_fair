class ApplicationEntity():
    def __init__(self, source, name, info):
        self.source = source
        self.name = name
        self.info = info

    def to_dict(self):
        return {
            'source': self.source,
            'name': self.name,
            'info': self.info,
        }
