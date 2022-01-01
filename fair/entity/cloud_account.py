class CloudAccountEntity():
    def __init__(self, provider, info):
        self.provider = provider
        self.info = info

    def to_dict(self):
        return {
            'provider': self.provider,
            'info': self.info,
        }
