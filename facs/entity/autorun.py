class AutorunEntity():
    def __init__(self, reg_key, last_modified_at, description, name, value, start_type='', service_type=''):
        self.reg_key = reg_key
        self.last_modified_at = last_modified_at
        self.description = description
        self.start_type = start_type
        self.service_type = service_type
        self.name = name
        self.value = value

    def to_dict(self):
        return {
            'registry_key': self.reg_key,
            'last_modified_at': str(self.last_modified_at),
            'description': self.description,
            'start_type': self.start_type,
            'service_type': self.service_type,
            'name': self.name,
            'value': self.value,
        }
