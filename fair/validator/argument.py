def check_type(self, value, expected_type):
    if not isinstance(value, expected_type):
        raise TypeError('Expected {} type, got {}.'.format(expected_type.__name__, type(value)))
