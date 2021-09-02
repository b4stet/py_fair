class ReportEntity():
    def __init__(self, title: str, details: list):
        self.title = title
        self.details = details

    def to_dict(self):
        return {
            'title': self.title,
            'details': self.details,
        }
