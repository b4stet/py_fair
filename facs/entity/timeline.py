class TimelineEntity():
    TIMELINE_TYPE_LOG = 'LOG'
    TIMELINE_TYPE_EVENT = 'EVENT'

    def __init__(self, start, host, event, event_type, source, user='', foreign='', end='', note=''):
        self.__start = start
        self.__end = end
        self.__host = host
        self.__user = user
        self.__foreign = foreign
        self.__event = event
        self.__type = event_type
        self.__source = source
        self.__note = note

    def to_dict(self):
        return {
            'start': self.__start,
            'end': self.__end,
            'host': self.__host,
            'user': self.__user,
            'foreign': self.__foreign,
            'event': self.__event,
            'type': self.__type,
            'source': self.__source,
            'note': self.__note,
        }

    def get_start(self):
        return self.__start

    def get_end(self):
        return self.__end

    def get_host(self):
        return self.__host

    def get_user(self):
        return self.__user

    def get_foreign(self):
        return self.__foreign

    def get_event(self):
        return self.__event

    def get_type(self):
        return self.__type

    def get_source(self):
        return self.__source

    def get_note(self):
        return self.__note
