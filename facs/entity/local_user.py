class LocalUserEntity():
    def __init__(
        self, rid, sid, username, full_name, ms_account,
        groups, is_disabled, created_at, expire_at,
        nb_logins_invalid, nb_logins_total, last_login_at,
        last_pw_incorrect_at, last_pw_change_at
    ):
        self.rid = rid
        self.sid = sid
        self.username = username
        self.full_name = full_name
        self.ms_account = ms_account
        self.groups = groups
        self.is_disabled = is_disabled
        self.created_at = created_at
        self.expire_at = expire_at
        self.nb_logins_invalid = nb_logins_invalid
        self.nb_logins_total = nb_logins_total
        self.last_login_at = last_login_at
        self.last_pw_incorrect_at = last_pw_incorrect_at
        self.last_pw_change_at = last_pw_change_at

    def to_dict(self):
        return {
            'rid': self.rid,
            'sid': self.sid,
            'username': self.username,
            'full_name': self.full_name,
            'ms_account': self.ms_account,
            'groups': self.groups,
            'is_disabled': self.is_disabled,
            'created_at': str(self.created_at),
            'expire_at': str(self.expire_at),
            'nb_logins_invalid': self.nb_logins_invalid,
            'nb_logins_total': self.nb_logins_total,
            'last_login_at': str(self.last_login_at),
            'last_pw_incorrect_at': str(self.last_pw_incorrect_at),
            'last_pw_change_at': str(self.last_pw_change_at),
        }
