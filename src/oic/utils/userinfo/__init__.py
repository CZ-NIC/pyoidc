__author__ = 'rolandh'


class UserInfo(object):
    """ Read only interface to a user info store """

    def __init__(self, db=None):
        self.db = db

    def __call__(self, userid, user_info_claims=None, **kwargs):
        try:
            return self.db[userid]
        except KeyError:
            return {}

