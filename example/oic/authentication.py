__author__ = 'rohe0002'


class AuthnFailure(Exception):
    pass

class Authentication(object):
    def __init__(self, filename):
        self._db = eval(open(filename).read())

    def verify_username_and_password(self, username, passwd):
        # verify username and password
        try:
            if self._db[username] == passwd:
                return True
            else:
                raise AuthnFailure("Wrong password")
        except KeyError:
            raise AuthnFailure("Wrong password")
            