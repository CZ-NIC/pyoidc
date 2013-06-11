class AuthzHandling(object):
    """ Class that allow an entity to manage authorization """

    def __init__(self):
        pass

    def __call__(self, *args, **kwargs):
        return ""


class UserInfoConsent(AuthzHandling):
    def __call__(self, user, userinfo, **kwargs):
        pass