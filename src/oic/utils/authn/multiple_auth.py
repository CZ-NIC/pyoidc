from oic.utils.authn.authn_context import make_auth_verify
from oic.utils.authn.user import UserAuthnMethod

__author__ = 'danielevertsson'

class MultipleAuth(UserAuthnMethod):

    def __init__(self, auth_module):
        UserAuthnMethod.__init__(self, None)
        self.auth_module = auth_module

    def __call__(self, **kwargs):
        cookie = self.create_cookie(kwargs['query'], "query", UserAuthnMethod.MULTI_AUTH_COOKIE)
        resp = self.auth_module(**kwargs)
        resp.headers.append(cookie)
        return resp

def setup_multi_auth(ac, URLS, auth_modules):
    multi_auth = MultipleAuth(auth_modules[0][0])

    for module_index in range(0, len(auth_modules)):
        (module_instance, callback_regexp) = auth_modules[module_index]
        ac.add("", module_instance, 0, "")

        next_module_instance = None

        if module_index < len(auth_modules)-1:
            next_module_instance = auth_modules[module_index+1][0]

        URLS.append((callback_regexp, make_auth_verify(module_instance.verify, next_module_instance)))

    return multi_auth