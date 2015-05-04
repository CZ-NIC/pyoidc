import importlib
from oic.utils.authn.user import UserAuthnMethod

__author__ = 'regu0004'

class AuthnModule(UserAuthnMethod):

    # override in subclass specifying suitable url endpoint to POST user input
    url_endpoint = "/verify"
    FAILED_AUTHN = (None, True)

    def __call__(self, *args, **kwargs):
        """
        Display user interaction.
        :return: instance of oic.utils.http_util.Response
        """
        raise NotImplementedError()

    def verify(self, *args, **kwargs):
        """
        Callback to verify user input
        :return: username of the authenticated user
        """
        raise NotImplementedError()


def make_cls_from_name(name):
    module_name, cls_name = name.rsplit(".", 1)
    cls = getattr(importlib.import_module(module_name), cls_name)
    return cls
