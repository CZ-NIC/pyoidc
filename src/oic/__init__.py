import hashlib
import random
import string

__author__ = 'rohe0002'
__version__ = '0.8.3'


OIDCONF_PATTERN = "%s/.well-known/openid-configuration"


def rndstr(size=16):
    """
    Returns a string of random ascii characters or digits

    :param size: The length of the string
    :return: string
    """
    _basech = string.ascii_letters + string.digits
    return "".join([random.choice(_basech) for _ in range(size)])


BASECH = string.ascii_letters + string.digits + '-._~'
CC_METHOD = {
    'S256': hashlib.sha256,
    'S384': hashlib.sha384,
    'S512': hashlib.sha512,
}


def unreserved(size=64):
    """
    Returns a string of random ascii characters, digits and unreserve characters

    :param size: The length of the string
    :return: string
    """

    return "".join([random.choice(BASECH) for _ in range(size)])
