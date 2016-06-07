import hashlib
import string

# Since SystemRandom is not available on all systems
try:
    import random.SystemRandom as rnd
except ImportError:
    import random as rnd

__author__ = 'rohe0002'
__version__ = '0.8.5.0'


OIDCONF_PATTERN = "%s/.well-known/openid-configuration"
CC_METHOD = {
    'S256': hashlib.sha256,
    'S384': hashlib.sha384,
    'S512': hashlib.sha512,
}


def rndstr(size=16):
    """
    Returns a string of random ascii characters or digits

    :param size: The length of the string
    :return: string
    """
    _basech = string.ascii_letters + string.digits
    return "".join([rnd.choice(_basech) for _ in range(size)])


BASECH = string.ascii_letters + string.digits + '-._~'


def unreserved(size=64):
    """
    Returns a string of random ascii characters, digits and unreserved
    characters

    :param size: The length of the string
    :return: string
    """

    return "".join([rnd.choice(BASECH) for _ in range(size)])
