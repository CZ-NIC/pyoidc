# Useful utilities

import sys
import traceback
from jwkest import as_unicode

__author__ = 'rohe0002'


def exception_trace(tag, exc, log=None):
    message = traceback.format_exception(*sys.exc_info())
    if log:
        log.error("[%s] ExcList: %s" % (tag, "".join(message),))
        log.error("[%s] Exception: %s" % (tag, exc))
    else:
        print >> sys.stderr, "[%s] ExcList: %s" % (tag, "".join(message),)
        print >> sys.stderr, "[%s] Exception: %s" % (tag, exc)


def elements_to_unicode(b):
    """
    Tries to convert all elements in a list/dict from a byte string to an unicode string
    :param b: list / dict
    :return: list / dict
    """

    if isinstance(b, list):
        return [as_unicode(v) for v in b]

    if isinstance(b, dict):
        conv_dict = dict()
        for key in b.keys():
            conv_dict[key] = as_unicode(b[key])
        return conv_dict


