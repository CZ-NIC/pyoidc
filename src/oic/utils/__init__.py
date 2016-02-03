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
        print("[%s] ExcList: %s" % (tag, "".join(message),), file=sys.stderr)
        print("[%s] Exception: %s" % (tag, exc), file=sys.stderr)
