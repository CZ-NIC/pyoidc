from __future__ import print_function
import sys
import traceback

__author__ = 'rohe0002'


def exception_trace(tag, exc, log=None):
    message = traceback.format_exception(*sys.exc_info())
    if log:
        log.error("[%s] ExcList: %s", tag, "".join(message))
        log.error("[%s] Exception: %s", tag, exc)
    else:
        print("[{0}] ExcList: {1}".format(tag, "".join(message)),
              file=sys.stderr)
        print("[{0}] Exception: {1}".format(tag, exc), file=sys.stderr)
