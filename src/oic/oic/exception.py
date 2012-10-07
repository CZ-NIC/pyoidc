__author__ = 'rohe0002'

class OICError(Exception):
    pass

class MissingAttribute(OICError):
    pass

class UnsupportedMethod(OICError):
    pass

class AccessDenied(OICError):
    pass

class UnknownClient(OICError):
    pass

class MissingParameter(OICError):
    pass
