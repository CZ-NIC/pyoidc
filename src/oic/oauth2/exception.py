__author__ = 'rohe0002'


class PyoidcError(Exception):
    pass


class MissingAttribute(PyoidcError):
    pass


class UnsupportedMethod(PyoidcError):
    pass


class AccessDenied(PyoidcError):
    pass


class UnknownClient(PyoidcError):
    pass


class MissingParameter(PyoidcError):
    pass


class UnknownAssertionType(PyoidcError):
    pass


class ParameterError(PyoidcError):
    pass


class URIError(PyoidcError):
    pass


class InvalidRequest(PyoidcError):
    pass


class RedirectURIError(PyoidcError):
    pass


class ParseError(PyoidcError):
    pass


class FailedAuthentication(PyoidcError):
    pass


class MissingSession(PyoidcError):
    pass


class NotForMe(PyoidcError):
    pass


class UnSupported(Exception):
    pass

