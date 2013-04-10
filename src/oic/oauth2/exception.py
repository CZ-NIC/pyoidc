__author__ = 'rohe0002'


class OauthError(Exception):
    pass


class MissingAttribute(OauthError):
    pass


class UnsupportedMethod(OauthError):
    pass


class AccessDenied(OauthError):
    pass


class UnknownClient(OauthError):
    pass


class MissingParameter(OauthError):
    pass


class UnknownAssertionType(OauthError):
    pass


class ParameterError(OauthError):
    pass


class URIError(OauthError):
    pass


class InvalidRequest(OauthError):
    pass


class RedirectURIError(OauthError):
    pass


class ParseError(OauthError):
    pass


class FailedAuthentication(OauthError):
    pass


class MissingSession(OauthError):
    pass


class NotForMe(OauthError):
    pass


class UnSupported(Exception):
    pass