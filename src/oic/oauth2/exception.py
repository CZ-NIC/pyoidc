from oic.exception import PyoidcError

__author__ = 'roland'


class HttpError(PyoidcError):
    pass


class MissingRequiredAttribute(PyoidcError):
    pass


class VerificationError(PyoidcError):
    pass


class ResponseError(PyoidcError):
    pass


class TimeFormatError(PyoidcError):
    pass


class CapabilitiesMisMatch(PyoidcError):
    pass


class MissingEndpoint(PyoidcError):
    pass


class TokenError(PyoidcError):
    pass


class GrantError(PyoidcError):
    pass


class ParseError(PyoidcError):
    pass


class OtherError(PyoidcError):
    pass


class AuthnToOld(PyoidcError):
    pass


class NoClientInfoReceivedError(PyoidcError):
    pass


class InvalidRequest(PyoidcError):
    pass


