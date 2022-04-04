"""
Settings for oic objects.

.. CAUTION::
    This part is under development.
    Most of the configuration options are being converted from keyword arguments to settings class.
    Using the settings class is optional for now, but will become a necessity later on.

In order to configure some objects in PyOIDC, you need a settings object.
If you need to add some settings, make sure that you settings class inherits from the appropriate class in this module.
"""
import typing
from typing import Tuple
from typing import Union

import requests


class SettingsException(Exception):
    """Exception raised by misconfigured settings class."""


class PyoidcSettings:
    """
    Main class for all settings shared among consumer and client.

    Keyword Args:
        verify_ssl
            Control TLS server certificate validation.
            If set to True the certificate is validated against the global settings,
            if set to False, no validation is performed.
            If set to a filename this is used as a certificate bundle in openssl format.
            If set to a directory name this is used as a CA directory in the openssl format.
        client_cert
            Local cert to use as client side certificate.
            Can be a single file (containing the private key and the certificate) or a tuple of both file's path.
        timeout
            Timeout for requests library.
            Can be specified either as a single float or as a tuple of floats.
            For more details, refer to ``requests`` documentation.

    """

    def __init__(
        self,
        verify_ssl: Union[bool, str] = True,
        client_cert: Union[str, Tuple[str, str]] = None,
        timeout: Union[float, Tuple[float, float]] = 5,
    ):
        self.verify_ssl = verify_ssl
        self.client_cert = client_cert
        self.timeout = timeout

    def __setattr__(self, name, value):
        """This attempts to check if value matches the expected value."""
        annotation = typing.get_type_hints(self.__init__)[name]  # type: ignore
        # Expand Union -> Since 3.8, this can be written as typing.get_origin
        if getattr(annotation, "__origin__", annotation) is Union:
            expanded = tuple(an for an in annotation.__args__)
        else:
            expanded = (annotation,)
        # Convert Generics
        # FIXME: this doesn't check the args of the generic
        resolved = tuple(getattr(an, "__origin__", an) for an in expanded)
        # Add int if float is present
        if float in resolved:
            resolved = resolved + (int,)
        # FIXME: Add more valid substitution
        if isinstance(value, resolved):
            # FIXME: Handle bool being an instance of int...
            super().__setattr__(name, value)
        else:
            raise SettingsException(
                "%s has a type of %s, expected any of %s."
                % (name, type(value), resolved),
            )


class ClientSettings(PyoidcSettings):
    """
    Base settings for consumer shared among OAuth 2.0 and OpenID Connect.

    Keyword Args:
        requests_session
            Instance of `requests.Session` with configuration options.

    """

    def __init__(
        self,
        verify_ssl: Union[bool, str] = True,
        client_cert: Union[str, Tuple[str, str]] = None,
        timeout: Union[float, Tuple[float, float]] = 5,
        requests_session: requests.Session = None,
    ):
        super().__init__(
            verify_ssl=verify_ssl, client_cert=client_cert, timeout=timeout
        )
        # For session persistence
        self.requests_session = requests_session


class OauthClientSettings(ClientSettings):
    """Specific settings for OAuth 2.0 consumer."""


class OicClientSettings(OauthClientSettings):
    """Settings for OpenID Connect Client."""


class OauthConsumerSettings(OauthClientSettings):
    """Settings for OAuth 2.0 client."""


class ServerSettings(PyoidcSettings):
    """Base settings for server shared among OAuth 2.0 and OpenID Connect."""


class OauthServerSettings(ServerSettings):
    """Specific settings for OAuth 2.0 server."""


class OicServerSettings(OauthServerSettings):
    """Specific settings for OpenID Connect server."""


class OauthProviderSettings(OauthServerSettings):
    """Specific settings for OAuth 2.0 provider."""


class OicProviderSettings(OicServerSettings):
    """Specific settings for OpenID Connect provider."""

    # TODO: Decide on inheritance...
    # It might be better to have a mixin providing OIC specific stuff?
