"""
Settings for oic objects.

.. CAUTION::
    This part is under development.
    Most of the configuration options are being converted from keyword arguments to settings class.
    Using the settings class is optional for now, but will become a necessity later on.

In order to configure some objects in PyOIDC, you need a settings object.
If you need to add some settings, make sure that you settings class inherits from the appropriate class in this module.
"""
from typing import Tuple
from typing import Union


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
            If set to a filename his is used as a certificate bundle in openssl format.
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


class ConsumerSettings(PyoidcSettings):
    """Base settings for consumer shared among OAuth 2.0 and OpenID Connect."""


class OauthConsumerSettings(ConsumerSettings):
    """Specific settings for consumer OAuth 2.0 consumer."""


class ProviderSettings(PyoidcSettings):
    """Base settings for provider shared among OAuth 2.0 and OpenID Connect."""


class OauthProviderSettings(ProviderSettings):
    """Specific settings for OAuth 2.0 provider."""
