from rp1.openidconnect import OpenIDConnect
from rp1.oauth2 import OAuth2

__author__ = 'haho0032'
__author__ = 'haho0032'

import logging

logger = logging.getLogger(__name__)


class pyoidcOAuth2(OAuth2):
    def __init__(self, client_id, client_secret, **kwargs):
        OAuth2.__init__(self, client_id, client_secret, **kwargs)
        self.token_response_body_type = "json"

class pyoidcOIC(OpenIDConnect):
    def __init__(self, client_id, client_secret, **kwargs):
        OpenIDConnect.__init__(self, client_id, client_secret, **kwargs)
        self.token_response_body_type = "json"
