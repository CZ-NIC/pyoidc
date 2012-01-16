__author__ = 'rohe0002'

from oic.oauth2.message import Base
from oic.oauth2.message import SINGLE_REQUIRED_STRING
from oic.oauth2.message import SINGLE_OPTIONAL_STRING
from oic.oauth2.message import SINGLE_OPTIONAL_INT
from oic.oauth2.message import OPTIONAL_LIST_OF_STRINGS

class AccessTokenRequest(Base):
    c_attributes = Base.c_attributes.copy()
    c_attributes["code"] = SINGLE_REQUIRED_STRING
    c_attributes["redirect_uri"] = SINGLE_REQUIRED_STRING
    c_attributes["client_id"] = SINGLE_REQUIRED_STRING
    c_attributes["client_secret"] = SINGLE_REQUIRED_STRING
    #c_attributes["grant_type"] = SINGLE_REQUIRED_STRING


    def __init__(self,
                 code=None,
                 redirect_uri=None,
                 client_id=None,
                 client_secret=None,
                 **kwargs):
        Base.__init__(self, **kwargs)
        self.code = code
        self.redirect_uri = redirect_uri
        self.client_id = client_id
        self.client_secret = client_secret

class AccessTokenResponse(Base):
    c_attributes = Base.c_attributes.copy()
    c_attributes["access_token"] = SINGLE_REQUIRED_STRING
    #c_attributes["token_type"] = SINGLE_REQUIRED_STRING
    c_attributes["expires"] = SINGLE_OPTIONAL_INT
    c_attributes["refresh_token"] = SINGLE_OPTIONAL_STRING
    c_attributes["scope"] = OPTIONAL_LIST_OF_STRINGS
    # Only for implicit flow
    c_attributes["state"] = SINGLE_OPTIONAL_STRING

    def __init__(self,
                 access_token=None,
                 token_type=None,
                 expires_in=None,
                 refresh_token=None,
                 scope=None,
                 state=None,
                 **kwargs):
        Base.__init__(self, **kwargs)
        self.access_token = access_token
        self.token_type = token_type
        self.expires_in = expires_in
        self.refresh_token = refresh_token
        self.scope = scope or []
        self.state = state
