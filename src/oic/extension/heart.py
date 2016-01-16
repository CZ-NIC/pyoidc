from oic.oauth2.message import SINGLE_REQUIRED_STRING
from oic.oic.message import JWT
from oic.oic.message import SINGLE_REQUIRED_INT

__author__ = 'roland'


class PrivateKeyJWT(JWT):
    c_param = JWT.c_param.copy()
    c_param.update({
        'aud': SINGLE_REQUIRED_STRING,
        "iss": SINGLE_REQUIRED_STRING,
        "sub": SINGLE_REQUIRED_STRING,
        "aud": SINGLE_REQUIRED_STRING,
        "exp": SINGLE_REQUIRED_INT,
        "iat": SINGLE_REQUIRED_INT,
        "jti": SINGLE_REQUIRED_STRING,
    })

