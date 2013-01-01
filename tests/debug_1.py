import time
from oic.oic import Client
from oic.utils.time_util import utc_time_sans_frac
from oic.oic.message import IdToken
from oic.utils.keyio import KeyChain, KeyJar

__author__ = 'rohe0002'

CLIENT_SECRET = "abcdefghijklmnop"
CLIENT_ID = "client_1"

KC_HMAC_VS = KeyChain({"hmac": "abcdefghijklmnop"}, usage=["ver", "sig"])
KC_RSA = KeyChain(source="file://../oc3/certs/mycert.key", type="rsa",
                  usage=["ver", "sig"])
KC_HMAC_S = KeyChain({"hmac": "abcdefghijklmnop"}, usage=["sig"])

KEYJ = KeyJar()
KEYJ[""] = [KC_RSA, KC_HMAC_S]
KEYJ["client_1"] = [KC_HMAC_VS]

IDTOKEN = IdToken(iss="http://oic.example.org/", user_id="user_id",
                  aud=CLIENT_ID, exp=utc_time_sans_frac()+86400,
                  nonce="N0nce",
                  iat=time.time())

# ----------------- CLIENT --------------------

client = Client(CLIENT_ID)
client.redirect_uris = ["http://example.com/redirect"]
client.client_secret = CLIENT_SECRET
client.keyjar[""] = KC_RSA

claims = {
    "name": {"essential": True},
    "nickname": None,
    "email": {"essential": True},
    "verified": {"essential": True},
    "picture": None
}

areq = client.construct_AuthorizationRequest(
    request_args={"scope":"openid", "response_type":["code"]},
    userinfo_claims={"claims":claims,
                     "preferred_locale":"en"},
    idtoken_claims={"claims":{"auth_time": None,
                              "acr":{"values":["2"]}},
                    "max_age": 86400},
    )

print areq