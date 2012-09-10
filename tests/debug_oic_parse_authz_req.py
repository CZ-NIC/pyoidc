from oic.oic.provider import Provider
from oic.utils.keystore import rsa_load
from oic.utils.sdb import SessionDB

__author__ = 'rohe0002'


URLMAP = {"client1": ["https://example.com/authz"]}
rsapub = rsa_load("/Users/rohe0002/code/oictest/test/oic/keys/pyoidc")

CLIENT_ID = "kwQVw2MWwSYr"
CLIENT_SECRET = ""

KEYS = [
    [rsapub, "rsa", "sig", "kwQVw2MWwSYr"],
    [rsapub, "rsa", "ver", "kwQVw2MWwSYr"]
]

CDB = {
    "kwQVw2MWwSYr": {
        "client_secret": "drickyoughurt",
        "redirect_uris": ["https://lingon.catalogix.se/authz_cb"]
    },
}

def verify_client(environ, areq, cdb):
    identity = areq.client_id
    secret = areq.client_secret
    if identity:
        if identity == CLIENT_ID and secret == CLIENT_SECRET:
            return True
        else:
            return False

    return False

FUNCTIONS = {
#    "authenticate": do_authentication,
#    "authorize": do_authorization,
#    "verify_user": verify_username_and_password,
    "verify_client": verify_client,
#    "userinfo": user_info,
}

# ===========================================================================

_srv = Provider("pyoicserv", SessionDB(), CDB, FUNCTIONS, userdb={},
                urlmap=URLMAP, jwt_keys=KEYS)

authz_req = "nonce=dummy_nonce&request=eyJhbGciOiJSUzI1NiJ9.eyJpZF90b2tlbiI6IHsibWF4X2FnZSI6IDg2NDAwfSwgInN0YXRlIjogIlNUQVRFMCIsICJyZWRpcmVjdF91cmkiOiAiaHR0cHM6Ly9saW5nb24uY2F0YWxvZ2l4LnNlL2F1dGh6X2NiIiwgInVzZXJpbmZvIjogeyJjbGFpbXMiOiB7Im5hbWUiOiBudWxsfX0sICJjbGllbnRfaWQiOiAia3dRVncyTVd3U1lyIiwgInNjb3BlIjogIm9wZW5pZCIsICJyZXNwb25zZV90eXBlIjogImNvZGUifQ.ag8efnGBk__ueuruHM8_xa-yBR3rk6A-6jxCN1pMR8kccypiuwQTMAYsmnu9NhkLWVYlxVrLnoXLnK5AOCF8nC_zDzil8lUje48SAexsXYfLXaGxLzluzuLoPEaTus_3W6-XOSDeRlzqxSY6wggjjHhmSm7LdDB0JaqnPvMMkVg&state=STATE0&redirect_uri=https%3A%2F%2Flingon.catalogix.se%2Fauthz_cb&response_type=code&client_id=kwQVw2MWwSYr&scope=openid"

v_keys = _srv.keystore.get_keys("ver", owner=None)
areq = _srv.server.parse_authorization_request(query=authz_req, keys=v_keys)
print areq