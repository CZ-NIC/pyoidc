from oic.oic import ProviderConfigurationResponse
from oic.utils.keyio import KeyJar
from requests import request

__author__ = 'rohe0002'

def http_request(url, **kwargs):
    return request("GET", url, **kwargs)

info = {"registration_endpoint": "https://openidconnect.info/connect/register",
 "userinfo_endpoint": "https://openidconnect.info/connect/userinfo",
 "token_endpoint_auth_types_supported": ["client_secret_basic", "client_secret_post", "client_secret_jwt", "private_key_jwt"],
 "jwk_url": "https://openidconnect.info/jwk/jwk.json",
 "userinfo_algs_supported": ["HS256", "HS384", "HS512", "RS256", "RS384", "RS512"],
 "user_id_types_supported": ["pairwise", "public"],
 "scopes_supported": ["openid", "profile", "email", "address", "phone"],
 "token_endpoint": "https://openidconnect.info/connect/token",
 "id_token_algs_supported": ["HS256", "HS384", "HS512", "RS256", "RS384", "RS512"],
 "version": "3.0",
 "token_endpoint_auth_algs_supported": ["RS256", "RS384", "RS512"],
 "request_object_algs_supported": ["HS256", "HS384", "HS512", "RS256", "RS384", "RS512"],
 "response_types_supported": ["code", "token", "id_token", "id_token token", "code token", "code id_token", "code id_token token"],
 "authorization_endpoint": "https://openidconnect.info/connect/authorize",
 "acrs_supported": ["1"],
 "check_id_endpoint": "https://openidconnect.info/connect/check_session",
 "x509_url": "https://openidconnect.info/x509/cert.pem",
 "issuer": "https://openidconnect.info"}

pi = ProviderConfigurationResponse(**info)

kj = KeyJar()

kj.load_keys(pi, pi["issuer"])

keys = kj.get("ver", "rsa", "https://openidconnect.info")

print keys