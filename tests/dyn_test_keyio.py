from oic.oic.message import ProviderConfigurationResponse
from oic.utils.keyio import KeyJar

__author__ = 'rolandh'

PROVIDER_INFO = {
    "registration_endpoint": "https://connect-op.heroku.com/connect/client",
    "userinfo_endpoint": "https://connect-op.heroku.com/user_info",
    "token_endpoint_auth_types_supported": "client_secret_basic",
    "request_object_signing_alg_values_supported": "RS256",
    "user_id_types_supported": ["public", "pairwise"],
    "scopes_supported": ["openid", "profile", "email", "address", "phone"],
    "token_endpoint": "https://connect-op.heroku.com/access_tokens",
    "id_token_algs_supported": ["RS256"], "version": "3.0",
    "jwk_url": "https://connect-op.heroku.com/jwk.json",
    "response_types_supported": ["code", "token", "id_token", "code token",
                                 "code id_token", "id_token token",
                                 "code id_token token"],
    "authorization_endpoint": "https://connect-op.heroku.com/authorizations/new",
    "x509_url": "https://connect-op.heroku.com/cert.pem",
    "issuer": "https://connect-op.heroku.com"}

def test_provider():
    ks = KeyJar()
    pcr = ProviderConfigurationResponse().from_dict(PROVIDER_INFO)
    ks.load_keys(pcr, "https://connect-op.heroku.com")

    assert ks["https://connect-op.heroku.com"]
