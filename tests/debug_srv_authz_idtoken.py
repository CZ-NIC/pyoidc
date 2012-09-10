from oic.oic.message import AuthorizationRequest, IdToken
from oic.utils.sdb import SessionDB
from oic.utils.time_util import epoch_in_a_while

from pinit import provider_init

__author__ = 'rohe0002'

provider = provider_init

bib = {"scope": ["openid"],
       "state": "id-6da9ca0cc23959f5f33e8becd9b08cae",
       "redirect_uri": "http://localhost:8087/authz",
       "response_type": ["code", "id_token"],
       "client_id": "a1b2c3",
       "nonce": "Nonce",
       "prompt": ["none"]}

req = AuthorizationRequest(**bib)
AREQ = AuthorizationRequest(response_type="code",
                            client_id="client1",
                            redirect_uri="http://example.com/authz",
                            scope=["openid"], state="state000")

sdb = SessionDB()
sid = sdb.create_authz_session("username", AREQ)

_info = sdb[sid]
_user_info = IdToken(iss="https://foo.example.om", user_id="foo",
                     aud=bib["client_id"], exp=epoch_in_a_while(minutes=10),
                     acr="2", nonce=bib["nonce"])

print _user_info.to_dict()
idt = provider.id_token_as_signed_jwt(_info, access_token="access_token",
                                      user_info=_user_info)

