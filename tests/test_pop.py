import json

from oic.extension.pop import PoPAS
from oic.extension.pop import PoPCallBack
from oic.extension.pop import PoPClient
from oic.extension.pop import PoPRS
from oic.oauth2 import AccessTokenRequest
from oic.oauth2 import AccessTokenResponse
from oic.utils.keyio import KeyBundle
from oic.utils.keyio import KeyJar

__author__ = "roland"

JWKS = {
    "keys": [
        {
            "alg": "RS256",
            "d": "vT9bnSZ63uIdaVsmZjrbmcvrDZG-_qzVQ1KmrSSC398sLJiyaQKRPkmBRvV-MGxW1MVPeCkhnSULCRgtqHq-zQxMeCviSScHTKOu"
            "DYJfwMB5qdOE3FkuqPMsEVf6EXYaSd90-O6GOA88LBCPNR4iKxsrQ6LNkawwiJoPw7muK3TbQk9HzuznF8WDkt72CQFxd4eT6wJ9"
            "7xpaIgxZce0oRmFcLYkQ4A0pgVhF42zxJjJDIBj_ZrSl5_qZIgiE76PV4hjHt9Nv4ZveabObnNbyz9YOiWHiOLdYZGmixHuauM98"
            "NK8udMxI6IuOkRypFhJzaQZFwMroa7ZNZF-mm78VYQ",
            "dp": "wLqivLfMc0FBhGFFRTb6WWzDpVZukcgOEQGb8wW3knmNEpgch699WQ4ZY_ws1xSbvQZtbx7MaIBXpn3qT1LYZosoP5oHVTAvdg6"
            "G8I7zgWyqj-nG4evciuoeAa1Ff52h4-J1moZ6FF2GelLdjXHoCbjIBjz_VljelSqOk5Sh5HU",
            "dq": "KXIUYNfDxwxv3A_w1t9Ohm92gOs-UJdI3_IVpe4FauCDrJ4mqgsnTisA15KY-9fCEvKfqG571WK6EKpBcxaRrqSU0ekpBvgJx8o"
            "3MGlqXWj-Lw0co8N9_-fo1rYx_8g-wCRrm5zeA5pYJdwdhOBnmKOqw_GsXJEcYeUod1xkcfU",
            "e": "AQAB",
            "kid": "abc",
            "kty": "RSA",
            "n": "wl0DPln-EFLqr_Ftn6A87wEQAUVbpZsUTN2OCEsJV0nhlvmX3GUzyZx5UXdlM3Dz68PfUWCgfx67Il6sURqWVCnjnU-_gr3GeDyz"
            "edj-lZejnBx-lEy_3j6B98SbcDfkJF6saXnPd7_kgilJT1_g-EVI9ifFB1cxZXHCd2WBeRABSCprAlCglF-YmnUeeDs5K32z2ckV"
            "jadF9BG27CO5UfNq0K8jI9Yj_coOhM9dRNrQ9UVZNdQVG-bAIDhB2y2o3ASGwqchHouIxv5YZNGS0SMJL5t0edh483q1tSWPqBw-"
            "ZeryLztOedBBzSuJk7QDmL1B6B7KKUIrlUYJmVsYzw",
            "p": "6MEg5Di_IFiPGKvMFRjyx2t7YAOQ4KfdIkU_Khny1t1eCG5O07omPe_jLU8I5fPaD5F5HhWExLNureHD4K6LB18JPE3VE8chQROi"
            "RSNPZo1-faUvHu-Dy0pr7I-TS8pl_P3vop1KelIbGwXhzPIRKQMqCEKi3tLJt4R_MQ18Dx0",
            "q": "1cZVPpUbf4p5n4cMv_kERCPh3cieMs4aVojgh3feAiJiLwWWL9Pc43oJUekK44aWMnbs68Y4kqXtc52PMtBDzVp0Gjt0lCY3M7MY"
            "RVI4JhtknqvQynMKQ2nKs3VldvVfY2SxyUmnRyEolQUGRA7rRMUyPb4AXhSR7oroRrJD59s",
            "qi": "50PhyaqbLSczhipWiYy149sLsGlx9cX0tnGMswy1JLam7nBvH4-MWB2oGwD2hmG-YN66q-xXBS9CVDLZZrj1sonRTQPtWE-zuZq"
            "ds6_NVlk2Ge4_IAA3TZ9tvIfM5FZVTOQsExu3_LX8FGCspWC1R-zDqT45Y9bpaCwxekluO7Q",
        }
    ]
}


def init_keyjar():
    # Keys that are kept by the AS
    kb = KeyBundle()
    kb.do_keys(JWKS["keys"])
    keyjar = KeyJar()
    keyjar.add_kb("", kb)
    return keyjar


def test_flow():
    cli = PoPClient()

    # Client creates access token request
    atreq = AccessTokenRequest(
        grant_type="authorization_code",
        code="SplxlOBeZQQYbYS6WxSbIA",
        redirect_uri="https://client.example.com/cb",
    )

    # adds key information, also connects the new key to the state value used
    atreq = cli.update(atreq, "state")

    assert "key" in atreq

    pas = PoPAS("https://example.com/as")
    pas.keyjar = init_keyjar()
    # Key is in the JSON string representation
    finger_print = pas.store_key(json.loads(atreq["key"]))
    access_token = pas.create_access_token(finger_print)
    # The AS constructs the access token response
    atrsp = AccessTokenResponse(
        access_token=access_token, token_type="bearer", state="state"
    )

    # The client receives the response and connects the key to the access token
    cli.handle_access_token_response(atrsp)

    assert access_token in cli.token2key
    assert cli.token2key[access_token] == cli.state2key["state"]

    # Time for the client to access the Resource Server
    url = "https://example.com/rs?foo=bar&format=json"
    headers = {"Content-type": "application/www-form-encoded"}
    body = "access_token={}".format(access_token)

    # creates the POP token using signed HTTP request
    cb = PoPCallBack(cli.token2key[atrsp["access_token"]], cli.alg)
    kwargs = cb("POST", url, headers=headers, body=body)
    assert kwargs["Authorization"].startswith("pop ")
    pop_token = kwargs["Authorization"][4:]

    assert len(pop_token.split(".")) == 3  # simple JWS check

    # now to the RS
    rs = PoPRS()

    # The AS gets a token introspection request
    # verifies the correctness of the access token
    # and if correct constructs the token introspection response
    tir = pas.token_introspection(atrsp["access_token"])

    # The RS binds the received key to the access token
    rs.store_key(access_token, tir)

    # The RS verifies the correctness of the POP token
    res = rs.eval_signed_http_request(
        pop_token, access_token, "POST", url, headers, body
    )

    # YEY :-)
    assert res
