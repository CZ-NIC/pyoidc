#!/usr/bin/env python

import json
import rp

info = {
    "config": {
        "redirect_uri": ["https://smultron.catalogix.se/authz_cb"],
        "password":"hemligt",
        "client_id": "client0",
        "contact": ["roland.hedberg@adm.umu.se"],
        "application_type": "web",
        "application_name": "OIC test tool"
    },
    "provider_conf_url": "https://connect-op.heroku.com",
    "phases": {
        "login": (["AUTHZREQ_CODE", "FORM_LOGIN_DEFAULT", "APPROVE_FORM"],
                    "AUTHZRESP"),
        "access-token-request":("ACCESS_TOKEN_REQUEST_CLI_SECRET",
                                "ACCESS_TOKEN_RESPONSE"),
        "user-info-request":("USER_INFO_REQUEST", "USER_INFO_RESPONSE"),
        "check-id-request":("CHECK_ID_REQUEST", "CHECK_ID_RESPONSE"),
    },
    "flows": [
        #["login", "access-token-request", "user-info-request"]
        ["login", "access-token-request", "check-id-request"]
    ],
    "register":True
}

rp.make_sequence(info)

print json.dumps(info)