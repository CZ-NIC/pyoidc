#!/usr/bin/env python

import json

info = {
    "config": {
        "redirect_uri": ["http://lingon.ladok.umu.se:8090/"],
        "client_id": "c94feca8a38886b9a105@coip-test.sunet.se",
        "client_secret": "YOOkcwJXqJJVZvFF8NuCLloTNIeypfSR0MnADlfT"
    },
    "flows": ["basic-code-authn",
              "basic-code-idtoken-get"],
    "server_conf": {
        "authorization_endpoint":
            "https://https://coip-test.sunet.se/oauth2/authorization",
        "token_endpoint": "https://coip-test.sunet.se/oauth2/token"
    },
#    "function_args": {
#        "login_form": { "user_label": "email",
#                        "password_label": "pass",
#                        "user": "roland.hedberg@adm.umu.se",
#                        "password": "888cartalk"}}
}

SCOPE = ["memberships", "opensocial"]
print json.dumps(info)

