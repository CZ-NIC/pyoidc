#!/usr/bin/env python

import json

info = {
    "config": {
        "redirect_uri": ["http://lingon.ladok.umu.se/authz_cb"],
        "client_id": "lingon",
        "client_secret": "Hallon"
#        "contact": ["roland.hedberg@adm.umu.se"],
#        "application_type": "web",
#        "application_name": "OIC test tool"
    },
    "flows": ["basic-code-authn",
              "basic-code-idtoken"],
    "server_conf": {
        "authorization_endpoint": "http://lingon.ladok.umu.se:8088/authorization",
        "token_endpoint": "http://lingon.ladok.umu.se:8088/token"
    },
    "function_args": {
        "login_form": { "user_label": "login",
                        "password_label": "password",
                        "user": "roland",
                        "password": "Meeting"}}
}

print json.dumps(info)