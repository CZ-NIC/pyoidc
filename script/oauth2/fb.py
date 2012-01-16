#!/usr/bin/env python

import json

info = {
    "config": {
        "redirect_uri": ["http://lingon.ladok.umu.se:8090/"],
        "client_id": "222438001106835",
        "client_secret": "7ab31def49ea8b80ab9acdbc991a236b"
    },
    "flows": ["facebook-idtoken-get"],
    "server_conf": {
        "authorization_endpoint":
            "https://www.facebook.com/dialog/oauth",
        "token_endpoint": "https://graph.facebook.com/oauth/access_token"
    },
    "function_args": {
        "login_form": { "user_label": "email",
                        "password_label": "pass",
                        "user": "",
                        "password": ""}}
}

print json.dumps(info)

