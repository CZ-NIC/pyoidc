#!/usr/bin/env python

import json

info = {
    "config": {
        "redirect_uri": ["https://smultron.catalogix.se/authz_cb"],
        "contact": ["roland.hedberg@adm.umu.se"],
        "application_type": "web",
        "application_name": "OIC test tool"
    },
    "provider_conf_url": "https://connect.openid4.us",
    "flows": ["basic-code-authn",
              "basic-code-idtoken",
              "basic-code-idtoken-userdata"],
    "register":True,
#    "function_args": {}
}

print json.dumps(info)