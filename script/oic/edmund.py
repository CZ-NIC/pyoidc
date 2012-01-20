#!/usr/bin/env python

import json

info = {
    "client": {
        "redirect_uri": ["https://smultron.catalogix.se/authz_cb"],
        "contact": ["roland.hedberg@adm.umu.se"],
        "application_type": "web",
        "application_name": "OIC test tool",
        "register":True,
    },
    "provider": {
        "version": { "oauth": "2.0", "openid": "3.0"},
        "conf_url": "https://connect.openid4.us",
    },

    #"basic-code-authn"
    #"basic-code-idtoken",
    #"basic-code-idtoken-userdata"
    #"basic-code-idtoken-check_id"
    "interaction": {
        #"OpenIDRequest": {"request": {"response_type": "token"}},
        "https://connect.openid4.us/abop/op.php/auth": ["login_form", None],
        "https://connect.openid4.us/abop/op.php/login": ["select_form",
                        {"_form_pick_": ("control", "persona", "Default")}]
    }
}

print json.dumps(info)