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
        "conf_url": "https://connect-op.heroku.com",
        },

    "interaction": {
        #"OpenIDRequest": {"request": {"response_type": "token"}},
        "https://connect-op.heroku.com/": ["select_form",
                        {"_form_pick_": {"action": "/connect/fake"}}],
        "https://connect-op.heroku.com/authorizations/new": ["select_form",
                {"_form_pick_": {"action": "/authorizations",
                                 "class": "approve"}}]
    }
}

print json.dumps(info)