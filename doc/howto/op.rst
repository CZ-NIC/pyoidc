.. _howto_op:

How to set up an OpenID Connect Provider (OP)
=============================================

According to the OpenID Connect (OIDC) Core document
a OpenID Connect Provider is an 'OAuth 2.0 Authorization Server that is capable
of Authenticating the End-User and providing Claims to a Relying Party about
the Authentication event and the End-User'.

This goal of this document is to show how you can build a OP using the pyoidc
library.

An OP provides a couple of endpoints to which RPs can send requests.


SAML authentication
-------------------

In pyoidc an OP can have a SAML Service Provider(SP) as backend performing the authentication.

An example is implemented in [..]/oidc_example/op2

To activate SAML authentication in the OP you have to perform some configuration in config.py.

This configuration will tell the OP that SAML can be used as authentication.::

    AUTHENTICATION = {
        "SAML" : {"ACR": "SAML", "WEIGHT": 1, "URL": SERVICE_URL}
    }


Set the USERINFO setting to SAML to collect userinformation from the underlying IdP.::

    USERINFO = "SAML"

Create an empty dictionary to cache the userinformation.::

    SAML = {}


Point out where to find the configuration file for the SP.::

    SP_CONFIG="sp_conf"

When this is performed you have to create a configuration file for the SP. Copy the example file
[..]/oidc_example/op2/sp_conf.py.example and give it the same name as in the setting SP_CONFIG, but use the file ending
.py.

This is a pysaml2 SP so to understand how to configure it read the
`pysaml2 documentation <https://dirg.org.umu.se/page/pysaml2>`.

There are some extra settings for this implementation, but all is described in the example file.

Just make sure that the BASE setting is exactly the same as the OP server!