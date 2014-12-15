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


Authentication
--------------
In general any authentication method can be used as long as the class implementing
it includes the following interface:

  * Inherit from :py:class:`oic.utils.authn.user.UserAuthnMethod`
  * Override :py:meth:`oic.utils.authn.user.UserAuthnMethod.__call__`: should
    return a HTTP response containing either the login page
    (see the simple username/password login authentication
    class :py:class:`oic.utils.authn.user.UsernamePasswordMako` ) or a redirect
    to a login page hosted elsewhere (see the SAML
    authentication class :py:class:`oic.utils.authn.user.SAMLAuthnMethod`).
  * Override :py:meth:`oic.utils.authn.user.UserAuthnMethod.verify`: should verify
    the authentication parameters from the associated login
    page (served by :py:meth:`oic.utils.authn.user.UserAuthMethod.__call__`).
    Must return a tuple `(a, b)` where `a` is a HTTP Response (most likely 200 OK
    or a redirect to collect more information necessary to authenticate) and `b` is a boolean value indicating
    whether the authentication is complete.

    The input to :py:meth:`verify` will contain any cookies received. If the
    authentication is part of a multi auth chain, see below, the cookie returned
    by :py:meth:`oic.utils.authn.user.UserAuthnMethod.get_multi_auth_cookie`
    should be used to retrieve the original query from the RP.

To properly register the implemented verify method as the callback function at
an endpoint of the OP,
use :py:meth:`oic.utils.authn.authn_context.make_auth_verify`
(which wraps the specified callback to properly parse the request
before it is passed along and handles the case of multi auth chains, see below).


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


SAML attribute authority
------------------------
In order to use attribute authority you need to set the variable USERINFO = "AA" and use SAML authentication
in the file named config.py

In the file sp_conf.py set AA_NAMEID_ATTRIBUTE to an appropriate key in the userinformation returned from a SAML
authentication response. If you like to use the name id from the SAML response, set AA_NAMEID_ATTRIBUTE to None. The
name id or the value for the defined attribute must match the name id settings on the attribute authority server.

AA_ENTITY_ID can be set to None if you like to use the same IdP as attribute authority, or you can define a new
attribute authority by defining its entity id string.

AA_NAMEID_FORMAT must be the format of the name id. You can use the defines formats in saml2.saml that you find in
pysaml2.


Multi auth
----------
All modules currently included in pyoidc can be combined to form multi authentication chains, where two or more
authentication methods must be completed before the user is authenticated.

To setup a multi authentication chain the following steps must be completed:
  #) Specify the multi authentication in the OP configuration, see e.g.

     `<pyoidc path>/oidc_example/op2/config_student.py.example`

     with the dictionary `AUTHENTICATION` containing
     the key "SamlPass" for a multi auth chain containing both SAML login combined with username/password login. Give it
     an Authentication Context Class Reference (ACR) to be used by the RP.

  #) Instantiate the classes that are part of the chain. If the OP supplies multiple authentication methods, the objects
     should be treated as singletons -- only instantiate one object for each authentication method.

     Tip: to make it possible to include SAML in multiple authentication methods (e.g., both multi auth and just single
     auth), the endpoints in the backend SP must be given indices to separate between multi auth chain(s) and
     single auth (see e.g. `<pyoidc path>/oidc_example/op2/sp_conf_student.py.example` and the
     `pysaml2 documentation <https://dirg.org.umu.se/static/pysaml2/howto/config.html#endpoints>`_).
     Use `AuthnIndexedEndpointWrapper` to apply the indices correctly in the OP.

  #) Create the chain and setup all endpoints at the OP using `oic.utils.authn.multi_auth.setup_multi_auth`.
     The input should be a list `[(m1, e1), (m2, e2), ...]`, specifying the ordered chain of authentication, where
     each tuple contains the authentication method instance and the callback endpoint at the OP (specified in the form of
     a regular expression matching the path in the HTTP request) the login page returns to. The object returned from
     `setup_multi_auth` must be added to the `AuthnBroker` instance.

  #) The RP can now ask for the multi auth chain using the ACR value specified in the OP config.

