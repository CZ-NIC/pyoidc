.. _howto_rp:

Python Cookbook for OpenID Connect Public Client
================================================

According to the OpenID Connect (OIDC) Core document
a Relying Party is an 'OAuth 2.0 Client application requiring End-User
Authentication and Claims from an OpenID Provider'.

This goal of this document is to show how you can build a RP using the pyoidc
library.

There are a couple of choices you have to make, but we'll take that as
we walk through the message flow.

Before I start you should now that the basic code flow in OpenID Connect
consists of a sequence of request-responses, namely these:

* Issuer discovery using WebFinger
* Provider Info discovery
* Client registration
* Authorization Request
* Access Token Request
* Userinfo Request


In the example below I will go through all the steps and I will use the basic
Client class because it will provide interfaces to all of them.
So lets start with instantiating a client::

    from oic.oic import Client
    import CLIENT_AUTHN_METHOD

    c = Client(client_authn_method=CLIENT_AUTHN_METHOD)

The first choices is really not yours it's the OpenID Connect Provider (OP)
that has to decide on whether it supports dynamic provider information
gathering and/or dynamic client registration.

If the OP doesn't support client registration then you have to static register
your client with the provider. Typically this is accomplished using a web
page provided by the organization that runs the OP. Can't help
you with this since each provider does it differently. What you eventually
must get from the service provide is a client id and a client secret.

If the service provider does not support dynamic OP information lookup, then
the necessary information will probably appear on some web page somewhere.
Again look to the service provider. Going through the dynamic process below
you will learn what information to look for.

Issuer discovery
----------------

OIDC uses webfinger (http://tools.ietf.org/html/rfc7033)to do the OP discovery.
In very general terms this means
that the user that accesses the RP provides an identifier. There are a number
of different syntaxes that this identifier can adhere to. The most common
probably the e-mail address syntax. It's something the looks like an e-mail
address (local@domain) but not necessarily is one.

At this point in time let us assume that you will instantiated a OIDC RP.

.. Note::Oh, by the way I will probably alternate between talking about the RP
    and the client, don't get caught up on that, they are the same thing.

As stated above depending on depending on the OP and the return_type you
will use some of these steps may be left out or replaced with an out-of-band
process.

Using pyoidc this is how you would do it::

    uid = "foo@example.com"
    issuer = client.discover(uid)

The discover method will use webfinger to find the OIDC OP given the user
identifier provided. If the user identifier follows another syntax/scheme
the same method can still be used, you just have to preface the 'uid'
value with the scheme used.
The returned issuer must according to the standard be a https url, but some
implementers have decided differently on this, so you may get a http url.

Provider Info discovery
-----------------------

When you have the provider info URL you want to get information about the OP, so
you query for that::

    provider_info = client.provider_config(issuer)

A description of the whole set of metadata can be found here:
http://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata

.. Note::One parameter of the provider info is the issuer parameter this
     is supposed to be *exactly* the same as the URL you used to fetch the
     information. Now, this isn't valid for some providers. You can tell the
     client to not care about this by setting
     client.allow["issuer_mismatch"] = True

The resulting provider_info is a dictionary, hence you can easily find the
necessary information::

    >> provider_info["issuer"]
    'https://example.com/op'
    >> provider_info["authorization_endpoint"]
    'https://example.com/op/authz_endp'

The provider info is also automatically stored in the client instance.::

    >> client.provider_info["scopes_supported"]
    ['openid', 'profile', 'email']


For the simple Client it is expected it will only talk to one OP during its
lifetime.

Now, you know all about the OP. The next step would be to register the
client with the OP.


Client registration
-------------------

To do that you need to know the 'registration_endpoint'.
And you have to decide on a couple of things about the RP.

Things like:

* redirect_uris
    REQUIRED. Array of Redirection URI values used by the Client.
* response_types
    OPTIONAL. JSON array containing a list of the OAuth 2.0 response_type
    values that the Client is declaring that it will restrict itself to using.
    If omitted, the default is that the Client will use only the code Response
    Type.
* contacts
    OPTIONAL. Array of e-mail addresses of people responsible for this Client.

The whole list of possible parameters can be found here:
http://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata

The only absolutely required information is the **redirect_uris**

So, registering a client could then be accomplished doing::

    client.redirect_uris = ['https://example.com/rp/authz_cb']
    registration_response = client.register(provider_info["registration_endpoint"])

You have two choices here, you can either assign the parameters with value to
the client instance as in the example above or you can provide them as an
argument to the method::

    args = {
        "redirect_uris": ['https://example.com/rp/authz_cb'],
        "contacts": ["foo@example.com"]
        }

    registration_response = client.register(
        provider_info["registration_endpoint"], **args)

or a combination of the two.

Provided the registration went flawlessly you will get the registration response
(an instance of a RegistrationResponse) as a result. But at the same time
automatically the response will be stored in the client instance
(client_info parameter).

.. Note:: The basic Client class is expected to only talk to one OP. If your service
    needs to talk to several OPs that are a couple of patterns you could use.
    One is to instantiate one RP per OP another to keep the OP specific information
    like provider information and client registration information outside the
    RP and then setup the RP every time you want to talk to a new OP.

Now back to the static variant. If you can not do the Provider discovery
dynamically you have to get the information out-of-band and then configure
the RP accordingly. And this is how you would do that::

    from oic.oic.message import ProviderConfigurationResponse

    op_info = ProviderConfigurationResponse(
        version="1.0", issuer="https://example.org/OP/1",
        authorization_endpoint="https://example.org/OP/1/authz",
        token_endpoint="https://example.org/OP/1/token",
        ... and so on )

    # or
    # op_info = ProviderConfigurationResponse(**info)
    # if you have the provider info in the form of a dictionary

    client.provider_info = op_info

Likewise if the client registration has been done out-of-band::

    from oic.oic.message import RegistrationResponse

    info = {"client_id": "1234567890", "client_secret": "abcdefghijklmnop"}
    client_reg = RegistrationResponse(**info)

    client.store_registration_info(client_reg)


Authorization query
-------------------

Once the client knows about the OP and the OP knows about the client we can
start doing business, that is get information about users.

The request you then want to make is the authentication request.

.. Note:: This might be slightly confusing. In OAuth2 (RFC 6749) the initial
    request is called authorization request and you do it at the authorization
    endpoint. In OIDC the request is renamed to authentication request.
    For historical reasons I've kept the name authorization request for the
    method that handles that request.

Before doing the request you have to decided on a couple of things:

* which response type you want to use.
    You can read up on response types in the OAuth2 RFC.
* the scope. The list of scopes must contain 'openid'. There is a list of
    extra scopes that OIDC defines which can be found in the specification.
* whether to use HTTP 'GET' or 'POST'. Either one is allowed. 'GET' is default.

Authorization Code Flow
^^^^^^^^^^^^^^^^^^^^^^^

From the list redirect_uris you have to pick one to use for this request.
Given you have all that, you now can send the request::

    import hashlib
    import hmac
    from oic.oauth2 import rndstr
    from oic.utils.http_util import Redirect

    session["state"] = rndstr()
    session["nonce"] = rndstr()
    args = {
        "client_id": client.client_id,
        "response_type": "code",
        "scope": ["openid"],
        "nonce": session["nonce"],
        "redirect_uri": client.redirect_uris[0],
        "state": session["state"]
    }

    auth_req = self.client.construct_AuthorizationRequest(request_args=request_args)
    login_url = client.authorization_endpoint + "?" + auth_req.to_urlencoded()

    return Redirect(login_url)

The arguments *state* are use to keep track on responses to
outstanding requests (state).

*nonce* is a string value used to associate a Client session with an ID Token,
and to mitigate replay attacks.

Since you will need both these arguments later in the process you probably
want to store them in a session object (assumed to look like a dictionary).
Also even if you initiate one Client instance per OP you probably won't do it
per user so you have to keep the state and nonce variables that belongs to
an user together and separate from other users.

Eventually a response is sent to the URL given as the redirect_uri.

You can parse this response by doing::

    from oic.oic.message import AuthorizationResponse

    # If you're in a WSGI environment
    response = environ["QUERY_STRING"]

    aresp = client.parse_response(AuthorizationResponse, info=response,
                                  sformat="urlencoded")

    code = aresp["code"]
    assert aresp["state"] == session["state"]

*aresp* is an instance of an AuthorizationResponse or an ErrorResponse.
The later if an error was return from the OP.
Among other things you should get back in the authorization response is
the same state value as you used
when sending the request. If you used the response_type='code' then you
should also receive a grant code which you then can use to get the access
token::

    args = {
        "code": aresp["code"],
        "redirect_uri": client.redirect_uris[0],
        "client_id": client.client_id,
        "client_secret": client.client_secret
    }

    resp = client.do_access_token_request(scope="openid",
                                          state=aresp["state"],
                                          request_args=args,
                                          authn_method="client_secret_post"
                                          )


'scope' has to be the same as in the authorization request.

If you don't specify a specific client authentication method, then
*client_secret_basic* is used.

You have to provide client_id and client_secret as arguments, how they are used
depends on the authentication method used.

The resp you get back is an instance of an AccessTokenResponse or again possibly
an ErrorResponse instance.

If it's an AccessTokenResponse the information in the response will be stored
in the client instance with *state* as the key for future use.
One if the items in the response will be the ID Token which contains information
about the authentication.
One parameter (or claim as its also called) is the nonce you provide with
the authorization request.

And then the final request, the user info request::

    userinfo = client.do_user_info_request(state=aresp["state"])

Using the *state* the client library will find the appropriate access token
and based on the token type chose the authentication method.

*userinfo* in an instance of OpenIDSchema or ErrorResponse. Given that you have
used openid as the scope, *userinfo* will not contain a lot of information.
actually only the *sub* parameter.

Implicit Flow
^^^^^^^^^^^^^

When using the Implicit Flow, all tokens are returned from the Authorization
Endpoint; the Token Endpoint is not used.

So::

    from oic.oauth2 import rndstr
    from oic.utils.http_util import Redirect

    session["state"] = rndstr()
    session["nonce"] = rndstr()
    args = {
        "client_id": client.client_id,
        "response_type": ["id_token", "token"],
        "scope": ["openid"],
        "nonce": session["nonce"],
        "redirect_uri": client.redirect_uris[0]
    }


    auth_req = self.client.construct_AuthorizationRequest(state=session["state"],
                                                          request_args=args)
    login_url = client.authorization_endpoint + "?" + auth_req.to_urlencoded()

    return Redirect(login_url)


As for the Authorization Code Flow the authentication part will begin
with a redirect to a login page and end with a redirect back to the
registered redirect_uri.

Since the response will be return as a fragment you need some special code
to catch that information. How you do that depends on your setup.

Again the response can be parse by doing::

    from oic.oic.message import AuthorizationResponse

    aresp = client.parse_response(AuthorizationResponse, info=response,
                                  sformat="urlencoded")

    assert aresp["state"] == client.state

Now *aresp* will not contain any code reference but instead an access token and
an ID token. The access token can be used as described above to fetch user
information.

Using Implicit Flow instead of Authorization Code Flow will save you a
round trip but at the same time you will get an access token and no
refresh_token. So in order to get a new access token you have to perform another
authorization request.