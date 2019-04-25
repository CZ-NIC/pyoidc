Features Cookbook
=================

Requesting Claims
-----------------

Specific claims can be requested using the Authorization request parameter

::

    from oic.oic.message import ClaimsRequest, Claims

    claims_request = ClaimsRequest(
        id_token=Claims(
          email={"essential": None},
          phone_number=None
        ),
        userinfo=Claims(
          given_name={"essential": True},
          family_name={"essential": True}, nickname=None
        )
    )

    request_args = {
        "redirect_uri": "https://example.com/rp/authz_cb",
        "scope": "openid",
        "response_type": "code",
        "claims": claims_request
    }

    # client is oic.oic.Client
    client.construct_AuthorizationRequest(request_args=request_args)

Client Assertions
-----------------

Client assertions can be used for authentication at the IdP token endpoint in
the OIDC authorization code flow, rather than a client secret. As a challenging
example, we'll use authenticating with a Microsoft Azure AD IdP, as this
additionally involves creating a custom client assertion.

Support for client assertions is provided in the ``do_access_token_request``
method of the ``oic.oic.Client`` class, using keyword arguments to the method:

::

            kwargs = dict(algorithm="RS256", authn_endpoint='token',
                          authn_method="private_key_jwt")

The ``authn_method`` parameter initiates authentication with a client assertion.
The ``algorithm`` and ``authn_endpoint`` parameters are needed by the
``oic.utils.authn.client.PrivateKeyJWT`` class to properly construct the
assertion. Also required is a signing key in the client's keyjar. A way to
accomplish this is illustrated by the ``TestPrivateKeyJWT`` class in
*tests/test_client.py*

::

    _key = rsa_load(os.path.join(BASE_PATH, "data/keys/rsa.key"))
    kc_rsa = KeyBundle([{"key": _key, "kty": "RSA", "use": "ver"},
                        {"key": _key, "kty": "RSA", "use": "sig"}])
    client.keyjar[""] = kc_rsa

The payload of the resulting JWT can be understood by examining the
``assertion_jwt`` function in ``oic.utils.authn.client``, shown below. Only the
``alg`` header claim is included when constructing and signing the JWT.

::

    def assertion_jwt(cli, keys, audience, algorithm, lifetime=600):
        _now = utc_time_sans_frac()

        at = AuthnToken(
            iss=cli.client_id,
            sub=cli.client_id,
            aud=audience,
            jti=rndstr(32),
            exp=_now + lifetime,
            iat=_now,
        )
        logger.debug("AuthnToken: {}".format(at.to_dict()))
        return at.to_jwt(key=keys, algorithm=algorithm)


So that's basically all you need to know if your IdP can use pyoidc's client
assertions.  If you're using out-of-band client registration, you would not
include a ``client_secret`` when constructing the ``RegistrationResponse``,
as shown in pyoidc's relying party documentation.

To use client assertions with Microsoft AzureAD, Microsoft provides this
`guidance
<https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-certificate-credentials>`_.
The differences from the client assertion pyoidc generates are:

* the ``typ`` and ``x5t`` header claims must be included.
* the payload claim ``iat`` is instead ``nbf``

pyoidc nicely provides a ``client_assertion`` keyword argument to
``do_access_token_request``. This argument's value is substituted for the
client assertion pyoidc would otherwise generate. Note that the other keyword
arguments identified above are still required:

::

            kwargs = dict(algorithm="RS256", authn_endpoint='token',
                          authn_method="private_key_jwt",
                          client_assertion=custom_assertion)


Generating a custom client assertion for Microsoft is illustrated by the
function below.

::

    import json
    from jwkest.jws import JWSig, SIGNER_ALGS
    from jwkest.jwt import b64encode_item
    from oic import rndstr
    from oic.utils.time_util import utc_time_sans_frac


    def make_assertion(client_id, token_endpoint, fingerprint, key, lifetime=60):
        """Creates a JWT for IdP token endpoint auth per Microsoft specs"""
        _alg = "RS256"
        headers = {'alg': _alg, 'typ': "JWT", 'x5t': fingerprint}
        _now = utc_time_sans_frac()
        payload = dict(
            iss=client_id,
            sub=client_id,
            aud=token_endpoint,
            jti=rndstr(32),
            nbf=_now,
            exp=_now + lifetime
        )
        jwt = JWSig(**headers)
        _signer = SIGNER_ALGS[_alg]
        _input = jwt.pack(parts=[json.dumps(payload)])
        sig = _signer.sign(_input.encode("utf-8"),
                           key.get_key(alg=_alg, private=True))
        return ".".join([_input, b64encode_item(sig).decode("utf-8")])


The ``client_id`` and ``token_endpoint`` arguments to this function should be
straightforward. ``key`` is a ``jwkest.jwk.RSAKey``. To create one from a
certificate private key file at ``path``:

::

    from jwkest.jwk import rsa_load, RSAKey
    signing_key = RSAKey(key=rsa_load(path), kty="RSA", use='sig')


``fingerprint`` is a Base64 encoded SHA-1 fingerprint of the X.509 certificate
corresponding to the private key. Microsoft Azure AD displays this fingerprint
as a hexadecimal string when the certificate is registered during IdP
configuration. You can easily convert this string by:

::

    from base64 import b64encode
    from binascii import unhexlify
    fingerprint = b64encode(unhexlify(hex_string))


If you don't have the hexadecimal fingerprint, but you have the X.509
certificate file, you can generate the fingerprint, as shown below using the
``cryptography`` package:

::

    from base64 import b64encode
    from binascii import hexlify
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes
    with open("cert.pem", "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read(), default_backend())
    fingerprint = cert.fingerprint(hashes.SHA1())
    hexadecimal_fingerprint = hexlify(fingerprint).upper()
    base64_fingerprint = b64encode(fingerprint)


Putting it together

::

    def make_token_request(client, state, code, redirect_uri, scopes, assertion):
        """Retrieves tokens by redeeming an authorization code"""
        request_args = dict(
            client_id=client.client_id,
            code=code,
            redirect_uri=redirect_uri
        )
        kwargs = dict(
            algorithm="RS256",
            authn_endpoint='token',
            authn_method="private_key_jwt",
            client_assertion=assertion,
            request_args=request_args,
            scope=scopes,
            state=state
        )
        return client.do_access_token_request(**kwargs)
