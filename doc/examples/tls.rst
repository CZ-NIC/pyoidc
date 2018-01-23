TLS configuration
=================

Both the OP and the RP side make HTTPS based requests
to various endpoints like webfinger, token endpoints and so on.

So this is used by various classes, a non exhaustive list:

    *  :py:class:`oic.oauth2.Client`
    *  :py:class:`oic.oic.Client`
    *  :py:class:`oic.oic.Provider`
    *  :py:class:`oic.oauth2.Provider`
    *  :py:class:`oic.utils.keyio.KeyJar`
    *  :py:class:`oic.utils.keyio.KeyBundle`

Server certificate verification
-------------------------------

If you want to use the library you should have a working
TLS certificate verification setup, as OAuth2/OIDC depends
on TLS for some of its security properties.

If you do nothing and just use all the default settings, certificates
will be verified using the global settings as documented
for the python requests library.

.. seealso::

    Requests SSL Cert Verification
        http://docs.python-requests.org/en/master/user/advanced/#ssl-cert-verification

You can customize the setting with the `verify_ssl` option to various classes.
The semantics follow the definition of the `verify` option for requests, see above.

In short, set `verify_ssl` to:

``True``
    Verify against the globally configured CA certificates.

``False``
    Do not verify any certificates. Not recommended.

``path to a ca bundle``
    Use the given CA bundle for verification.

``path to ca directory``
    Use the directory as a source for trusted CA certificates.


Client side certificates
------------------------

Some classes allow the configuration of client side TLS certificates
for mutual authentication. You can configure it with the `client_cert`
option, which follows the semantics of the request libraries `cert`
option.
