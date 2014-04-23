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
