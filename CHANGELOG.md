# Change Log
All notable changes to this project will be documented in this file.

The format is based on the [KeepAChangeLog] project.

[KeepAChangeLog]: http://keepachangelog.com/

## Unreleased

### Fixed
- [#341] Using constant time comparison for password verification
- [#598] Move alabaster from runtime dependencies to docs
- [#398] Do not echo cookies that do not belong to us
- [#607] Fixed key recovery on encryption of payload
- [#618] Prettified `client_management.py` CLI and wrapped it as
         a setup.py console script `oic-client-management`

### Changed
- [#578] Dropped python 2.7 support
- [#612] Dropped python 3.4 support
- [#588] Switch to defusedxml for XML parsing
- [#605] Message.c_param dictionary values have to be a ParamDefinition namedtuple type

### Added
- [#441] CookieDealer now accepts secure and httponly params

[#598]: https://github.com/OpenIDC/pyoidc/issues/598
[#588]: https://github.com/OpenIDC/pyoidc/issues/588
[#341]: https://github.com/OpenIDC/pyoidc/issues/341
[#398]: https://github.com/OpenIDC/pyoidc/issues/398
[#605]: https://github.com/OpenIDC/pyoidc/pull/605
[#607]: https://github.com/OpenIDC/pyoidc/issues/607
[#441]: https://github.com/OpenIDC/pyoidc/issues/441
[#612]: https://github.com/OpenIDC/pyoidc/pull/612
[#618]: https://github.com/OpenIDC/pyoidc/pull/618

## 0.15.1 [2019-01-31]

### Fixed
- [#592] Do not append cookie header if there is nothing to append
- [#591] Fix verification of encrypted id_token
- [#601] Fix headers od encrypted id_token

[#578]: https://github.com/OpenIDC/pyoidc/issues/578
[#592]: https://github.com/OpenIDC/pyoidc/issues/592
[#591]: https://github.com/OpenIDC/pyoidc/issues/591
[#601]: https://github.com/OpenIDC/pyoidc/pull/600

## 0.15.0 [2019-01-17]

### Fixed
- [#553] Made sure a reload would not lead to duplicated keys in a keybundle.
- [#557] Fixed PKCE verification
- [#562] Fixed error response from oic request with invalid params
- [#565] Fixed checking token_type in AuthorizationResponse
- [#547] Fixed get_userinfo_claims method
- [#268] Fixed SessionDB.revoke_token implementation
- [#571] Return error when when resolving request_uri fails
- [#579] Fix error with unicode chars in redirect_uris
- [#581] Fix error in verification of sector_identifier
- [#542] Updated examples
- [#587] Fix JWKS content type detection
- [#582] Handling import of non-compliant JWKS

### Added
- [#577] Check that issuer of a signed JWT exists in the KeyJar used to verify the signature.
- [#566] Added timeout to communications to remote servers
- [#590] Worked on support for RP initiated logout

[#553]: https://github.com/OpenIDC/pyoidc/pull/553
[#557]: https://github.com/OpenIDC/pyoidc/pull/557
[#562]: https://github.com/OpenIDC/pyoidc/issues/562
[#565]: https://github.com/OpenIDC/pyoidc/issues/565
[#577]: https://github.com/OpenIDC/pyoidc/pull/577
[#566]: https://github.com/OpenIDC/pyoidc/issues/566
[#547]: https://github.com/OpenIDC/pyoidc/issues/547
[#268]: https://github.com/OpenIDC/pyoidc/issues/268
[#571]: https://github.com/OpenIDC/pyoidc/issues/571
[#579]: https://github.com/OpenIDC/pyoidc/issues/579
[#581]: https://github.com/OpenIDC/pyoidc/issues/581
[#542]: https://github.com/OpenIDC/pyoidc/pull/542
[#587]: https://github.com/OpenIDC/pyoidc/pull/587
[#582]: https://github.com/OpenIDC/pyoidc/issues/582
[#590]: https://github.com/OpenIDC/pyoidc/pull/590

## 0.14.0 [2018-05-15]

### Fixed
- [#534] Fixed a bug in client_secret_basic authentication
- [#503] Fix error on UserInfo endpoint for removed clients
- [#508] JWT now uses verify keys for JWT verification
- [#502] IntrospectionEndpoint now returns False if it encounters any error as per specs
- [#481] Loading AuthnEvent from session
- [#492] Do not verify JWT signature on distributed claims
- [#526] Cleaned up extra claims from UserInfo with distributed claims
- [#528] Fix faulty redirect_uri with query
- [#532] Fix userinfo endpoint without auhtn_event in session
- [#528] Fix faulty redirect_uri with query
- [#498] Clean up replaced tokens on refresh and add Client.clean_tokens to clean old and replaced tokens

### Removed
- [#494] Methods and functions deprecated in previous releases have been removed

### Changed
- [#507] Altered structure of client_db. It no longer stores mapping of ``registration_access_token`` to ``client_id``
- [#481] AuthnEvent in session is now represented as JSON

### Added
- [#496] Ability to specify additional supported scopes for oic.Provider
- [#432] Ability to specify Initial Access Token for ``Client.register``

[#494]: https://github/com/OpenIDC/issues/494
[#496]: https://github.com/OpenIDC/pyoidc/issues/496
[#503]: https://github.com/OpenIDC/pyoidc/issues/503
[#508]: https://github.com/OpenIDC/pyoidc/issues/508
[#507]: https://github.com/OpenIDC/pyoidc/issues/507
[#502]: https://github.com/OpenIDC/pyoidc/issues/502
[#481]: https://github.com/OpenIDC/pyoidc/issues/481
[#492]: https://github.com/OpenIDC/pyoidc/issues/492
[#432]: https://github.com/OpenIDC/pyoidc/issues/432
[#526]: https://github.com/OpenIDC/pyoidc/issues/526
[#528]: https://github.com/OpenIDC/pyoidc/issues/528
[#532]: https://github.com/OpenIDC/pyoidc/pull/532
[#498]: https://github.com/OpenIDC/pyoidc/issues/498
[#534]: https://github.com/OpenIDC/pyoidc/pull/534

## 0.13.1 [2018-04-06]

### Fixed
- [#515]: Fix arguments to WSGI start_response

[#515]: https://github.com/OpenIDC/pyoidc/issues/515

## 0.13.0 [2018-02-19]

### Added
- [#493] grant_types specification should follow the response_types specification in a client registration request.
- [#469] Allow endpoints to have query parts
- [#443] Ability to specify additional supported claims for oic.Provider
- [#134] Added method kwarg to registration_endpoint that enables the client to read/modify registration
- [#478] Addedd base-class for Client databases ``oic.utils.clientdb.BaseClientDatabase``
- [#334] Ability to specify custom template rendering function for form_post and verify_logout

### Changed
- [#134] ``l_registration_enpoint`` has been deprecated, use ``create_registration`` instead
- [#457] pyldap is now an optional dependency. ``oic.utils.authn.ldapc`` and ``oic.utils.userinfo.ldap_info`` raise
         ``ImportError`` on import if ``pyldap`` is not present
- [#471] ``ca_certs`` option has been removed, use ``verify_ssl`` instead
- [#483] ``oic.oauth2.uril.verify_header`` now raises ``ValueError`` insteaad of ``AssertionError``.
- [#491] ``oic.utils.http_util.Response.status`` is deprecated in favor of ``status_code``
- [#491] Some functions and kwargs in ``oic.oauth2`` module are deprecated

### Removed
- [#334] Removed template_lookup and template kwargs from oic.Provider

### Fixed
- [#430] Audience of a client assertion is endpoint dependent.
- [#427] Made matching for response_types order independent for authorization requests
- [#399] Matching response_types for authz requests is too strict
- [#436] Fixed client.read_registration
- [#446] Fixed provider.read_registration
- [#449] Fixed creation of error_response on client registration
- [#445] Fixed get_client_id
- [#421] Fixed handling of unicode in sanitize function
- [#145] Successful token endpoint responses have correct no-cache headers
- [#352] Fixed broken windows test for ``test_provider_key_setup``. 
- [#475] ``get_verify_key`` returns inactive ``sig`` keys for verification
- [#429] An expired token is not possible to use.
- [#485] Skip import of improperly defined keys
- [#370] Use oic.oic.Provider.endp instead of dynamic provider.endpoints in examples

### Security
- [#486] SystemRandom is not imported correctly, so various secrets get initialized with bad randomness

[#493]: https://github.com/OpenIDC/pyoidc/pull/493
[#430]: https://github.com/OpenIDC/pyoidc/pull/430
[#427]: https://github.com/OpenIDC/pyoidc/pull/427
[#399]: https://github.com/OpenIDC/pyoidc/issues/399
[#436]: https://github.com/OpenIDC/pyoidc/pull/436
[#443]: https://github.com/OpenIDC/pyoidc/pull/443
[#446]: https://github.com/OpenIDC/pyoidc/issues/446
[#449]: https://github.com/OpenIDC/pyoidc/issues/449
[#445]: https://github.com/OpenIDC/pyoidc/issues/445
[#421]: https://github.com/OpenIDC/pyoidc/issues/421
[#134]: https://github.com/OpenIDC/pyoidc/issues/134
[#457]: https://github.com/OpenIDC/pyoidc/issues/457
[#145]: https://github.com/OpenIDC/pyoidc/issues/145
[#471]: https://github.com/OpenIDC/pyoidc/issues/471
[#352]: https://github.com/OpenIDC/pyoidc/issues/352
[#475]: https://github.com/OpenIDC/pyoidc/issues/475
[#478]: https://github.com/OpenIDC/pyoidc/issues/478
[#483]: https://github.com/OpenIDC/pyoidc/pull/483
[#429]: https://github.com/OpenIDC/pyoidc/issues/424
[#485]: https://github.com/OpenIDC/pyoidc/pull/485
[#486]: https://github.com/OpenIDC/pyoidc/issues/486
[#370]: https://github.com/OpenIDC/pyoidc/issues/370
[#491]: https://github.com/OpenIDC/pyoidc/pull/491
[#334]: https://github.com/OpenIDC/pyoidc/issues/334
[#469]: https://github.com/OpenIDC/pyoidc/pull/469

## 0.12.0 [2017-09-25]

### Fixed
- [#419]: Inconsistent release numbers/tags
- [#420]: Distributed claims

[#419]: https://github.com/OpenIDC/pyoidc/issues/419
[#420]: https://github.com/OpenIDC/pyoidc/pull/420

## 0.11.1.0 [2017-08-26]

### Fixed
- [#405]: Fix generation of endpoint urls
- [#411]: Empty lists not indexable
- [#413]: Fix error when wrong response_mode requested
- [#418]: Made phone_number_claim be boolean and fixed a bug when importing JSON (non-boolean where boolean expected)

[#418]: https://github.com/OpenIDC/pyoidc/pull/418
[#411]: https://github.com/OpenIDC/pyoidc/issues/411
[#405]: https://github.com/OpenIDC/pyoidc/issues/405
[#413]: https://github.com/OpenIDC/pyoidc/issues/413

## 0.11.0.0 [2017-07-07]

### Changed
- [#318]: `oic.utils.authn.saml` raises `ImportError` on import if optional `saml2` dependency is not present.
- [#324]: Make the Provider `symkey` argument optional.
- [#325]: `oic.oic.claims_match` implementation refactored.
- [#368]: `oic.oauth2.Client.construct_AccessTokenRequest()` as well as `oic.oic.Client` are now able to perform proper Resource Owner Password Credentials Grant
- [#374]: Made the to_jwe/from_jwe methods of Message accept list of keys value of parameter keys.
- [#387]: Refactored the `oic.utils.sdb.SessionDB` constructor API.
- [#380]: Made cookie_path and cookie_domain configurable via Provider like the cookie_name.
- [#386]: An exception will now be thrown if a sub claim received from the userinfo endpoint is not the same as a sub claim previously received in an ID Token.
- [#392]: Made sid creation simpler and faster

### Fixed
- [#317]: Resolved an `AttibuteError` exception under Python 2.
- [#313]: Catch exception correctly
- [#319]: Fix sanitize on strings starting with "B" or "U"
- [#330]: Fix client_management user input being eval'd under Python 2
- [#358]: Fixed claims_match
- [#362]: Fix bad package settings URL
- [#369]: The AuthnEvent object is now serialized to JSON for the session.
- [#373]: Made the standard way the default when dealing with signed JWTs without 'kid'. Added the possibility to override this behavior if necessary.
- [#401]: Fixed message decoding and verifying errors.

### Security
- [#349]: Changed crypto algorithm used by `oic.utils.sdb.Crypt` for token encryption to Fernet. Old stored tokens are incompatible.
- [#363]: Fixed IV reuse for CookieDealer class. Replaced the encrypt-then-mac construction with a proper AEAD (AES-SIV).

[#401]: https://github.com/OpenIDC/pyoidc/pull/401
[#386]: https://github.com/OpenIDC/pyoidc/pull/386
[#380]: https://github.com/OpenIDC/pyoidc/pull/380
[#317]: https://github.com/OpenIDC/pyoidc/pull/317
[#313]: https://github.com/OpenIDC/pyoidc/issues/313
[#387]: https://github.com/OpenIDC/pyoidc/pull/387
[#318]: https://github.com/OpenIDC/pyoidc/pull/318
[#319]: https://github.com/OpenIDC/pyoidc/pull/319
[#324]: https://github.com/OpenIDC/pyoidc/pull/324
[#325]: https://github.com/OpenIDC/pyoidc/pull/325
[#330]: https://github.com/OpenIDC/pyoidc/issues/330
[#349]: https://github.com/OpenIDC/pyoidc/issues/349
[#358]: https://github.com/OpenIDC/pyoidc/pull/358
[#362]: https://github.com/OpenIDC/pyoidc/pull/362
[#363]: https://github.com/OpenIDC/pyoidc/issue/363
[#368]: https://github.com/OpenIDC/pyoidc/issues/368
[#369]: https://github.com/OpenIDC/pyoidc/pull/369
[#373]: https://github.com/OpenIDC/pyoidc/pull/373
[#374]: https://github.com/OpenIDC/pyoidc/pull/374
[#392]: https://github.com/OpenIDC/pyoidc/issue/392

## 0.10.0.0 [2017-03-28]

### Changed
- [#291]: Testing more relevant Python versions.
- [#296]: `parse_qs` import from `future.backports` to `future.moves`.
- [#188]: Added `future` dependency, updated dependecies
- [#305]: Some import were removed from `oic.oauth2` and `oic.oic.provider`, please import them from respective modules (`oic.oath2.message` and `oic.exception`).

### Removed
- [#294]: Generating code indices in documentation.

### Fixed
- [#295]: Access token issuance and typo/exception handling.

[#291]: https://github.com/OpenIDC/pyoidc/pull/291
[#294]: https://github.com/OpenIDC/pyoidc/pull/294
[#295]: https://github.com/OpenIDC/pyoidc/pull/295
[#296]: https://github.com/OpenIDC/pyoidc/pull/296
[#188]: https://github.com/OpenIDC/pyoidc/issues/188
[#305]: https://github.com/OpenIDC/pyoidc/pull/305

## 0.9.5.0 [2017-03-22]

### Added
- [#276]: Use a Change log for change history.
- [#277]: Use pip-tools for dependency management.

[#276]: https://github.com/OpenIDC/pyoidc/pull/276
[#277]: https://github.com/OpenIDC/pyoidc/pull/277

### Removed
- [#274]: Moved `oidc_fed` to [fedoidc].

[#274]: https://github.com/OpenIDC/pyoidc/pull/274
[fedoidc]: https://github.com/OpenIDC/fedoidc

### Changed
- [#273]: Allow webfinger accept `kwargs`.

[#273]: https://github.com/OpenIDC/pyoidc/pull/273

### Fixed
- [#286]: Account for missing code in the SessionDB.

[#286]: https://github.com/OpenIDC/pyoidc/pulls/286

## 0.9.4.0 [2016-12-22]
No change log folks. Sorry.
