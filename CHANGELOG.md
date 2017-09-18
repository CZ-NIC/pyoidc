# Change Log
All notable changes to this project will be documented in this file.

The format is based on the [KeepAChangeLog] project.

[KeepAChangeLog]: http://keepachangelog.com/

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
