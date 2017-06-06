# Change Log
All notable changes to this project will be documented in this file.

The format is based on the [KeepAChangeLog] project.

[KeepAChangeLog]: http://keepachangelog.com/

## 0.11.0.0 [UNRELEASED]

### Changed
- [#324]: Make the Provider `symkey` argument optional.

### Fixed
- [#369]: The AuthnEvent object is now serialized to JSON for the session.

[#324]: https://github.com/OpenIDC/pyoidc/pull/324
[#369]: https://github.com/OpenIDC/pyoidc/pull/369

## 0.10.0.1 [UNRELEASED]

### Fixed
- [#362]: Fix bad package settings URL
- [#358]: Fixed claims_match
- [#313]: Catch exception correctly
- [#319]: Fix sanitize on strings starting with "B" or "U"
- [#330]: Fix client_management user input being eval'd under Python 2

### Changed
- [#318]: `oic.utils.authn.saml` raises `ImportError` on import if optional `saml2` dependency is not present.
- [#325]: `oic.oic.claims_match` implementation refactored.

### Security
- [#349]: Changed crypto algorithm used by `oic.utils.sdb.Crypt` for token encryption to Fernet. Old stored tokens are incompatible.

[#313]: https://github.com/OpenIDC/pyoidc/issues/313
[#318]: https://github.com/OpenIDC/pyoidc/pull/318
[#319]: https://github.com/OpenIDC/pyoidc/pull/319
[#325]: https://github.com/OpenIDC/pyoidc/pull/325
[#349]: https://github.com/OpenIDC/pyoidc/issues/349
[#362]: https://github.com/OpenIDC/pyoidc/pull/362

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
