# Change Log
All notable changes to this project will be documented in this file.

The format is based on the [KeepAChangeLog] project.

[KeepAChangeLog]: http://keepachangelog.com/

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
