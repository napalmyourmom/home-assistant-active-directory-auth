# Changelog

## 2.1.1
- Admin group membership now implies user access: a user may log in if they belong to **either** the admin group or the user group (admins no longer need to be members of both).

## 2.1.0
- Security: bind the internal auth server to `127.0.0.1` only (was `0.0.0.0`). With `host_network: true` this keeps the credential endpoint off the LAN; Home Assistant Core still reaches it on the host loopback.
- Security: remove the unauthenticated `/diagnose` endpoint (leaked CA subject/issuer and shelled out to `openssl`).
- Fix admin provisioning: emit `group = system-admin` / `group = system-users` from the wrapper. Home Assistant ignores `is_admin`; with no `group` it defaults new provider users to admin — so non-admins were wrongly made admins.
- Groups: resolve the group DN by CN under `groups_base_dn` and match **direct or nested** membership via `LDAP_MATCHING_RULE_IN_CHAIN`. Groups no longer must sit directly under `groups_base_dn`.
- Serve via **waitress** (production WSGI) instead of the Flask development server.
- Warn when `ldaps_verify` is disabled.
- Add `build.yaml` (Alpine base images) so the add-on builds.

## 2.0.0
- Added LDAPS support

## 1.0.3
- Moved `options` to `config.json` to preserve user configuration during updates
- Minor improvements to metadata

## 1.0.0
- Initial release with Active Directory authentication via LDAP
