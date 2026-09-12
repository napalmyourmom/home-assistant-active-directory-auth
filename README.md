# Active Directory authentication add-on for Home Assistant

This Home Assistant add-on enables authentication against a Microsoft Active Directory (AD) domain using LDAP or LDAPS.
It integrates with the Home Assistant `command_line` authentication provider and supports:

- Lookup and verification of AD users via LDAP or LDAPS bind
- Group-based access control (direct **or** nested membership)
- Administrator assignment based on AD group membership
- Automatic loading of a trusted CA certificate from `/config/certs/ldap-cert.pem` (or a pasted PEM) for LDAPS

## Features

- Authenticate users against Active Directory using LDAP (port 389) or LDAPS (port 636)
- A user may log in only if they are a member of the configured `user_group`
- Automatically creates the user account in Home Assistant if none exists
- Promotes the user to admin only if they are a member of `admin_group`
- Supports full names (`displayName` or `cn`) and email from AD
- The internal auth server binds to loopback only and runs on a production WSGI server (waitress)

## Installation

1. Open the Home Assistant UI
2. Navigate to **Settings → Add-ons → Add-on Store**
3. Click the ⋮ menu in the top-right corner → **Repositories**
4. Add the repository: `https://github.com/napalmyourmom/home-assistant-active-directory-auth`
5. Install the **Active Directory authentication Add-on**, configure it (below), and start it

## Configuration

### 1. Home Assistant `configuration.yaml`

Add the `command_line` auth provider (keep the built-in `homeassistant` provider as break-glass):

```yaml
homeassistant:
  auth_providers:
    - type: command_line
      name: "Microsoft Active Directory"
      command: /config/auth-wrapper.sh
      args: []          # required on recent HA cores — omitting args crashes login
      meta: true
    - type: homeassistant
      name: "Local users"
      meta: true
```

The command points to a wrapper script that talks to this add-on's local auth server on `127.0.0.1:8000`.

### 2. Add-on configuration

| Config field | Description |
|--------------|-------------|
| **ldap_server** | Full LDAP or LDAPS URI to your domain controller (e.g. `ldaps://dc1.example.org:636`) |
| **bind_user** | A read-only AD service account used to look up users/groups (e.g. `ha-bind@example.com`) |
| **bind_password** | Password for the bind user |
| **user_base_dn** | Base DN to search for user accounts |
| **groups_base_dn** | Base DN to search for security groups (searched recursively) |
| **user_group** | CN of the group a user must belong to in order to log in |
| **admin_group** | CN of the group that grants Home Assistant admin |
| **enable_ldaps** | Use secure LDAPS (port 636) |
| **ldaps_verify** | Validate the domain controller certificate (keep `true`) |
| **ldaps_ca_pem** | Paste the issuing CA certificate (PEM) if not using `/config/certs/ldap-cert.pem` |
| **debug_logging** | Verbose logging for troubleshooting |

### 3. The wrapper script (place in the `/config` folder)

`auth-wrapper.sh` calls the local auth server and prints the metadata Home Assistant expects:

```bash
#!/bin/bash
# Requires curl + jq.  NOTE: the Home Assistant OS "Core" container often lacks curl/jq,
# in which case use a Python equivalent that POSTs to http://127.0.0.1:8000/auth and prints
# the same "name" / "group" lines below.

response=$(curl -s -f -X POST \
  --data-urlencode "username=$username" \
  --data-urlencode "password=$password" \
  http://127.0.0.1:8000/auth) || exit 1

NAME=$(echo "$response" | jq -r .name)
IS_ADMIN=$(echo "$response" | jq -r .is_admin)

[ "$NAME" != "null" ] && echo "name = $NAME"

# Home Assistant honours ONLY the meta keys: name, group, local_only.
# `is_admin` is ignored, and with NO group HA defaults a new provider user to admin,
# so the group MUST be set explicitly.
if [ "$IS_ADMIN" == "true" ]; then
  echo "group = system-admin"
else
  echo "group = system-users"
fi
```

### Notes

- A user can log in if they are a **direct or nested** member of `user_group` **or** `admin_group` (admin membership implies user access).
- Admin is granted only to members of `admin_group`; everyone else is provisioned as a normal user (`group = system-users`).
- Home Assistant applies the group at user **creation** only. Changing someone's AD group afterwards does **not** re-tier an existing HA user — adjust it in Home Assistant (or delete and recreate the HA user).
- Passwords are never stored; they are posted to the local auth server (loopback) and bound straight to AD.
- The bind user should have **minimal permissions** — read access to users and groups only.

### Troubleshooting

- Check the add-on log under **Settings → Add-ons → Active Directory authentication** (enable `debug_logging`).
- From an environment that has `curl` you can test the `/auth` endpoint directly (loopback only):

  ```bash
  curl -i -X POST --data-urlencode "username=youruser" --data-urlencode "password=yourpass" \
    http://127.0.0.1:8000/auth
  ```
