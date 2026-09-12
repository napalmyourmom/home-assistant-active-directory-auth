#!/usr/bin/env python3
import os
import json
import ssl
import logging
from urllib.parse import urlparse
from flask import Flask, request, abort, jsonify
from ldap3 import Server, Connection, ALL, BASE, Tls
from ldap3.utils.conv import escape_filter_chars

CONFIG_PATH = "/data/options.json"
with open(CONFIG_PATH) as f:
    config = json.load(f)

LDAP_SERVER_RAW = config["ldap_server"]
LDAP_LOOKUP_USER = config["bind_user"]
LDAP_LOOKUP_PASSWORD = config["bind_password"]
LDAP_USER_BASE_DN = config["user_base_dn"]
LDAP_GROUPS_BASE_DN = config["groups_base_dn"]
LDAP_USER_GROUP_CN = config["user_group"]
LDAP_ADMIN_GROUP_CN = config.get("admin_group") or ""
ENABLE_LDAPS = bool(config.get("enable_ldaps", False))
LDAPS_VERIFY = bool(config.get("ldaps_verify", True))
LDAPS_CA_PEM = (config.get("ldaps_ca_pem") or "").strip()
if "\\n" in LDAPS_CA_PEM:
    LDAPS_CA_PEM = LDAPS_CA_PEM.replace("\\n", "\n")
if "BEGIN CERTIFICATE" in LDAPS_CA_PEM and "\n" not in LDAPS_CA_PEM:
    LDAPS_CA_PEM = LDAPS_CA_PEM.replace("-----BEGIN CERTIFICATE-----", "-----BEGIN CERTIFICATE-----\n")
    LDAPS_CA_PEM = LDAPS_CA_PEM.replace("-----END CERTIFICATE-----", "\n-----END CERTIFICATE-----\n")
DEBUG_LOGGING = bool(config.get("debug_logging", False))
LDAP_TIMEOUT = 3
# AD "LDAP_MATCHING_RULE_IN_CHAIN" — matches direct AND nested group membership.
MATCHING_RULE_IN_CHAIN = "1.2.840.113556.1.4.1941"

logging.basicConfig(level=logging.DEBUG if DEBUG_LOGGING else logging.INFO, format="%(asctime)s %(levelname)s %(message)s", force=True)
logger = logging.getLogger(__name__)

if ENABLE_LDAPS and not LDAPS_VERIFY:
    logger.warning("ldaps_verify is FALSE: the domain controller certificate is NOT validated "
                   "(man-in-the-middle risk). Set ldaps_verify: true and supply the CA via "
                   "ldaps_ca_pem for production use.")

EMBEDDED_CA_FILE = "/data/ldaps_ca.pem"
DEFAULT_CA_PATH = "/config/certs/ldap-cert.pem"
if os.path.exists(DEFAULT_CA_PATH):
    try:
        with open(DEFAULT_CA_PATH, "r", encoding="utf-8") as f:
            LDAPS_CA_PEM = f.read().strip()
        logger.info(f"Loaded CA certificate from {DEFAULT_CA_PATH}")
    except Exception as e:
        logger.error(f"Error reading {DEFAULT_CA_PATH}: {e}")
elif LDAPS_CA_PEM:
    try:
        with open(EMBEDDED_CA_FILE, "w", encoding="utf-8") as f:
            f.write(LDAPS_CA_PEM.strip() + "\n")
        logger.info(f"CA file written: {EMBEDDED_CA_FILE}")
    except Exception as e:
        logger.error(f"Error writing CA file: {e}")

SEARCH_FILTER_TPL = "(&(objectClass=person)(|(sAMAccountName={})(userPrincipalName={})))"
app = Flask(__name__)


def _parse_ldap_server(url_or_host: str):
    parsed = urlparse(url_or_host)
    if parsed.scheme in ("ldap", "ldaps"):
        host = parsed.hostname
        port = parsed.port or (636 if parsed.scheme == "ldaps" else 389)
        use_ssl = parsed.scheme == "ldaps"
    else:
        host = url_or_host
        use_ssl = ENABLE_LDAPS
        port = 636 if use_ssl else 389
    if ENABLE_LDAPS:
        use_ssl = True
        if port == 389 or port is None:
            port = 636
    logger.debug(f"Connecting to {host}:{port} (SSL={use_ssl})")
    return host, port, use_ssl


def _make_server():
    host, port, use_ssl = _parse_ldap_server(LDAP_SERVER_RAW)
    tls = None
    if use_ssl:
        validate_mode = ssl.CERT_REQUIRED if LDAPS_VERIFY else ssl.CERT_NONE
        ca_file = DEFAULT_CA_PATH if os.path.exists(DEFAULT_CA_PATH) else EMBEDDED_CA_FILE if LDAPS_CA_PEM else None
        tls = Tls(ca_certs_file=ca_file, validate=validate_mode, version=ssl.PROTOCOL_TLS_CLIENT)
    return Server(host=host, port=port, use_ssl=use_ssl, get_info=ALL, tls=tls)


def _resolve_group_dn(conn, cn):
    """Find a group's real DN by CN anywhere under groups_base_dn (subtree), so
    membership does not depend on the group living directly under that OU."""
    flt = f"(&(objectClass=group)(cn={escape_filter_chars(cn)}))"
    if conn.search(LDAP_GROUPS_BASE_DN, flt, attributes=[]):
        return conn.entries[0].entry_dn
    return None


def _is_member(conn, user_dn, group_dn):
    """True if user_dn is a direct OR nested member of group_dn (AD IN_CHAIN rule)."""
    flt = f"(memberOf:{MATCHING_RULE_IN_CHAIN}:={escape_filter_chars(group_dn)})"
    return bool(conn.search(user_dn, flt, search_scope=BASE, attributes=[]))


def ldap_auth(username, password):
    safe = escape_filter_chars(username)
    search_filter = SEARCH_FILTER_TPL.format(safe, safe)
    server = _make_server()
    conn = Connection(server, user=LDAP_LOOKUP_USER, password=LDAP_LOOKUP_PASSWORD,
                      receive_timeout=LDAP_TIMEOUT, auto_bind=True)
    if not conn.search(LDAP_USER_BASE_DN, search_filter, attributes=["sAMAccountName", "displayName", "cn", "mail"]):
        raise Exception("User not found")
    entry = conn.entries[0]
    user_dn = entry.entry_dn

    # Verify the password by binding as the user.
    if not conn.rebind(user=user_dn, password=password):
        raise Exception("Invalid credentials")
    # Rebind back to the service account for reliable group reads.
    if not conn.rebind(user=LDAP_LOOKUP_USER, password=LDAP_LOOKUP_PASSWORD):
        raise Exception("Service rebind failed")

    user_group_dn = _resolve_group_dn(conn, LDAP_USER_GROUP_CN)
    if not user_group_dn:
        raise Exception(f"Configured user_group not found under groups_base_dn: {LDAP_USER_GROUP_CN}")
    if not _is_member(conn, user_dn, user_group_dn):
        raise Exception("Not in required user group")

    is_admin = False
    if LDAP_ADMIN_GROUP_CN:
        admin_group_dn = _resolve_group_dn(conn, LDAP_ADMIN_GROUP_CN)
        is_admin = bool(admin_group_dn and _is_member(conn, user_dn, admin_group_dn))

    display = entry.displayName.value if entry.displayName else username
    email = entry.mail.value if entry.mail else ""
    return username, display, email, is_admin


@app.route("/auth", methods=["POST"])
def auth():
    u = request.form.get("username")
    p = request.form.get("password")
    if not u or not p:
        abort(401)
    try:
        username, name, email, is_admin = ldap_auth(u, p)
    except Exception as e:
        logger.error(f"Authentication failed for {u}: {e}")
        abort(401)
    return jsonify({"username": username, "name": name, "email": email, "is_active": True, "is_admin": is_admin}), 200


if __name__ == "__main__":
    from waitress import serve
    # Bind to loopback only. With host_network=true this keeps the credential
    # endpoint off the LAN; Home Assistant Core reaches it on the host loopback.
    logger.info("Starting AD auth server on 127.0.0.1:8000 (waitress)")
    serve(app, host="127.0.0.1", port=8000)
