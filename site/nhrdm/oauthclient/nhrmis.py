# -*- coding: utf-8 -*-
# Copyright (C) 2025 National Institute for Medical Research (NIMR)
# This file is part of NHRDM.
#
# NHRMIS OAuth Provider Plugin for InvenioRDM
#

"""
NHRMIS OAuth Provider Integration for InvenioRDM
================================================

This module provides a fully pre-configured OAuth remote application for
enabling Single Sign-On (SSO) between NHRMIS (National Health Research
Management Information System) and the NHRDM InvenioRDM repository.

Overview
--------

The integration follows the standard Invenio OAuthClient architecture and
provides:

- A `NHRMISOAuthSettingsHelper` class that defines OAuth endpoints,
  authorization URLs, token URLs, handler mappings, and application metadata.
- Automatically constructed `REMOTE_APP` and `REMOTE_REST_APP` configuration
  objects consumed by Invenio-OAuthClient.
- Serialization and normalization of NHRMIS user data so it can be used by
  Invenio for account creation, linking, and authentication.
- Complete signup, account-setup, and linking flows.
- Support for both HTML UI handlers and REST API handlers.
- Disconnect/unlink functionality to remove an external NHRMIS identity from
  an Invenio account.

Configuration
-------------

To enable this provider in your Invenio instance, edit your configuration
and add:

.. code-block:: python

    from nhrdm.oauthclient import nhrmis

    OAUTHCLIENT_REMOTE_APPS = dict(
        nhrmis=nhrmis.REMOTE_APP,
    )

    NHRMIS_APP_CREDENTIALS = dict(
        consumer_key="changeme",
        consumer_secret="changeme",
    )

You may override the userinfo endpoint if needed:

.. code-block:: python

    NHRMIS_APP_USERINFO_URL = "https://nhrmis.nimr.or.tz/api/user"


Key Functional Components
-------------------------

1. **Settings Helper (`NHRMISOAuthSettingsHelper`)**
   - Declares OAuth endpoints:
     - Authorization URL: `https://nhrmis.nimr.or.tz/oauth/authorize`
     - Token URL:        `https://nhrmis.nimr.or.tz/oauth/token`
   - Defines handler mappings for:
     - Authorization callback
     - Disconnect operations
     - Signup flow (info → serialize → setup)
   - Exposes:
     - `REMOTE_APP`
     - `REMOTE_REST_APP`
     used by InvenioRDM to register this provider.

2. **Account Information Retrieval**
   - User info is fetched from NHRMIS via:
     `/api/user`
   - Data is normalized into the structure expected by Invenio:
     - Email
     - Full name
     - Institution (affiliation)
     - External unique identifier
   - The `account_info_serializer` ensures consistent representation.

3. **Account Setup & Linking**
   - After successful OAuth authorization:
     - User metadata is stored in `RemoteAccount.extra_data`
     - The NHRMIS external ID is linked to the Invenio user
       using `oauth_link_external_id`.

4. **Disconnect / Unlink**
   - Users may unlink their NHRMIS identity.
   - Implements the standard Invenio unlink flow:
     - Remove external identifier
     - Remove any associated `RemoteAccount` rows

5. **HTML and REST Support**
   - Both interface types are supported:
     - `/oauth/login/nhrmis/`
     - `/oauth/authorized/nhrmis/`
     - REST endpoints for programmatic sign-in.

Usage
-----

Once configured:

- The login endpoint becomes:
  `/oauth/login/nhrmis/`

- Users will be redirected to NHRMIS for authentication and returned to the
  Invenio callback where:
  - User data is fetched
  - The account is created or matched
  - External identity is linked

- The provider will appear under:
  `/account/settings/linkedaccounts/`

This module provides a complete NHRMIS → InvenioRDM SSO bridge, following
Invenio best practices for external authentication, user provisioning,
and identity linking.
"""


import requests
from flask import current_app, redirect, url_for
from flask_login import current_user, login_user
from invenio_accounts.models import User
from invenio_accounts.proxies import current_datastore
from invenio_db import db
from invenio_i18n import lazy_gettext as _
from invenio_oauthclient import current_oauthclient
from invenio_oauthclient.contrib.settings import OAuthSettingsHelper
from invenio_oauthclient.handlers import authorized_signup_handler, oauth_error_handler
from invenio_oauthclient.handlers.rest import (
    authorized_signup_handler as authorized_signup_rest_handler,
)
from invenio_oauthclient.handlers.rest import oauth_resp_remote_error_handler
from invenio_oauthclient.handlers.utils import (
    make_handler,
    require_more_than_one_external_account,
)
from invenio_oauthclient.models import RemoteAccount
from invenio_oauthclient.oauth import oauth_link_external_id, oauth_unlink_external_id
from nhrdm.oauthclient.utils import generate_unique_username, slugify_name

#
# --- SETTINGS HELPER -------------------------------------------------------
#


class NHRMISOAuthSettingsHelper(OAuthSettingsHelper):
    """
    Default configuration for NHRMIS OAuth provider.
    """

    def __init__(
        self,
        title=None,
        description=None,
        base_url=None,
        app_key=None,
        icon=None,
        precedence_mask=None,
        signup_options=None,
    ):
        super().__init__(
            title or _("NHRMIS SSO"),
            description or _("National Health Research Management Information System"),
            base_url or "https://nhrmis.nimr.or.tz/",
            app_key or "NHRMIS_APP_CREDENTIALS",
            icon=icon or "fa fa-user",
            access_token_url="https://nhrmis.nimr.or.tz/oauth/token",
            authorize_url="https://nhrmis.nimr.or.tz/oauth/authorize",
            request_token_params={"scope": ""},
            precedence_mask=precedence_mask,
            signup_options=signup_options,
        )

        #
        # Handlers (HTML UI)
        #
        self._handlers = dict(
            authorized_handler="nhrdm.oauthclient.nhrmis:authorized_auto_login_create",
            # authorized_handler="invenio_oauthclient.handlers:authorized_signup_handler",
            disconnect_handler="nhrdm.oauthclient.nhrmis:disconnect_handler",
            signup_handler=dict(
                info="nhrdm.oauthclient.nhrmis:account_info",
                info_serializer="nhrdm.oauthclient.nhrmis:account_info_serializer",
                setup="nhrdm.oauthclient.nhrmis:account_setup",
                view="invenio_oauthclient.handlers:signup_handler",
            ),
        )

        #
        # REST handlers
        #
        self._rest_handlers = dict(
            authorized_handler="nhrdm.oauthclient.nhrmis:authorized_auto_login_create",
            # authorized_handler="invenio_oauthclient.handlers.rest"
            # ":authorized_signup_handler",
            disconnect_handler="nhrdm.oauthclient.nhrmis:disconnect_rest_handler",
            signup_handler=dict(
                info="nhrdm.oauthclient.nhrmis:account_info",
                info_serializer="nhrdm.oauthclient.nhrmis:account_info_serializer",
                setup="nhrdm.oauthclient.nhrmis:account_setup",
                view="invenio_oauthclient.handlers.rest:signup_handler",
            ),
            response_handler="invenio_oauthclient.handlers.rest"
            ":default_remote_response_handler",
            authorized_redirect_url="/",
            disconnect_redirect_url="/",
            signup_redirect_url="/",
            error_redirect_url="/",
        )

    def get_handlers(self):
        """Return NHRMIS OAuth handlers."""
        return self._handlers

    def get_rest_handlers(self):
        """Return NHRMIS OAuth REST handlers."""
        return self._rest_handlers


#
# --- REMOTE APP DEFINITIONS ------------------------------------------------
#

_nhrmis_app = NHRMISOAuthSettingsHelper()

BASE_APP = _nhrmis_app.base_app
REMOTE_APP = _nhrmis_app.remote_app
REMOTE_REST_APP = _nhrmis_app.remote_rest_app


#
# --- ACCOUNT SERIALIZATION -------------------------------------------------
#


def account_info_serializer(remote, resp, user_info, **kwargs):
    """
    Serialize the account info response object.
    Translate NHRMIS account data -> Invenio standard structure.

    : param remote: The remote app.
    : param resp: The OAuth response.
    : param user_info: The user info dictionary returned from NHRMIS.

    Output:
        {
            "external_id": "...",
            "external_method": "nhrmis",
            "user": {
                "email": "...",
                "profile": {
                    "full_name": "...",
                    "affiliations": "...",
                }
            }
        }
    """
    # Build full name
    full_name = (
        f"{user_info.get('first_name','')} {user_info.get('last_name','')}".strip()
    )

    # ------------------------------------------------------------
    # 1) Build a base username from full name or email prefix
    # ------------------------------------------------------------
    if full_name:
        base_username = slugify_name(full_name)
    else:
        # fallback: email prefix
        email = user_info.get("email", "")
        base_username = slugify_name(email.split("@")[0] if email else "user")

    # ------------------------------------------------------------
    # 2) Fetch existing usernames so the utility can ensure uniqueness
    # ------------------------------------------------------------
    existing_usernames = {u.username for u in db.session.query(User.username).all()}

    # ------------------------------------------------------------
    # 3) Generate a unique, regex-compliant InvenioRDM username
    # ------------------------------------------------------------
    username = generate_unique_username(base_username, existing_usernames)

    # ------------------------------------------------------------
    # 4) Return standard structure
    # ------------------------------------------------------------
    return dict(
        user=dict(
            email=user_info.get("email"),
            username=username,
            profile=dict(
                full_name=full_name,
                affiliations=user_info.get("institution"),
            ),
        ),
        external_id=str(user_info["id"]),
        external_method=remote.name,
    )


def account_info(remote, resp):
    """
    Retrieve user information from NHRMIS `/api/user`.

    : param remote: The remote app.
    : param resp: The OAuth response.
    Output:
        The serialized account info dictionary.
    """
    access_token = resp["access_token"]

    userinfo_url = current_app.config.get(
        "NHRMIS_APP_USERINFO_URL",
        f"{remote.base_url.rstrip('/')}/api/user",
    )

    r = requests.get(
        userinfo_url,
        headers={"Authorization": f"Bearer {access_token}"},
        timeout=5,
    )
    r.raise_for_status()
    user_info = r.json()

    handlers = current_oauthclient.signup_handlers[remote.name]
    return handlers["info_serializer"](resp, user_info=user_info)


def account_setup(remote, token, resp):
    """
    Additional setup after login.

    Stores NHRMIS external ID in the RemoteAccount and links
    the external identifier to the local user.
    : param remote: The remote app.
    : param token: The OAuth token.
    : param resp: The OAuth response.
    """
    access_token = resp["access_token"]

    # Fetch data for storage in extra_data
    userinfo_url = current_app.config.get(
        "NHRMIS_APP_USERINFO_URL",
        f"{remote.base_url.rstrip('/')}/api/user",
    )
    r = requests.get(
        userinfo_url,
        headers={"Authorization": f"Bearer {access_token}"},
        timeout=5,
    )
    userinfo = r.json()

    with db.session.begin_nested():
        token.remote_account.extra_data = {
            "id": userinfo.get("id"),
            "email": userinfo.get("email"),
            "institution": userinfo.get("institution"),
        }

        oauth_link_external_id(
            token.remote_account.user,
            dict(id=str(userinfo["id"]), method=remote.name),
        )


#
# --- DISCONNECT HANDLING ---------------------------------------------------
#


@require_more_than_one_external_account
def _disconnect(remote, *args, **kwargs):
    """
    Shared unlink logic, follows GitHub implementation.
    : param remote: The remote app.
    """
    if not current_user.is_authenticated:
        return current_app.login_manager.unauthorized()

    remote_account = RemoteAccount.get(
        user_id=current_user.get_id(),
        client_id=remote.consumer_key,
    )

    external_ids = [
        i.id for i in current_user.external_identifiers if i.method == remote.name
    ]

    if external_ids:
        oauth_unlink_external_id(dict(id=external_ids[0], method=remote.name))

    if remote_account:
        with db.session.begin_nested():
            remote_account.delete()


def disconnect_handler(remote, *args, **kwargs):
    _disconnect(remote, *args, **kwargs)
    return redirect(url_for("invenio_oauthclient_settings.index"))


def disconnect_rest_handler(remote, *args, **kwargs):
    _disconnect(remote, *args, **kwargs)
    return {"status": "disconnected"}


#
# --- AUTHORIZED (OAUTH CALLBACK) -------------------------------------------
#


@oauth_error_handler
def authorized(resp, remote):
    """
     HTML callback handler.

    : param resp: The OAuth response.
    : param remote: The remote app.
    """
    return authorized_signup_handler(resp, remote)


@oauth_resp_remote_error_handler
def authorized_rest(resp, remote):
    """
    REST callback handler.
    """
    return authorized_signup_rest_handler(resp, remote)


@oauth_error_handler
def authorized_auto_login_create(resp, remote):
    """
    HTML callback handler with auto-login or auto-create user from NHRMIS.

    1. Fetches user info from NHRMIS.
    2. Checks if a user exists by external ID or email.
    3. If not, creates the user.
    4. Logs in the user and redirects to dashboard.

    : param resp: The OAuth response.
    : param remote: The remote app.
    """
    # 1. Fetch user info (serialized)
    user_data = account_info(remote, resp)  # calls account_info -> serializer

    email = user_data["user"]["email"]
    username = user_data["user"]["username"]
    full_name = user_data["user"]["profile"]["full_name"]
    affiliations = user_data["user"]["profile"]["affiliations"]
    external_id = user_data["external_id"]

    # 2. Check for existing user by external ID
    user = (
        db.session.query(User)
        .filter(User.external_identifiers.any(id=external_id, method=remote.name))
        .one_or_none()
    )

    # 3. If not found, check by email
    if not user and email:
        user = current_datastore.find_user(email=email)

    # 4. If still not found, create the user
    if not user:
        user = User(
            username=username,
            email=email,
            active=True,
            user_profile={
                "full_name": full_name,
                "affiliations": affiliations,
            },
        )
        db.session.add(user)
        db.session.flush()  # to get user.id

    # 5. Link external ID
    oauth_link_external_id(
        user,
        dict(id=external_id, method=remote.name),
    )

    db.session.commit()

    # 6. Log in the user
    login_user(user)

    return redirect(url_for("invenio_app_rdm_users.uploads"))
