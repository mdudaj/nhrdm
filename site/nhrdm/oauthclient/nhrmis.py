# -*- coding: utf-8 -*-
# Copyright (C) 2025 National Institute for Medical Research (NIMR)
# This file is part of NHRDM.
#
# NHRMIS OAuth Provider Plugin for InvenioRDM
#

import requests
from flask import current_app, redirect, url_for
from flask_login import current_user
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
            # authorized_handler="nhrdm.oauthclient.nhrmis:authorized",
            authorized_handler="invenio_oauthclient.handlers:authorized_signup_handler",
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
            # authorized_handler="nhrdm.oauthclient.nhrmis:authorized_rest",
            authorized_handler="invenio_oauthclient.handlers.rest"
            ":authorized_signup_handler",
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
    full_name = (
        f"{user_info.get('first_name','')} {user_info.get('last_name','')}".strip()
    )

    return dict(
        user=dict(
            email=user_info.get("email"),
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
