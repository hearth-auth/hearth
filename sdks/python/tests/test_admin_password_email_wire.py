"""AdminClient.send_password_email — ``POST /admin/users/{id}/password-email``.

The server emails the user a link to choose a password: the welcome email for
a user with no password, the reset email for a user with one. It answers with
the kind of email it sent.
"""

from __future__ import annotations

import httpx

from hearth.admin import AdminClient

BASE = "http://localhost:8420"


def test_send_password_email_posts_and_returns_the_kind(respx_mock):
    route = respx_mock.post(f"{BASE}/admin/users/u-1/password-email").mock(
        return_value=httpx.Response(200, json={"kind": "PASSWORD_EMAIL_KIND_RESET"})
    )

    kind = AdminClient(BASE, "admin-token", "realm-1").send_password_email("u-1")

    assert route.called
    assert route.calls[0].request.headers["x-realm-id"] == "realm-1"
    assert kind == "PASSWORD_EMAIL_KIND_RESET"
