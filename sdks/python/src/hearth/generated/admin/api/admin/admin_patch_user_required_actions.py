from http import HTTPStatus
from typing import Any, cast
from urllib.parse import quote

import httpx

from ...client import AuthenticatedClient, Client
from ...types import Response, UNSET
from ... import errors

from ...models.admin_patch_user_required_actions_body import (
    AdminPatchUserRequiredActionsBody,
)
from typing import cast


def _get_kwargs(
    realm_id: str,
    user_id: str,
    *,
    body: AdminPatchUserRequiredActionsBody,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "patch",
        "url": "/admin/realms/{realm_id}/users/{user_id}/required-actions".format(
            realm_id=quote(str(realm_id), safe=""),
            user_id=quote(str(user_id), safe=""),
        ),
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Any | None:
    if response.status_code == 200:
        return None

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[Any]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    realm_id: str,
    user_id: str,
    *,
    client: AuthenticatedClient | Client,
    body: AdminPatchUserRequiredActionsBody,
) -> Response[Any]:
    """Patch required actions for a user

    Args:
        realm_id (str):
        user_id (str):
        body (AdminPatchUserRequiredActionsBody):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any]
    """

    kwargs = _get_kwargs(
        realm_id=realm_id,
        user_id=user_id,
        body=body,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


async def asyncio_detailed(
    realm_id: str,
    user_id: str,
    *,
    client: AuthenticatedClient | Client,
    body: AdminPatchUserRequiredActionsBody,
) -> Response[Any]:
    """Patch required actions for a user

    Args:
        realm_id (str):
        user_id (str):
        body (AdminPatchUserRequiredActionsBody):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any]
    """

    kwargs = _get_kwargs(
        realm_id=realm_id,
        user_id=user_id,
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)
