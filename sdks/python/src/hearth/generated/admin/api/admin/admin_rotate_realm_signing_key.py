from http import HTTPStatus
from typing import Any, cast
from urllib.parse import quote

import httpx

from ...client import AuthenticatedClient, Client
from ...types import Response, UNSET
from ... import errors

from ...types import UNSET, Unset


def _get_kwargs(
    id: str,
    *,
    grace_period_secs: int | Unset = 0,
) -> dict[str, Any]:

    params: dict[str, Any] = {}

    params["grace_period_secs"] = grace_period_secs

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/admin/realms/{id}/rotate-signing-key".format(
            id=quote(str(id), safe=""),
        ),
        "params": params,
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Any | None:
    if response.status_code == 200:
        return None

    if response.status_code == 400:
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
    id: str,
    *,
    client: AuthenticatedClient | Client,
    grace_period_secs: int | Unset = 0,
) -> Response[Any]:
    """Rotate the realm's Ed25519 signing key

     Publishes a new signing key and revokes every retired key for the realm. Tokens signed with the old
    key stop validating immediately, which is what makes this a usable remedy for a leaked key. A
    planned rotation may opt into a grace window with `grace_period_secs`; do not use it after a
    compromise, because the window protects whoever holds the leaked key too.

    Args:
        id (str):
        grace_period_secs (int | Unset):  Default: 0.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any]
    """

    kwargs = _get_kwargs(
        id=id,
        grace_period_secs=grace_period_secs,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


async def asyncio_detailed(
    id: str,
    *,
    client: AuthenticatedClient | Client,
    grace_period_secs: int | Unset = 0,
) -> Response[Any]:
    """Rotate the realm's Ed25519 signing key

     Publishes a new signing key and revokes every retired key for the realm. Tokens signed with the old
    key stop validating immediately, which is what makes this a usable remedy for a leaked key. A
    planned rotation may opt into a grace window with `grace_period_secs`; do not use it after a
    compromise, because the window protects whoever holds the leaked key too.

    Args:
        id (str):
        grace_period_secs (int | Unset):  Default: 0.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any]
    """

    kwargs = _get_kwargs(
        id=id,
        grace_period_secs=grace_period_secs,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)
