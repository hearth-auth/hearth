from http import HTTPStatus
from typing import Any, cast
from urllib.parse import quote

import httpx

from ...client import AuthenticatedClient, Client
from ...types import Response, UNSET
from ... import errors

from ...models.rpc_status import RpcStatus
from ...models.v1_update_client_request import V1UpdateClientRequest
from ...models.v1o_auth_client import V1OAuthClient
from typing import cast


def _get_kwargs(
    client_id: str,
    *,
    body: V1UpdateClientRequest,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "patch",
        "url": "/admin/applications/{client_id}".format(
            client_id=quote(str(client_id), safe=""),
        ),
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> RpcStatus | V1OAuthClient:
    if response.status_code == 200:
        response_200 = V1OAuthClient.from_dict(response.json())

        return response_200

    response_default = RpcStatus.from_dict(response.json())

    return response_default


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[RpcStatus | V1OAuthClient]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    client_id: str,
    *,
    client: AuthenticatedClient | Client,
    body: V1UpdateClientRequest,
) -> Response[RpcStatus | V1OAuthClient]:
    """
    Args:
        client_id (str):
        body (V1UpdateClientRequest): Request to update an existing OAuth 2.0 client.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[RpcStatus | V1OAuthClient]
    """

    kwargs = _get_kwargs(
        client_id=client_id,
        body=body,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    client_id: str,
    *,
    client: AuthenticatedClient | Client,
    body: V1UpdateClientRequest,
) -> RpcStatus | V1OAuthClient | None:
    """
    Args:
        client_id (str):
        body (V1UpdateClientRequest): Request to update an existing OAuth 2.0 client.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        RpcStatus | V1OAuthClient
    """

    return sync_detailed(
        client_id=client_id,
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    client_id: str,
    *,
    client: AuthenticatedClient | Client,
    body: V1UpdateClientRequest,
) -> Response[RpcStatus | V1OAuthClient]:
    """
    Args:
        client_id (str):
        body (V1UpdateClientRequest): Request to update an existing OAuth 2.0 client.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[RpcStatus | V1OAuthClient]
    """

    kwargs = _get_kwargs(
        client_id=client_id,
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    client_id: str,
    *,
    client: AuthenticatedClient | Client,
    body: V1UpdateClientRequest,
) -> RpcStatus | V1OAuthClient | None:
    """
    Args:
        client_id (str):
        body (V1UpdateClientRequest): Request to update an existing OAuth 2.0 client.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        RpcStatus | V1OAuthClient
    """

    return (
        await asyncio_detailed(
            client_id=client_id,
            client=client,
            body=body,
        )
    ).parsed
