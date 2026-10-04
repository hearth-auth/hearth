from http import HTTPStatus
from typing import Any, cast
from urllib.parse import quote

import httpx

from ...client import AuthenticatedClient, Client
from ...types import Response, UNSET
from ... import errors

from ...models.rpc_status import RpcStatus
from ...models.v1o_auth_client import V1OAuthClient
from typing import cast


def _get_kwargs(
    client_id: str,
) -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/admin/applications/{client_id}/regenerate-secret".format(
            client_id=quote(str(client_id), safe=""),
        ),
    }

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
) -> Response[RpcStatus | V1OAuthClient]:
    """Replaces a confidential client's secret with a new Hearth-generated one
    (256 bits from the OS CSPRNG, stored only as a hash). The new secret is
    returned once, in the response's client_secret; the old one stops
    authenticating at once. Refused for a public client. Audited.

    Args:
        client_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[RpcStatus | V1OAuthClient]
    """

    kwargs = _get_kwargs(
        client_id=client_id,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    client_id: str,
    *,
    client: AuthenticatedClient | Client,
) -> RpcStatus | V1OAuthClient | None:
    """Replaces a confidential client's secret with a new Hearth-generated one
    (256 bits from the OS CSPRNG, stored only as a hash). The new secret is
    returned once, in the response's client_secret; the old one stops
    authenticating at once. Refused for a public client. Audited.

    Args:
        client_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        RpcStatus | V1OAuthClient
    """

    return sync_detailed(
        client_id=client_id,
        client=client,
    ).parsed


async def asyncio_detailed(
    client_id: str,
    *,
    client: AuthenticatedClient | Client,
) -> Response[RpcStatus | V1OAuthClient]:
    """Replaces a confidential client's secret with a new Hearth-generated one
    (256 bits from the OS CSPRNG, stored only as a hash). The new secret is
    returned once, in the response's client_secret; the old one stops
    authenticating at once. Refused for a public client. Audited.

    Args:
        client_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[RpcStatus | V1OAuthClient]
    """

    kwargs = _get_kwargs(
        client_id=client_id,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    client_id: str,
    *,
    client: AuthenticatedClient | Client,
) -> RpcStatus | V1OAuthClient | None:
    """Replaces a confidential client's secret with a new Hearth-generated one
    (256 bits from the OS CSPRNG, stored only as a hash). The new secret is
    returned once, in the response's client_secret; the old one stops
    authenticating at once. Refused for a public client. Audited.

    Args:
        client_id (str):

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
        )
    ).parsed
