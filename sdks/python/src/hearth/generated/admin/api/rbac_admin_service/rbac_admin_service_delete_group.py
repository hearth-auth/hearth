from http import HTTPStatus
from typing import Any, cast
from urllib.parse import quote

import httpx

from ...client import AuthenticatedClient, Client
from ...types import Response, UNSET
from ... import errors

from ...models.rpc_status import RpcStatus
from ...models.v1_delete_group_response import V1DeleteGroupResponse
from ...types import UNSET, Unset
from typing import cast


def _get_kwargs(
    group_id: str,
    *,
    realm_id: str | Unset = UNSET,
) -> dict[str, Any]:

    params: dict[str, Any] = {}

    params["realmId"] = realm_id

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "delete",
        "url": "/admin/groups/{group_id}".format(
            group_id=quote(str(group_id), safe=""),
        ),
        "params": params,
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> RpcStatus | V1DeleteGroupResponse:
    if response.status_code == 200:
        response_200 = V1DeleteGroupResponse.from_dict(response.json())

        return response_200

    response_default = RpcStatus.from_dict(response.json())

    return response_default


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[RpcStatus | V1DeleteGroupResponse]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    group_id: str,
    *,
    client: AuthenticatedClient | Client,
    realm_id: str | Unset = UNSET,
) -> Response[RpcStatus | V1DeleteGroupResponse]:
    """
    Args:
        group_id (str):
        realm_id (str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[RpcStatus | V1DeleteGroupResponse]
    """

    kwargs = _get_kwargs(
        group_id=group_id,
        realm_id=realm_id,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    group_id: str,
    *,
    client: AuthenticatedClient | Client,
    realm_id: str | Unset = UNSET,
) -> RpcStatus | V1DeleteGroupResponse | None:
    """
    Args:
        group_id (str):
        realm_id (str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        RpcStatus | V1DeleteGroupResponse
    """

    return sync_detailed(
        group_id=group_id,
        client=client,
        realm_id=realm_id,
    ).parsed


async def asyncio_detailed(
    group_id: str,
    *,
    client: AuthenticatedClient | Client,
    realm_id: str | Unset = UNSET,
) -> Response[RpcStatus | V1DeleteGroupResponse]:
    """
    Args:
        group_id (str):
        realm_id (str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[RpcStatus | V1DeleteGroupResponse]
    """

    kwargs = _get_kwargs(
        group_id=group_id,
        realm_id=realm_id,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    group_id: str,
    *,
    client: AuthenticatedClient | Client,
    realm_id: str | Unset = UNSET,
) -> RpcStatus | V1DeleteGroupResponse | None:
    """
    Args:
        group_id (str):
        realm_id (str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        RpcStatus | V1DeleteGroupResponse
    """

    return (
        await asyncio_detailed(
            group_id=group_id,
            client=client,
            realm_id=realm_id,
        )
    ).parsed
