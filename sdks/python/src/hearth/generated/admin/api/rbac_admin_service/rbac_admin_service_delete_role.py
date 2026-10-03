from http import HTTPStatus
from typing import Any, cast
from urllib.parse import quote

import httpx

from ...client import AuthenticatedClient, Client
from ...types import Response, UNSET
from ... import errors

from ...models.rpc_status import RpcStatus
from ...models.v1_delete_role_response import V1DeleteRoleResponse
from ...types import UNSET, Unset
from typing import cast


def _get_kwargs(
    role_id: str,
    *,
    realm_id: str | Unset = UNSET,
    cascade: bool | Unset = UNSET,
) -> dict[str, Any]:

    params: dict[str, Any] = {}

    params["realmId"] = realm_id

    params["cascade"] = cascade

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "delete",
        "url": "/admin/roles/{role_id}".format(
            role_id=quote(str(role_id), safe=""),
        ),
        "params": params,
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> RpcStatus | V1DeleteRoleResponse:
    if response.status_code == 200:
        response_200 = V1DeleteRoleResponse.from_dict(response.json())

        return response_200

    response_default = RpcStatus.from_dict(response.json())

    return response_default


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[RpcStatus | V1DeleteRoleResponse]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    role_id: str,
    *,
    client: AuthenticatedClient | Client,
    realm_id: str | Unset = UNSET,
    cascade: bool | Unset = UNSET,
) -> Response[RpcStatus | V1DeleteRoleResponse]:
    """
    Args:
        role_id (str):
        realm_id (str | Unset):
        cascade (bool | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[RpcStatus | V1DeleteRoleResponse]
    """

    kwargs = _get_kwargs(
        role_id=role_id,
        realm_id=realm_id,
        cascade=cascade,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    role_id: str,
    *,
    client: AuthenticatedClient | Client,
    realm_id: str | Unset = UNSET,
    cascade: bool | Unset = UNSET,
) -> RpcStatus | V1DeleteRoleResponse | None:
    """
    Args:
        role_id (str):
        realm_id (str | Unset):
        cascade (bool | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        RpcStatus | V1DeleteRoleResponse
    """

    return sync_detailed(
        role_id=role_id,
        client=client,
        realm_id=realm_id,
        cascade=cascade,
    ).parsed


async def asyncio_detailed(
    role_id: str,
    *,
    client: AuthenticatedClient | Client,
    realm_id: str | Unset = UNSET,
    cascade: bool | Unset = UNSET,
) -> Response[RpcStatus | V1DeleteRoleResponse]:
    """
    Args:
        role_id (str):
        realm_id (str | Unset):
        cascade (bool | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[RpcStatus | V1DeleteRoleResponse]
    """

    kwargs = _get_kwargs(
        role_id=role_id,
        realm_id=realm_id,
        cascade=cascade,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    role_id: str,
    *,
    client: AuthenticatedClient | Client,
    realm_id: str | Unset = UNSET,
    cascade: bool | Unset = UNSET,
) -> RpcStatus | V1DeleteRoleResponse | None:
    """
    Args:
        role_id (str):
        realm_id (str | Unset):
        cascade (bool | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        RpcStatus | V1DeleteRoleResponse
    """

    return (
        await asyncio_detailed(
            role_id=role_id,
            client=client,
            realm_id=realm_id,
            cascade=cascade,
        )
    ).parsed
