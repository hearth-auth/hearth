from http import HTTPStatus
from typing import Any, cast
from urllib.parse import quote

import httpx

from ...client import AuthenticatedClient, Client
from ...types import Response, UNSET
from ... import errors

from ...models.admin_remove_group_member_type import AdminRemoveGroupMemberType
from ...types import UNSET, Unset


def _get_kwargs(
    id: str,
    member_id: str,
    *,
    type_: AdminRemoveGroupMemberType | Unset = AdminRemoveGroupMemberType.USER,
) -> dict[str, Any]:

    params: dict[str, Any] = {}

    json_type_: str | Unset = UNSET
    if not isinstance(type_, Unset):
        json_type_ = type_.value

    params["type"] = json_type_

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "delete",
        "url": "/admin/groups/{id}/members/{member_id}".format(
            id=quote(str(id), safe=""),
            member_id=quote(str(member_id), safe=""),
        ),
        "params": params,
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Any | None:
    if response.status_code == 204:
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
    member_id: str,
    *,
    client: AuthenticatedClient | Client,
    type_: AdminRemoveGroupMemberType | Unset = AdminRemoveGroupMemberType.USER,
) -> Response[Any]:
    """Remove a member from a group

    Args:
        id (str):
        member_id (str):
        type_ (AdminRemoveGroupMemberType | Unset):  Default: AdminRemoveGroupMemberType.USER.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any]
    """

    kwargs = _get_kwargs(
        id=id,
        member_id=member_id,
        type_=type_,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


async def asyncio_detailed(
    id: str,
    member_id: str,
    *,
    client: AuthenticatedClient | Client,
    type_: AdminRemoveGroupMemberType | Unset = AdminRemoveGroupMemberType.USER,
) -> Response[Any]:
    """Remove a member from a group

    Args:
        id (str):
        member_id (str):
        type_ (AdminRemoveGroupMemberType | Unset):  Default: AdminRemoveGroupMemberType.USER.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any]
    """

    kwargs = _get_kwargs(
        id=id,
        member_id=member_id,
        type_=type_,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)
