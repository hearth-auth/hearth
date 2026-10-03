from http import HTTPStatus
from typing import Any, cast
from urllib.parse import quote

import httpx

from ...client import AuthenticatedClient, Client
from ...types import Response, UNSET
from ... import errors

from ...models.admin_audit_event_list import AdminAuditEventList
from ...types import UNSET, Unset
from typing import cast


def _get_kwargs(
    *,
    actor: str | Unset = UNSET,
    action: str | Unset = UNSET,
    start_time: int | Unset = UNSET,
    end_time: int | Unset = UNSET,
    limit: int | Unset = UNSET,
) -> dict[str, Any]:

    params: dict[str, Any] = {}

    params["actor"] = actor

    params["action"] = action

    params["start_time"] = start_time

    params["end_time"] = end_time

    params["limit"] = limit

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/admin/audit",
        "params": params,
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> AdminAuditEventList | Any | None:
    if response.status_code == 200:
        response_200 = AdminAuditEventList.from_dict(response.json())

        return response_200

    if response.status_code == 400:
        response_400 = cast(Any, None)
        return response_400

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[AdminAuditEventList | Any]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient | Client,
    actor: str | Unset = UNSET,
    action: str | Unset = UNSET,
    start_time: int | Unset = UNSET,
    end_time: int | Unset = UNSET,
    limit: int | Unset = UNSET,
) -> Response[AdminAuditEventList | Any]:
    """List audit events

     Requires `hearth.realm.admin`. Newest first.

    Args:
        actor (str | Unset):
        action (str | Unset):
        start_time (int | Unset):
        end_time (int | Unset):
        limit (int | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[AdminAuditEventList | Any]
    """

    kwargs = _get_kwargs(
        actor=actor,
        action=action,
        start_time=start_time,
        end_time=end_time,
        limit=limit,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient | Client,
    actor: str | Unset = UNSET,
    action: str | Unset = UNSET,
    start_time: int | Unset = UNSET,
    end_time: int | Unset = UNSET,
    limit: int | Unset = UNSET,
) -> AdminAuditEventList | Any | None:
    """List audit events

     Requires `hearth.realm.admin`. Newest first.

    Args:
        actor (str | Unset):
        action (str | Unset):
        start_time (int | Unset):
        end_time (int | Unset):
        limit (int | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        AdminAuditEventList | Any
    """

    return sync_detailed(
        client=client,
        actor=actor,
        action=action,
        start_time=start_time,
        end_time=end_time,
        limit=limit,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient | Client,
    actor: str | Unset = UNSET,
    action: str | Unset = UNSET,
    start_time: int | Unset = UNSET,
    end_time: int | Unset = UNSET,
    limit: int | Unset = UNSET,
) -> Response[AdminAuditEventList | Any]:
    """List audit events

     Requires `hearth.realm.admin`. Newest first.

    Args:
        actor (str | Unset):
        action (str | Unset):
        start_time (int | Unset):
        end_time (int | Unset):
        limit (int | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[AdminAuditEventList | Any]
    """

    kwargs = _get_kwargs(
        actor=actor,
        action=action,
        start_time=start_time,
        end_time=end_time,
        limit=limit,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient | Client,
    actor: str | Unset = UNSET,
    action: str | Unset = UNSET,
    start_time: int | Unset = UNSET,
    end_time: int | Unset = UNSET,
    limit: int | Unset = UNSET,
) -> AdminAuditEventList | Any | None:
    """List audit events

     Requires `hearth.realm.admin`. Newest first.

    Args:
        actor (str | Unset):
        action (str | Unset):
        start_time (int | Unset):
        end_time (int | Unset):
        limit (int | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        AdminAuditEventList | Any
    """

    return (
        await asyncio_detailed(
            client=client,
            actor=actor,
            action=action,
            start_time=start_time,
            end_time=end_time,
            limit=limit,
        )
    ).parsed
