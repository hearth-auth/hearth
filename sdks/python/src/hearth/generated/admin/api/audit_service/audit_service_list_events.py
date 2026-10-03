from http import HTTPStatus
from typing import Any, cast
from urllib.parse import quote

import httpx

from ...client import AuthenticatedClient, Client
from ...types import Response, UNSET
from ... import errors

from ...models.audit_service_list_events_action import AuditServiceListEventsAction
from ...models.rpc_status import RpcStatus
from ...models.v1_audit_event_page import V1AuditEventPage
from ...types import UNSET, Unset
from typing import cast


def _get_kwargs(
    *,
    realm_id: str | Unset = UNSET,
    start_time: str | Unset = UNSET,
    end_time: str | Unset = UNSET,
    actor: str | Unset = UNSET,
    action: AuditServiceListEventsAction
    | Unset = AuditServiceListEventsAction.AUDIT_ACTION_UNSPECIFIED,
    limit: int | Unset = UNSET,
) -> dict[str, Any]:

    params: dict[str, Any] = {}

    params["realmId"] = realm_id

    params["startTime"] = start_time

    params["endTime"] = end_time

    params["actor"] = actor

    json_action: str | Unset = UNSET
    if not isinstance(action, Unset):
        json_action = action.value

    params["action"] = json_action

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
) -> RpcStatus | V1AuditEventPage:
    if response.status_code == 200:
        response_200 = V1AuditEventPage.from_dict(response.json())

        return response_200

    response_default = RpcStatus.from_dict(response.json())

    return response_default


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[RpcStatus | V1AuditEventPage]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient | Client,
    realm_id: str | Unset = UNSET,
    start_time: str | Unset = UNSET,
    end_time: str | Unset = UNSET,
    actor: str | Unset = UNSET,
    action: AuditServiceListEventsAction
    | Unset = AuditServiceListEventsAction.AUDIT_ACTION_UNSPECIFIED,
    limit: int | Unset = UNSET,
) -> Response[RpcStatus | V1AuditEventPage]:
    """Query audit events with optional filters. Maps to GET /admin/audit.

    Args:
        realm_id (str | Unset):
        start_time (str | Unset):
        end_time (str | Unset):
        actor (str | Unset):
        action (AuditServiceListEventsAction | Unset):  Default:
            AuditServiceListEventsAction.AUDIT_ACTION_UNSPECIFIED.
        limit (int | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[RpcStatus | V1AuditEventPage]
    """

    kwargs = _get_kwargs(
        realm_id=realm_id,
        start_time=start_time,
        end_time=end_time,
        actor=actor,
        action=action,
        limit=limit,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient | Client,
    realm_id: str | Unset = UNSET,
    start_time: str | Unset = UNSET,
    end_time: str | Unset = UNSET,
    actor: str | Unset = UNSET,
    action: AuditServiceListEventsAction
    | Unset = AuditServiceListEventsAction.AUDIT_ACTION_UNSPECIFIED,
    limit: int | Unset = UNSET,
) -> RpcStatus | V1AuditEventPage | None:
    """Query audit events with optional filters. Maps to GET /admin/audit.

    Args:
        realm_id (str | Unset):
        start_time (str | Unset):
        end_time (str | Unset):
        actor (str | Unset):
        action (AuditServiceListEventsAction | Unset):  Default:
            AuditServiceListEventsAction.AUDIT_ACTION_UNSPECIFIED.
        limit (int | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        RpcStatus | V1AuditEventPage
    """

    return sync_detailed(
        client=client,
        realm_id=realm_id,
        start_time=start_time,
        end_time=end_time,
        actor=actor,
        action=action,
        limit=limit,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient | Client,
    realm_id: str | Unset = UNSET,
    start_time: str | Unset = UNSET,
    end_time: str | Unset = UNSET,
    actor: str | Unset = UNSET,
    action: AuditServiceListEventsAction
    | Unset = AuditServiceListEventsAction.AUDIT_ACTION_UNSPECIFIED,
    limit: int | Unset = UNSET,
) -> Response[RpcStatus | V1AuditEventPage]:
    """Query audit events with optional filters. Maps to GET /admin/audit.

    Args:
        realm_id (str | Unset):
        start_time (str | Unset):
        end_time (str | Unset):
        actor (str | Unset):
        action (AuditServiceListEventsAction | Unset):  Default:
            AuditServiceListEventsAction.AUDIT_ACTION_UNSPECIFIED.
        limit (int | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[RpcStatus | V1AuditEventPage]
    """

    kwargs = _get_kwargs(
        realm_id=realm_id,
        start_time=start_time,
        end_time=end_time,
        actor=actor,
        action=action,
        limit=limit,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient | Client,
    realm_id: str | Unset = UNSET,
    start_time: str | Unset = UNSET,
    end_time: str | Unset = UNSET,
    actor: str | Unset = UNSET,
    action: AuditServiceListEventsAction
    | Unset = AuditServiceListEventsAction.AUDIT_ACTION_UNSPECIFIED,
    limit: int | Unset = UNSET,
) -> RpcStatus | V1AuditEventPage | None:
    """Query audit events with optional filters. Maps to GET /admin/audit.

    Args:
        realm_id (str | Unset):
        start_time (str | Unset):
        end_time (str | Unset):
        actor (str | Unset):
        action (AuditServiceListEventsAction | Unset):  Default:
            AuditServiceListEventsAction.AUDIT_ACTION_UNSPECIFIED.
        limit (int | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        RpcStatus | V1AuditEventPage
    """

    return (
        await asyncio_detailed(
            client=client,
            realm_id=realm_id,
            start_time=start_time,
            end_time=end_time,
            actor=actor,
            action=action,
            limit=limit,
        )
    ).parsed
