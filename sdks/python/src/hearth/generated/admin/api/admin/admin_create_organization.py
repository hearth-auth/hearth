from http import HTTPStatus
from typing import Any, cast
from urllib.parse import quote

import httpx

from ...client import AuthenticatedClient, Client
from ...types import Response, UNSET
from ... import errors

from ...models.admin_create_organization_request import AdminCreateOrganizationRequest
from ...models.admin_organization import AdminOrganization
from typing import cast


def _get_kwargs(
    *,
    body: AdminCreateOrganizationRequest,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/admin/organizations",
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> AdminOrganization | Any | None:
    if response.status_code == 201:
        response_201 = AdminOrganization.from_dict(response.json())

        return response_201

    if response.status_code == 403:
        response_403 = cast(Any, None)
        return response_403

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[AdminOrganization | Any]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient | Client,
    body: AdminCreateOrganizationRequest,
) -> Response[AdminOrganization | Any]:
    """Create an organization

     Requires `hearth.realm.admin`. Body: `{slug, display_name, member_limit?, mfa_required?,
    attributes?}`. `mfa_required` (default `false`) makes members need MFA even where the realm does
    not; it can only tighten. Refused in the system realm.

    Args:
        body (AdminCreateOrganizationRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[AdminOrganization | Any]
    """

    kwargs = _get_kwargs(
        body=body,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient | Client,
    body: AdminCreateOrganizationRequest,
) -> AdminOrganization | Any | None:
    """Create an organization

     Requires `hearth.realm.admin`. Body: `{slug, display_name, member_limit?, mfa_required?,
    attributes?}`. `mfa_required` (default `false`) makes members need MFA even where the realm does
    not; it can only tighten. Refused in the system realm.

    Args:
        body (AdminCreateOrganizationRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        AdminOrganization | Any
    """

    return sync_detailed(
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient | Client,
    body: AdminCreateOrganizationRequest,
) -> Response[AdminOrganization | Any]:
    """Create an organization

     Requires `hearth.realm.admin`. Body: `{slug, display_name, member_limit?, mfa_required?,
    attributes?}`. `mfa_required` (default `false`) makes members need MFA even where the realm does
    not; it can only tighten. Refused in the system realm.

    Args:
        body (AdminCreateOrganizationRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[AdminOrganization | Any]
    """

    kwargs = _get_kwargs(
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient | Client,
    body: AdminCreateOrganizationRequest,
) -> AdminOrganization | Any | None:
    """Create an organization

     Requires `hearth.realm.admin`. Body: `{slug, display_name, member_limit?, mfa_required?,
    attributes?}`. `mfa_required` (default `false`) makes members need MFA even where the realm does
    not; it can only tighten. Refused in the system realm.

    Args:
        body (AdminCreateOrganizationRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        AdminOrganization | Any
    """

    return (
        await asyncio_detailed(
            client=client,
            body=body,
        )
    ).parsed
