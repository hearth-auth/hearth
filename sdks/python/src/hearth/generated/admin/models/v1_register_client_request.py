from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, BinaryIO, TextIO, TYPE_CHECKING, Generator

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

from ..models.v1_access_token_authorization import V1AccessTokenAuthorization
from ..models.v1_client_trust_level import V1ClientTrustLevel
from ..models.v1_register_client_request_token_endpoint_auth_method import (
    V1RegisterClientRequestTokenEndpointAuthMethod,
)
from ..types import UNSET, Unset
from typing import cast


T = TypeVar("T", bound="V1RegisterClientRequest")


@_attrs_define
class V1RegisterClientRequest:
    """Request to register a new OAuth 2.0 client.

    Attributes:
        client_name (str | Unset):
        redirect_uris (list[str] | Unset):
        client_secret (str | Unset): Not accepted on the admin create paths (REST and gRPC refuse it): Hearth
            generates client secrets. Request one with token_endpoint_auth_method.
        grant_types (list[str] | Unset):
        access_token_authorization (V1AccessTokenAuthorization | Unset): Controls how access-token authorization data is
            exposed to resource servers.

             - EMBEDDED: Permissions, roles, and groups are embedded in the JWT at issuance (default).
             - INTROSPECTION: JWT carries only identity claims; resource servers call /introspect.
             - DECISION: JWT carries only identity claims; resource servers call POST /oauth/authorize.
        trust_level (V1ClientTrustLevel | Unset): Controls whether a client is trusted as a first-party application.

            FirstParty clients skip the consent screen and receive the full
            `permissions`, `roles`, and `groups` claims in issued JWTs.  ThirdParty
            clients are shown the consent screen and do not receive those claims.
            Unspecified defaults to ThirdParty on the DCR path; on the authenticated
            admin path the caller must pass FIRST_PARTY explicitly to grant first-party
            trust.
        id_token_signed_response_alg (str | Unset): JWS algorithm for this client's ID tokens (OIDC Dynamic Client
            Registration 1.0 s2): "RS256" or "EdDSA"; anything else is rejected.
            Omitted means RS256 on the dynamic registration path (the OIDC default)
            and EdDSA on the authenticated admin path. Only ID tokens are affected;
            access and refresh tokens are always EdDSA.
        token_endpoint_auth_method (V1RegisterClientRequestTokenEndpointAuthMethod | Unset): How the client
            authenticates at the token endpoint (RFC 7591 s2):
            "client_secret_basic", "client_secret_post", "private_key_jwt" or "none".
            On the authenticated admin create paths (POST /admin/applications,
            POST /clients, gRPC CreateApplication and RegisterClient) a
            "client_secret_*" value creates a confidential client whose secret Hearth
            generates (256 bits from the OS CSPRNG) and returns exactly once, in the
            response's client_secret. Only a hash is stored. "private_key_jwt"
            requires jwks. Omitted or "none" registers a public client (or a
            private_key_jwt client when jwks is given).
    """

    client_name: str | Unset = UNSET
    redirect_uris: list[str] | Unset = UNSET
    client_secret: str | Unset = UNSET
    grant_types: list[str] | Unset = UNSET
    access_token_authorization: V1AccessTokenAuthorization | Unset = UNSET
    trust_level: V1ClientTrustLevel | Unset = UNSET
    id_token_signed_response_alg: str | Unset = UNSET
    token_endpoint_auth_method: (
        V1RegisterClientRequestTokenEndpointAuthMethod | Unset
    ) = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        client_name = self.client_name

        redirect_uris: list[str] | Unset = UNSET
        if not isinstance(self.redirect_uris, Unset):
            redirect_uris = self.redirect_uris

        client_secret = self.client_secret

        grant_types: list[str] | Unset = UNSET
        if not isinstance(self.grant_types, Unset):
            grant_types = self.grant_types

        access_token_authorization: str | Unset = UNSET
        if not isinstance(self.access_token_authorization, Unset):
            access_token_authorization = self.access_token_authorization.value

        trust_level: str | Unset = UNSET
        if not isinstance(self.trust_level, Unset):
            trust_level = self.trust_level.value

        id_token_signed_response_alg = self.id_token_signed_response_alg

        token_endpoint_auth_method: str | Unset = UNSET
        if not isinstance(self.token_endpoint_auth_method, Unset):
            token_endpoint_auth_method = self.token_endpoint_auth_method.value

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if client_name is not UNSET:
            field_dict["clientName"] = client_name
        if redirect_uris is not UNSET:
            field_dict["redirectUris"] = redirect_uris
        if client_secret is not UNSET:
            field_dict["clientSecret"] = client_secret
        if grant_types is not UNSET:
            field_dict["grantTypes"] = grant_types
        if access_token_authorization is not UNSET:
            field_dict["accessTokenAuthorization"] = access_token_authorization
        if trust_level is not UNSET:
            field_dict["trustLevel"] = trust_level
        if id_token_signed_response_alg is not UNSET:
            field_dict["id_token_signed_response_alg"] = id_token_signed_response_alg
        if token_endpoint_auth_method is not UNSET:
            field_dict["token_endpoint_auth_method"] = token_endpoint_auth_method

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        client_name = d.pop("clientName", UNSET)

        redirect_uris = cast(list[str], d.pop("redirectUris", UNSET))

        client_secret = d.pop("clientSecret", UNSET)

        grant_types = cast(list[str], d.pop("grantTypes", UNSET))

        _access_token_authorization = d.pop("accessTokenAuthorization", UNSET)
        access_token_authorization: V1AccessTokenAuthorization | Unset
        if isinstance(_access_token_authorization, Unset):
            access_token_authorization = UNSET
        else:
            access_token_authorization = V1AccessTokenAuthorization(
                _access_token_authorization
            )

        _trust_level = d.pop("trustLevel", UNSET)
        trust_level: V1ClientTrustLevel | Unset
        if isinstance(_trust_level, Unset):
            trust_level = UNSET
        else:
            trust_level = V1ClientTrustLevel(_trust_level)

        id_token_signed_response_alg = d.pop("id_token_signed_response_alg", UNSET)

        _token_endpoint_auth_method = d.pop("token_endpoint_auth_method", UNSET)
        token_endpoint_auth_method: (
            V1RegisterClientRequestTokenEndpointAuthMethod | Unset
        )
        if isinstance(_token_endpoint_auth_method, Unset):
            token_endpoint_auth_method = UNSET
        else:
            token_endpoint_auth_method = V1RegisterClientRequestTokenEndpointAuthMethod(
                _token_endpoint_auth_method
            )

        v1_register_client_request = cls(
            client_name=client_name,
            redirect_uris=redirect_uris,
            client_secret=client_secret,
            grant_types=grant_types,
            access_token_authorization=access_token_authorization,
            trust_level=trust_level,
            id_token_signed_response_alg=id_token_signed_response_alg,
            token_endpoint_auth_method=token_endpoint_auth_method,
        )

        v1_register_client_request.additional_properties = d
        return v1_register_client_request

    @property
    def additional_keys(self) -> list[str]:
        return list(self.additional_properties.keys())

    def __getitem__(self, key: str) -> Any:
        return self.additional_properties[key]

    def __setitem__(self, key: str, value: Any) -> None:
        self.additional_properties[key] = value

    def __delitem__(self, key: str) -> None:
        del self.additional_properties[key]

    def __contains__(self, key: str) -> bool:
        return key in self.additional_properties
