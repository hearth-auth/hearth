from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, BinaryIO, TextIO, TYPE_CHECKING, Generator

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

from ..models.v1_access_token_authorization import V1AccessTokenAuthorization
from ..types import UNSET, Unset
from typing import cast


T = TypeVar("T", bound="V1OAuthClient")


@_attrs_define
class V1OAuthClient:
    """A registered OAuth 2.0 client.

    Attributes:
        client_id (str | Unset):
        client_name (str | Unset):
        redirect_uris (list[str] | Unset):
        created_at (int | Unset):
        is_confidential (bool | Unset):
        grant_types (list[str] | Unset):
        access_token_authorization (V1AccessTokenAuthorization | Unset): Controls how access-token authorization data is
            exposed to resource servers.

             - EMBEDDED: Permissions, roles, and groups are embedded in the JWT at issuance (default).
             - INTROSPECTION: JWT carries only identity claims; resource servers call /introspect.
             - DECISION: JWT carries only identity claims; resource servers call POST /oauth/authorize.
        id_token_signed_response_alg (str | Unset): The algorithm this client's ID tokens are signed with: "RS256" or
            "EdDSA".
        client_secret (str | Unset): The client secret Hearth generated for a confidential client. Present
            only in the response that created the client (token_endpoint_auth_method
            "client_secret_basic" or "client_secret_post"); never returned again.
            Store it on receipt: Hearth keeps only its hash. Also set, once, by
            RegenerateApplicationSecret.
        dpop_bound_access_tokens (bool | Unset): RFC 9449 s5.2: when true, every token request from this client must
            carry
            a DPoP proof, and every token it gets is bound to the proof's key.
    """

    client_id: str | Unset = UNSET
    client_name: str | Unset = UNSET
    redirect_uris: list[str] | Unset = UNSET
    created_at: int | Unset = UNSET
    is_confidential: bool | Unset = UNSET
    grant_types: list[str] | Unset = UNSET
    access_token_authorization: V1AccessTokenAuthorization | Unset = UNSET
    id_token_signed_response_alg: str | Unset = UNSET
    client_secret: str | Unset = UNSET
    dpop_bound_access_tokens: bool | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        client_id = self.client_id

        client_name = self.client_name

        redirect_uris: list[str] | Unset = UNSET
        if not isinstance(self.redirect_uris, Unset):
            redirect_uris = self.redirect_uris

        created_at = self.created_at

        is_confidential = self.is_confidential

        grant_types: list[str] | Unset = UNSET
        if not isinstance(self.grant_types, Unset):
            grant_types = self.grant_types

        access_token_authorization: str | Unset = UNSET
        if not isinstance(self.access_token_authorization, Unset):
            access_token_authorization = self.access_token_authorization.value

        id_token_signed_response_alg = self.id_token_signed_response_alg

        client_secret = self.client_secret

        dpop_bound_access_tokens = self.dpop_bound_access_tokens

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if client_id is not UNSET:
            field_dict["client_id"] = client_id
        if client_name is not UNSET:
            field_dict["client_name"] = client_name
        if redirect_uris is not UNSET:
            field_dict["redirect_uris"] = redirect_uris
        if created_at is not UNSET:
            field_dict["created_at"] = created_at
        if is_confidential is not UNSET:
            field_dict["is_confidential"] = is_confidential
        if grant_types is not UNSET:
            field_dict["grant_types"] = grant_types
        if access_token_authorization is not UNSET:
            field_dict["access_token_authorization"] = access_token_authorization
        if id_token_signed_response_alg is not UNSET:
            field_dict["id_token_signed_response_alg"] = id_token_signed_response_alg
        if client_secret is not UNSET:
            field_dict["client_secret"] = client_secret
        if dpop_bound_access_tokens is not UNSET:
            field_dict["dpop_bound_access_tokens"] = dpop_bound_access_tokens

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        client_id = d.pop("client_id", UNSET)

        client_name = d.pop("client_name", UNSET)

        redirect_uris = cast(list[str], d.pop("redirect_uris", UNSET))

        created_at = d.pop("created_at", UNSET)

        is_confidential = d.pop("is_confidential", UNSET)

        grant_types = cast(list[str], d.pop("grant_types", UNSET))

        _access_token_authorization = d.pop("access_token_authorization", UNSET)
        access_token_authorization: V1AccessTokenAuthorization | Unset
        if isinstance(_access_token_authorization, Unset):
            access_token_authorization = UNSET
        else:
            access_token_authorization = V1AccessTokenAuthorization(
                _access_token_authorization
            )

        id_token_signed_response_alg = d.pop("id_token_signed_response_alg", UNSET)

        client_secret = d.pop("client_secret", UNSET)

        dpop_bound_access_tokens = d.pop("dpop_bound_access_tokens", UNSET)

        v1o_auth_client = cls(
            client_id=client_id,
            client_name=client_name,
            redirect_uris=redirect_uris,
            created_at=created_at,
            is_confidential=is_confidential,
            grant_types=grant_types,
            access_token_authorization=access_token_authorization,
            id_token_signed_response_alg=id_token_signed_response_alg,
            client_secret=client_secret,
            dpop_bound_access_tokens=dpop_bound_access_tokens,
        )

        v1o_auth_client.additional_properties = d
        return v1o_auth_client

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
