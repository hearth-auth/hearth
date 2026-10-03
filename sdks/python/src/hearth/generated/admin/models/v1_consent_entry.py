from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, BinaryIO, TextIO, TYPE_CHECKING, Generator

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

from ..types import UNSET, Unset
from typing import cast


T = TypeVar("T", bound="V1ConsentEntry")


@_attrs_define
class V1ConsentEntry:
    """
    Attributes:
        client_id (str | Unset):
        client_name (str | Unset):
        granted_scopes (list[str] | Unset):
        granted_at (str | Unset):
        updated_at (str | Unset):
    """

    client_id: str | Unset = UNSET
    client_name: str | Unset = UNSET
    granted_scopes: list[str] | Unset = UNSET
    granted_at: str | Unset = UNSET
    updated_at: str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        client_id = self.client_id

        client_name = self.client_name

        granted_scopes: list[str] | Unset = UNSET
        if not isinstance(self.granted_scopes, Unset):
            granted_scopes = self.granted_scopes

        granted_at = self.granted_at

        updated_at = self.updated_at

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if client_id is not UNSET:
            field_dict["clientId"] = client_id
        if client_name is not UNSET:
            field_dict["clientName"] = client_name
        if granted_scopes is not UNSET:
            field_dict["grantedScopes"] = granted_scopes
        if granted_at is not UNSET:
            field_dict["grantedAt"] = granted_at
        if updated_at is not UNSET:
            field_dict["updatedAt"] = updated_at

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        client_id = d.pop("clientId", UNSET)

        client_name = d.pop("clientName", UNSET)

        granted_scopes = cast(list[str], d.pop("grantedScopes", UNSET))

        granted_at = d.pop("grantedAt", UNSET)

        updated_at = d.pop("updatedAt", UNSET)

        v1_consent_entry = cls(
            client_id=client_id,
            client_name=client_name,
            granted_scopes=granted_scopes,
            granted_at=granted_at,
            updated_at=updated_at,
        )

        v1_consent_entry.additional_properties = d
        return v1_consent_entry

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
