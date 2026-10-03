from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, BinaryIO, TextIO, TYPE_CHECKING, Generator

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

from ..types import UNSET, Unset
from typing import cast


T = TypeVar("T", bound="V1CreateRoleRequest")


@_attrs_define
class V1CreateRoleRequest:
    """
    Attributes:
        realm_id (str | Unset):
        name (str | Unset):
        description (str | Unset):
        permissions (list[str] | Unset):
        parent_role_ids (list[str] | Unset):
    """

    realm_id: str | Unset = UNSET
    name: str | Unset = UNSET
    description: str | Unset = UNSET
    permissions: list[str] | Unset = UNSET
    parent_role_ids: list[str] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        realm_id = self.realm_id

        name = self.name

        description = self.description

        permissions: list[str] | Unset = UNSET
        if not isinstance(self.permissions, Unset):
            permissions = self.permissions

        parent_role_ids: list[str] | Unset = UNSET
        if not isinstance(self.parent_role_ids, Unset):
            parent_role_ids = self.parent_role_ids

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if realm_id is not UNSET:
            field_dict["realmId"] = realm_id
        if name is not UNSET:
            field_dict["name"] = name
        if description is not UNSET:
            field_dict["description"] = description
        if permissions is not UNSET:
            field_dict["permissions"] = permissions
        if parent_role_ids is not UNSET:
            field_dict["parentRoleIds"] = parent_role_ids

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        realm_id = d.pop("realmId", UNSET)

        name = d.pop("name", UNSET)

        description = d.pop("description", UNSET)

        permissions = cast(list[str], d.pop("permissions", UNSET))

        parent_role_ids = cast(list[str], d.pop("parentRoleIds", UNSET))

        v1_create_role_request = cls(
            realm_id=realm_id,
            name=name,
            description=description,
            permissions=permissions,
            parent_role_ids=parent_role_ids,
        )

        v1_create_role_request.additional_properties = d
        return v1_create_role_request

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
