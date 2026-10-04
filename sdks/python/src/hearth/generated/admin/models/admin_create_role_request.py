from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, BinaryIO, TextIO, TYPE_CHECKING, Generator

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

from ..types import UNSET, Unset
from typing import cast
from uuid import UUID


T = TypeVar("T", bound="AdminCreateRoleRequest")


@_attrs_define
class AdminCreateRoleRequest:
    """
    Attributes:
        name (str):
        description (None | str | Unset):
        permissions (list[str] | Unset):
        parent_roles (list[UUID] | Unset):
    """

    name: str
    description: None | str | Unset = UNSET
    permissions: list[str] | Unset = UNSET
    parent_roles: list[UUID] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        description: None | str | Unset
        if isinstance(self.description, Unset):
            description = UNSET
        else:
            description = self.description

        permissions: list[str] | Unset = UNSET
        if not isinstance(self.permissions, Unset):
            permissions = self.permissions

        parent_roles: list[str] | Unset = UNSET
        if not isinstance(self.parent_roles, Unset):
            parent_roles = []
            for parent_roles_item_data in self.parent_roles:
                parent_roles_item = str(parent_roles_item_data)
                parent_roles.append(parent_roles_item)

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
            }
        )
        if description is not UNSET:
            field_dict["description"] = description
        if permissions is not UNSET:
            field_dict["permissions"] = permissions
        if parent_roles is not UNSET:
            field_dict["parent_roles"] = parent_roles

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        name = d.pop("name")

        def _parse_description(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        description = _parse_description(d.pop("description", UNSET))

        permissions = cast(list[str], d.pop("permissions", UNSET))

        _parent_roles = d.pop("parent_roles", UNSET)
        parent_roles: list[UUID] | Unset = UNSET
        if _parent_roles is not UNSET:
            parent_roles = []
            for parent_roles_item_data in _parent_roles:
                parent_roles_item = UUID(parent_roles_item_data)

                parent_roles.append(parent_roles_item)

        admin_create_role_request = cls(
            name=name,
            description=description,
            permissions=permissions,
            parent_roles=parent_roles,
        )

        admin_create_role_request.additional_properties = d
        return admin_create_role_request

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
