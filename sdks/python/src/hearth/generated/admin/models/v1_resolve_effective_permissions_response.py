from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, BinaryIO, TextIO, TYPE_CHECKING, Generator

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

from ..types import UNSET, Unset
from typing import cast


T = TypeVar("T", bound="V1ResolveEffectivePermissionsResponse")


@_attrs_define
class V1ResolveEffectivePermissionsResponse:
    """
    Attributes:
        roles (list[str] | Unset):
        groups (list[str] | Unset):
        permissions (list[str] | Unset):
    """

    roles: list[str] | Unset = UNSET
    groups: list[str] | Unset = UNSET
    permissions: list[str] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        roles: list[str] | Unset = UNSET
        if not isinstance(self.roles, Unset):
            roles = self.roles

        groups: list[str] | Unset = UNSET
        if not isinstance(self.groups, Unset):
            groups = self.groups

        permissions: list[str] | Unset = UNSET
        if not isinstance(self.permissions, Unset):
            permissions = self.permissions

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if roles is not UNSET:
            field_dict["roles"] = roles
        if groups is not UNSET:
            field_dict["groups"] = groups
        if permissions is not UNSET:
            field_dict["permissions"] = permissions

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        roles = cast(list[str], d.pop("roles", UNSET))

        groups = cast(list[str], d.pop("groups", UNSET))

        permissions = cast(list[str], d.pop("permissions", UNSET))

        v1_resolve_effective_permissions_response = cls(
            roles=roles,
            groups=groups,
            permissions=permissions,
        )

        v1_resolve_effective_permissions_response.additional_properties = d
        return v1_resolve_effective_permissions_response

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
