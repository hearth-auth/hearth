from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, BinaryIO, TextIO, TYPE_CHECKING, Generator

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

from ..types import UNSET, Unset


T = TypeVar("T", bound="RbacAdminServiceUpdateGroupBody")


@_attrs_define
class RbacAdminServiceUpdateGroupBody:
    """
    Attributes:
        realm_id (str | Unset):
        name (str | Unset):
        slug (str | Unset):
        description (str | Unset):
    """

    realm_id: str | Unset = UNSET
    name: str | Unset = UNSET
    slug: str | Unset = UNSET
    description: str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        realm_id = self.realm_id

        name = self.name

        slug = self.slug

        description = self.description

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if realm_id is not UNSET:
            field_dict["realmId"] = realm_id
        if name is not UNSET:
            field_dict["name"] = name
        if slug is not UNSET:
            field_dict["slug"] = slug
        if description is not UNSET:
            field_dict["description"] = description

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        realm_id = d.pop("realmId", UNSET)

        name = d.pop("name", UNSET)

        slug = d.pop("slug", UNSET)

        description = d.pop("description", UNSET)

        rbac_admin_service_update_group_body = cls(
            realm_id=realm_id,
            name=name,
            slug=slug,
            description=description,
        )

        rbac_admin_service_update_group_body.additional_properties = d
        return rbac_admin_service_update_group_body

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
