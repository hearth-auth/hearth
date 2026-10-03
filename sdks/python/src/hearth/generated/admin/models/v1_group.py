from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, BinaryIO, TextIO, TYPE_CHECKING, Generator

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

from ..types import UNSET, Unset


T = TypeVar("T", bound="V1Group")


@_attrs_define
class V1Group:
    """
    Attributes:
        id (str | Unset):
        realm_id (str | Unset):
        name (str | Unset):
        slug (str | Unset):
        description (str | Unset):
        created_at_micros (str | Unset):
        updated_at_micros (str | Unset):
    """

    id: str | Unset = UNSET
    realm_id: str | Unset = UNSET
    name: str | Unset = UNSET
    slug: str | Unset = UNSET
    description: str | Unset = UNSET
    created_at_micros: str | Unset = UNSET
    updated_at_micros: str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        id = self.id

        realm_id = self.realm_id

        name = self.name

        slug = self.slug

        description = self.description

        created_at_micros = self.created_at_micros

        updated_at_micros = self.updated_at_micros

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if id is not UNSET:
            field_dict["id"] = id
        if realm_id is not UNSET:
            field_dict["realmId"] = realm_id
        if name is not UNSET:
            field_dict["name"] = name
        if slug is not UNSET:
            field_dict["slug"] = slug
        if description is not UNSET:
            field_dict["description"] = description
        if created_at_micros is not UNSET:
            field_dict["createdAtMicros"] = created_at_micros
        if updated_at_micros is not UNSET:
            field_dict["updatedAtMicros"] = updated_at_micros

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        id = d.pop("id", UNSET)

        realm_id = d.pop("realmId", UNSET)

        name = d.pop("name", UNSET)

        slug = d.pop("slug", UNSET)

        description = d.pop("description", UNSET)

        created_at_micros = d.pop("createdAtMicros", UNSET)

        updated_at_micros = d.pop("updatedAtMicros", UNSET)

        v1_group = cls(
            id=id,
            realm_id=realm_id,
            name=name,
            slug=slug,
            description=description,
            created_at_micros=created_at_micros,
            updated_at_micros=updated_at_micros,
        )

        v1_group.additional_properties = d
        return v1_group

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
