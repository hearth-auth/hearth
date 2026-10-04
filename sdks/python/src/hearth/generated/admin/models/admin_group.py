from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, BinaryIO, TextIO, TYPE_CHECKING, Generator

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

from typing import cast
from uuid import UUID


T = TypeVar("T", bound="AdminGroup")


@_attrs_define
class AdminGroup:
    """
    Attributes:
        id (UUID):
        realm_id (UUID):
        name (str):
        slug (str):
        description (None | str):
        yaml_managed (bool): Declared in hearth.yaml; the admin API cannot change or delete it.
        created_at (int): Microseconds since the Unix epoch.
        updated_at (int): Microseconds since the Unix epoch.
    """

    id: UUID
    realm_id: UUID
    name: str
    slug: str
    description: None | str
    yaml_managed: bool
    created_at: int
    updated_at: int
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        id = str(self.id)

        realm_id = str(self.realm_id)

        name = self.name

        slug = self.slug

        description: None | str
        description = self.description

        yaml_managed = self.yaml_managed

        created_at = self.created_at

        updated_at = self.updated_at

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "id": id,
                "realm_id": realm_id,
                "name": name,
                "slug": slug,
                "description": description,
                "yaml_managed": yaml_managed,
                "created_at": created_at,
                "updated_at": updated_at,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        id = UUID(d.pop("id"))

        realm_id = UUID(d.pop("realm_id"))

        name = d.pop("name")

        slug = d.pop("slug")

        def _parse_description(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        description = _parse_description(d.pop("description"))

        yaml_managed = d.pop("yaml_managed")

        created_at = d.pop("created_at")

        updated_at = d.pop("updated_at")

        admin_group = cls(
            id=id,
            realm_id=realm_id,
            name=name,
            slug=slug,
            description=description,
            yaml_managed=yaml_managed,
            created_at=created_at,
            updated_at=updated_at,
        )

        admin_group.additional_properties = d
        return admin_group

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
