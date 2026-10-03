from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, BinaryIO, TextIO, TYPE_CHECKING, Generator

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

from ..models.v1_realm_status import V1RealmStatus
from ..types import UNSET, Unset
from typing import cast

if TYPE_CHECKING:
    from ..models.v1_realm_config import V1RealmConfig


T = TypeVar("T", bound="V1Realm")


@_attrs_define
class V1Realm:
    """A realm record.

    Attributes:
        id (str | Unset):
        name (str | Unset):
        status (V1RealmStatus | Unset): The lifecycle status of a realm.
        config (V1RealmConfig | Unset): Per-realm configuration overrides.
        created_at (str | Unset):
        updated_at (str | Unset):
    """

    id: str | Unset = UNSET
    name: str | Unset = UNSET
    status: V1RealmStatus | Unset = UNSET
    config: V1RealmConfig | Unset = UNSET
    created_at: str | Unset = UNSET
    updated_at: str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.v1_realm_config import V1RealmConfig  # noqa: PLC0415

        id = self.id

        name = self.name

        status: str | Unset = UNSET
        if not isinstance(self.status, Unset):
            status = self.status.value

        config: dict[str, Any] | Unset = UNSET
        if not isinstance(self.config, Unset):
            config = self.config.to_dict()

        created_at = self.created_at

        updated_at = self.updated_at

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if id is not UNSET:
            field_dict["id"] = id
        if name is not UNSET:
            field_dict["name"] = name
        if status is not UNSET:
            field_dict["status"] = status
        if config is not UNSET:
            field_dict["config"] = config
        if created_at is not UNSET:
            field_dict["createdAt"] = created_at
        if updated_at is not UNSET:
            field_dict["updatedAt"] = updated_at

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.v1_realm_config import V1RealmConfig  # noqa: PLC0415

        d = dict(src_dict)
        id = d.pop("id", UNSET)

        name = d.pop("name", UNSET)

        _status = d.pop("status", UNSET)
        status: V1RealmStatus | Unset
        if isinstance(_status, Unset):
            status = UNSET
        else:
            status = V1RealmStatus(_status)

        _config = d.pop("config", UNSET)
        config: V1RealmConfig | Unset
        if isinstance(_config, Unset):
            config = UNSET
        else:
            config = V1RealmConfig.from_dict(_config)

        created_at = d.pop("createdAt", UNSET)

        updated_at = d.pop("updatedAt", UNSET)

        v1_realm = cls(
            id=id,
            name=name,
            status=status,
            config=config,
            created_at=created_at,
            updated_at=updated_at,
        )

        v1_realm.additional_properties = d
        return v1_realm

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
