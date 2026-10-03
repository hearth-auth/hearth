from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, BinaryIO, TextIO, TYPE_CHECKING, Generator

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

from ..types import UNSET, Unset


T = TypeVar("T", bound="V1RealmConfig")


@_attrs_define
class V1RealmConfig:
    """Per-realm configuration overrides.

    Attributes:
        session_ttl_micros (str | Unset):
        password_memory_cost (int | Unset):
        password_time_cost (int | Unset):
    """

    session_ttl_micros: str | Unset = UNSET
    password_memory_cost: int | Unset = UNSET
    password_time_cost: int | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        session_ttl_micros = self.session_ttl_micros

        password_memory_cost = self.password_memory_cost

        password_time_cost = self.password_time_cost

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if session_ttl_micros is not UNSET:
            field_dict["sessionTtlMicros"] = session_ttl_micros
        if password_memory_cost is not UNSET:
            field_dict["passwordMemoryCost"] = password_memory_cost
        if password_time_cost is not UNSET:
            field_dict["passwordTimeCost"] = password_time_cost

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        session_ttl_micros = d.pop("sessionTtlMicros", UNSET)

        password_memory_cost = d.pop("passwordMemoryCost", UNSET)

        password_time_cost = d.pop("passwordTimeCost", UNSET)

        v1_realm_config = cls(
            session_ttl_micros=session_ttl_micros,
            password_memory_cost=password_memory_cost,
            password_time_cost=password_time_cost,
        )

        v1_realm_config.additional_properties = d
        return v1_realm_config

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
