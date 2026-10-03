from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, BinaryIO, TextIO, TYPE_CHECKING, Generator

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

from ..types import UNSET, Unset
from typing import cast

if TYPE_CHECKING:
    from ..models.v1_consent_entry import V1ConsentEntry


T = TypeVar("T", bound="V1ListUserConsentsResponse")


@_attrs_define
class V1ListUserConsentsResponse:
    """
    Attributes:
        consents (list[V1ConsentEntry] | Unset):
    """

    consents: list[V1ConsentEntry] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.v1_consent_entry import V1ConsentEntry  # noqa: PLC0415

        consents: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.consents, Unset):
            consents = []
            for consents_item_data in self.consents:
                consents_item = consents_item_data.to_dict()
                consents.append(consents_item)

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if consents is not UNSET:
            field_dict["consents"] = consents

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.v1_consent_entry import V1ConsentEntry  # noqa: PLC0415

        d = dict(src_dict)
        _consents = d.pop("consents", UNSET)
        consents: list[V1ConsentEntry] | Unset = UNSET
        if _consents is not UNSET:
            consents = []
            for consents_item_data in _consents:
                consents_item = V1ConsentEntry.from_dict(consents_item_data)

                consents.append(consents_item)

        v1_list_user_consents_response = cls(
            consents=consents,
        )

        v1_list_user_consents_response.additional_properties = d
        return v1_list_user_consents_response

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
