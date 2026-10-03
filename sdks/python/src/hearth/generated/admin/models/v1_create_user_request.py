from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, BinaryIO, TextIO, TYPE_CHECKING, Generator

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

from ..types import UNSET, Unset
from typing import cast

if TYPE_CHECKING:
    from ..models.v1_create_user_request_attributes import V1CreateUserRequestAttributes


T = TypeVar("T", bound="V1CreateUserRequest")


@_attrs_define
class V1CreateUserRequest:
    """Request to create a new user.

    Attributes:
        email (str | Unset):
        display_name (str | Unset):
        first_name (str | Unset):
        last_name (str | Unset):
        attributes (V1CreateUserRequestAttributes | Unset):
    """

    email: str | Unset = UNSET
    display_name: str | Unset = UNSET
    first_name: str | Unset = UNSET
    last_name: str | Unset = UNSET
    attributes: V1CreateUserRequestAttributes | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.v1_create_user_request_attributes import (
            V1CreateUserRequestAttributes,
        )  # noqa: PLC0415

        email = self.email

        display_name = self.display_name

        first_name = self.first_name

        last_name = self.last_name

        attributes: dict[str, Any] | Unset = UNSET
        if not isinstance(self.attributes, Unset):
            attributes = self.attributes.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if email is not UNSET:
            field_dict["email"] = email
        if display_name is not UNSET:
            field_dict["display_name"] = display_name
        if first_name is not UNSET:
            field_dict["first_name"] = first_name
        if last_name is not UNSET:
            field_dict["last_name"] = last_name
        if attributes is not UNSET:
            field_dict["attributes"] = attributes

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.v1_create_user_request_attributes import (
            V1CreateUserRequestAttributes,
        )  # noqa: PLC0415

        d = dict(src_dict)
        email = d.pop("email", UNSET)

        display_name = d.pop("display_name", UNSET)

        first_name = d.pop("first_name", UNSET)

        last_name = d.pop("last_name", UNSET)

        _attributes = d.pop("attributes", UNSET)
        attributes: V1CreateUserRequestAttributes | Unset
        if isinstance(_attributes, Unset):
            attributes = UNSET
        else:
            attributes = V1CreateUserRequestAttributes.from_dict(_attributes)

        v1_create_user_request = cls(
            email=email,
            display_name=display_name,
            first_name=first_name,
            last_name=last_name,
            attributes=attributes,
        )

        v1_create_user_request.additional_properties = d
        return v1_create_user_request

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
