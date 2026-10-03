from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, BinaryIO, TextIO, TYPE_CHECKING, Generator

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

from ..models.v1_user_status import V1UserStatus
from ..types import UNSET, Unset
from typing import cast

if TYPE_CHECKING:
    from ..models.v1_update_user_request_attributes import V1UpdateUserRequestAttributes


T = TypeVar("T", bound="V1UpdateUserRequest")


@_attrs_define
class V1UpdateUserRequest:
    """Request to update an existing user.

    Attributes:
        email (str | Unset):
        display_name (str | Unset):
        status (V1UserStatus | Unset): The lifecycle status of a user account.
        first_name (str | Unset):
        last_name (str | Unset):
        attributes (V1UpdateUserRequestAttributes | Unset): When non-empty, replaces the user's entire custom attribute
            map.
            An empty map is treated as "no change"; use clear_attributes to remove all.
        clear_attributes (bool | Unset): When true and attributes is empty, clears all custom attributes.
    """

    email: str | Unset = UNSET
    display_name: str | Unset = UNSET
    status: V1UserStatus | Unset = UNSET
    first_name: str | Unset = UNSET
    last_name: str | Unset = UNSET
    attributes: V1UpdateUserRequestAttributes | Unset = UNSET
    clear_attributes: bool | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.v1_update_user_request_attributes import (
            V1UpdateUserRequestAttributes,
        )  # noqa: PLC0415

        email = self.email

        display_name = self.display_name

        status: str | Unset = UNSET
        if not isinstance(self.status, Unset):
            status = self.status.value

        first_name = self.first_name

        last_name = self.last_name

        attributes: dict[str, Any] | Unset = UNSET
        if not isinstance(self.attributes, Unset):
            attributes = self.attributes.to_dict()

        clear_attributes = self.clear_attributes

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if email is not UNSET:
            field_dict["email"] = email
        if display_name is not UNSET:
            field_dict["displayName"] = display_name
        if status is not UNSET:
            field_dict["status"] = status
        if first_name is not UNSET:
            field_dict["firstName"] = first_name
        if last_name is not UNSET:
            field_dict["lastName"] = last_name
        if attributes is not UNSET:
            field_dict["attributes"] = attributes
        if clear_attributes is not UNSET:
            field_dict["clearAttributes"] = clear_attributes

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.v1_update_user_request_attributes import (
            V1UpdateUserRequestAttributes,
        )  # noqa: PLC0415

        d = dict(src_dict)
        email = d.pop("email", UNSET)

        display_name = d.pop("displayName", UNSET)

        _status = d.pop("status", UNSET)
        status: V1UserStatus | Unset
        if isinstance(_status, Unset):
            status = UNSET
        else:
            status = V1UserStatus(_status)

        first_name = d.pop("firstName", UNSET)

        last_name = d.pop("lastName", UNSET)

        _attributes = d.pop("attributes", UNSET)
        attributes: V1UpdateUserRequestAttributes | Unset
        if isinstance(_attributes, Unset):
            attributes = UNSET
        else:
            attributes = V1UpdateUserRequestAttributes.from_dict(_attributes)

        clear_attributes = d.pop("clearAttributes", UNSET)

        v1_update_user_request = cls(
            email=email,
            display_name=display_name,
            status=status,
            first_name=first_name,
            last_name=last_name,
            attributes=attributes,
            clear_attributes=clear_attributes,
        )

        v1_update_user_request.additional_properties = d
        return v1_update_user_request

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
