from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, BinaryIO, TextIO, TYPE_CHECKING, Generator

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

from ..models.v1_user_status import V1UserStatus
from ..types import UNSET, Unset
from typing import cast


T = TypeVar("T", bound="V1User")


@_attrs_define
class V1User:
    """A user record within a realm.

    Attributes:
        id (str | Unset):
        email (str | Unset):
        display_name (str | Unset):
        status (V1UserStatus | Unset): The lifecycle status of a user account.
        created_at (str | Unset):
        updated_at (str | Unset):
        first_name (str | Unset):
        last_name (str | Unset):
        required_actions (list[str] | Unset): Actions the user must complete before full access is granted.
            Values: "VERIFY_EMAIL", "UPDATE_PASSWORD".
    """

    id: str | Unset = UNSET
    email: str | Unset = UNSET
    display_name: str | Unset = UNSET
    status: V1UserStatus | Unset = UNSET
    created_at: str | Unset = UNSET
    updated_at: str | Unset = UNSET
    first_name: str | Unset = UNSET
    last_name: str | Unset = UNSET
    required_actions: list[str] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        id = self.id

        email = self.email

        display_name = self.display_name

        status: str | Unset = UNSET
        if not isinstance(self.status, Unset):
            status = self.status.value

        created_at = self.created_at

        updated_at = self.updated_at

        first_name = self.first_name

        last_name = self.last_name

        required_actions: list[str] | Unset = UNSET
        if not isinstance(self.required_actions, Unset):
            required_actions = self.required_actions

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if id is not UNSET:
            field_dict["id"] = id
        if email is not UNSET:
            field_dict["email"] = email
        if display_name is not UNSET:
            field_dict["displayName"] = display_name
        if status is not UNSET:
            field_dict["status"] = status
        if created_at is not UNSET:
            field_dict["createdAt"] = created_at
        if updated_at is not UNSET:
            field_dict["updatedAt"] = updated_at
        if first_name is not UNSET:
            field_dict["firstName"] = first_name
        if last_name is not UNSET:
            field_dict["lastName"] = last_name
        if required_actions is not UNSET:
            field_dict["requiredActions"] = required_actions

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        id = d.pop("id", UNSET)

        email = d.pop("email", UNSET)

        display_name = d.pop("displayName", UNSET)

        _status = d.pop("status", UNSET)
        status: V1UserStatus | Unset
        if isinstance(_status, Unset):
            status = UNSET
        else:
            status = V1UserStatus(_status)

        created_at = d.pop("createdAt", UNSET)

        updated_at = d.pop("updatedAt", UNSET)

        first_name = d.pop("firstName", UNSET)

        last_name = d.pop("lastName", UNSET)

        required_actions = cast(list[str], d.pop("requiredActions", UNSET))

        v1_user = cls(
            id=id,
            email=email,
            display_name=display_name,
            status=status,
            created_at=created_at,
            updated_at=updated_at,
            first_name=first_name,
            last_name=last_name,
            required_actions=required_actions,
        )

        v1_user.additional_properties = d
        return v1_user

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
